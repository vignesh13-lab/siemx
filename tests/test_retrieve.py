"""RAG step C: BM25 retrieval, metadata filter, name lookup, two-hop query expansion."""
import pytest

from siemx import llm, retrieve
from siemx.chunking import Chunk


def ch(id_, lang, title, names, text, section="Overview"):
    full = f"[{lang.upper()}] {title} > {section}\n\n{text}"
    return Chunk(id=id_, lang=lang, kind="x", title=title, section=section, names=names,
                 url=f"https://docs/{id_}", text=full, chars=len(full))


CHUNKS = [
    ch("spl/transaction#0", "spl", "transaction", ["transaction"],
       "Groups events into transactions based on time constraints such as maxspan and "
       "maxpause. Each session of related events starts and ends."),
    ch("spl/stats#0", "spl", "stats", ["stats"], "Calculates aggregate statistics such as count."),
    ch("kql/row-window-session#0", "kql", "row_window_session()", ["row_window_session"],
       "Calculates session start values of a column in a serialized row set. A new session "
       "starts when the time since the session start exceeds maxDistanceFromFirst."),
    ch("kql/summarize-operator#0", "kql", "summarize operator", ["summarize"],
       "Produces a table that aggregates the content of the input table: count, sum."),
    ch("kql/take-operator#0", "kql", "take operator", ["take"], "Return up to the specified number of rows."),
    ch("xql/comp#0", "xql", "comp", ["comp"], "Aggregates rows. Session statistics count."),
    ch("kql/long#0", "kql", "long page", ["long"], ("session " * 3 + "filler " * 300)),
]


@pytest.fixture
def index():
    return retrieve.BM25Index(CHUNKS)


def test_tokens_keep_names_and_parts():
    assert retrieve.tokens("project-rename arg_max() The count") == [
        "project-rename", "project", "rename", "arg_max", "arg", "max", "count"]


def test_code_keywords_are_not_stopwords():
    """`where`, `if`, `not`, `has` are English filler but SPL/KQL keywords."""
    assert retrieve.tokens("where if not has the of") == ["where", "if", "not", "has"]


def test_language_filter(index):
    hits = index.search("session count", lang="kql", k=10)
    assert hits and all(h.chunk.lang == "kql" for h in hits)


def test_bm25_prefers_rare_terms_and_short_docs(index):
    hits = index.search("session start", lang="kql", k=3)
    assert hits[0].chunk.id == "kql/row-window-session#0"     # beats the long page
    assert [h.chunk.id for h in hits].index("kql/long#0") > 0


def test_name_boost(index):
    plain = {h.chunk.id: h.score for h in index.search("rows", lang="kql", k=10)}
    boosted = {h.chunk.id: h.score for h in index.search("rows", lang="kql", k=10, names={"take"})}
    assert boosted["kql/take-operator#0"] == pytest.approx(plain["kql/take-operator#0"] + retrieve.NAME_BOOST)


def test_by_name(index):
    assert [c.id for c in index.by_name("transaction", "spl")] == ["spl/transaction#0"]
    assert index.by_name("transaction", "kql") == []


@pytest.mark.parametrize("stage, names", [
    ("stats count by host", ["stats"]),
    ("eval t = strftime(_time, \"%H\"), n = len(user)", ["eval", "strftime", "len"]),
    ("where if(a > 1, 1, 0) = 1", ["where", "if"]),
])
def test_spl_names(stage, names):
    assert retrieve.spl_names(stage) == names


def test_two_hop_bridges_the_vocabulary_gap(index):
    """'transaction' never appears in KQL docs; the SPL doc's words (session, start,
    maxspan...) lead to row_window_session."""
    direct = index.search("transaction host maxspan=5m", lang="kql", k=3)
    assert all(h.chunk.id != "kql/row-window-session#0" for h in direct)   # keyword-only miss
    opts = retrieve.Options(expansion_chars=200)          # expansion is off by default
    res = retrieve.retrieve(index, "index=x | transaction host maxspan=5m", "kql", opts=opts)
    ids = [d["source"].rsplit("/", 1)[1] for d in res.docs]
    assert ids[0] == "transaction#0"                       # hop 1: what the SPL does
    assert "row-window-session#0" in ids                   # hop 2: found via the SPL words
    assert all(d["lang"] in ("spl", "kql") for d in res.docs)
    assert any("name match" in t for t in res.trace) and any("BM25" in t for t in res.trace)


def test_budget_limits_prompt_size(index):
    res = retrieve.retrieve(index, "index=x | transaction host | stats count", "kql", budget=400,
                            opts=retrieve.Options(expansion_chars=200))
    assert sum(len(d["text"]) for d in res.docs) <= 400
    assert any(t.startswith("budget: skipped") for t in res.trace)


def test_llm_retrieve_without_index_is_empty(tmp_path, monkeypatch):
    from siemx import config
    monkeypatch.setattr(config, "ROOT", tmp_path)
    assert llm.retrieve("index=x | transaction host", "kql") == {"docs": [], "examples": []}


def test_llm_prompt_contains_docs(tmp_path, monkeypatch):
    from siemx import config
    from siemx.chunking import asdict
    import json
    monkeypatch.setattr(config, "ROOT", tmp_path)
    idx = tmp_path / "rag" / "index"
    idx.mkdir(parents=True)
    (idx / "chunks.jsonl").write_text("\n".join(json.dumps(asdict(c)) for c in CHUNKS))
    prompt = llm.build_prompt("index=x | stats count", "kql")
    assert "summarize" in prompt and "https://docs/spl/stats#0" in prompt
    assert '"sources"' in prompt


def test_default_options_skip_base_search_and_no_expansion(index):
    """Defaults chosen by `siemx docs eval --ablation` on the real corpus."""
    assert retrieve.Options() == retrieve.Options(skip_base=True, use_bridge=True, expansion_chars=0)
    res = retrieve.retrieve(index, "index=wineventlog session | stats count", "kql")
    assert not any(t.startswith("stage 0") for t in res.trace)


def test_bridge_adds_target_docs_by_name():
    idx = retrieve.BM25Index(CHUNKS, bridge={"kql": {"stats": ["summarize"]}})
    res = retrieve.retrieve(idx, "index=x | stats dc(user)", "kql")
    assert "stage 1: bridge -> KQL 'summarize' -> kql/summarize-operator#0" in res.trace
    no = retrieve.retrieve(idx, "index=x | stats dc(user)", "kql",
                           opts=retrieve.Options(use_bridge=False))
    assert not any("bridge" in t for t in no.trace)


CHEAT = """# Splunk to Kusto cheat sheet
| Splunk | Kusto | Comment |
|--|--|--|
| `strcat` | `strcat()` | (1) |
| `upper`<br />`lower` |`toupper()`<br />`tolower()`|(1) |
| `tonumber` | `todouble()`<br />`tolong()` | (1) |
| Product | Operator | Example |
|:---|:---|:---|
| Splunk | `rename` | `rename a as b` |
| Kusto | `project-rename` | `project-rename b = a` |
| Splunk | `fields -` |`fields - quota` |
| Kusto | `project-away` |`project-away state` |
| Splunk operator | Splunk example | Kusto operator | Kusto example |
| `stats` | `stats count by x` | `summarize` | `summarize count() by x` |
| `match` | `matches regex` | (2) |
"""


def test_parse_cheat_sheet():
    assert retrieve.parse_cheat_sheet(CHEAT) == {
        "strcat": ["strcat"], "upper": ["toupper"], "lower": ["tolower"],
        "tonumber": ["todouble", "tolong"], "rename": ["project-rename"],
        "fields": ["project-away"], "stats": ["summarize"], "match": ["matches"]}
