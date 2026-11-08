"""Roadmap 7 (part 2): LLM fallback for KQL -> SPL. The model is always stubbed here."""
import json

import pytest

from siemx import cli, config, gold, llm, pipeline, retrieve, reverse, validate

GAP = "SecurityEvent\n| mv-expand Targets"          # valid KQL, no rule for mv-expand


def answer(query, warnings=None, confidence=0.8):
    return {"query": query, "confidence": confidence, "warnings": warnings or [],
            "unsupported": False, "tokens": 10, "sources": []}


@pytest.fixture
def stub_llm(monkeypatch):
    """Records every call; returns queued answers in order."""
    calls, queue = [], []

    def translate(text, target, source="spl", base=None):
        calls.append({"text": text, "target": target, "source": source, "base": base})
        return queue.pop(0)

    monkeypatch.setattr(llm, "translate", translate)
    return calls, queue


# ---- which failures go to the LLM -----------------------------------------------------------------

def test_rule_gap_marks_llm_base(sources_map):
    r = reverse.convert(GAP)
    assert r["unsupported"] and r["llm_base"] == "index=wineventlog"


@pytest.mark.parametrize("kql", [
    "CommonSecurityLog | take 1",           # unmapped table: the model can't know the index
    "let x = 1; SecurityEvent",             # no table first
])
def test_no_llm_when_input_or_mapping_is_the_problem(sources_map, no_llm, kql):
    r = pipeline.convert_any(kql, "spl", source="kql")
    assert r["unsupported"] and not r.get("llm_base")


def test_rule_covered_query_never_calls_llm(sources_map, no_llm):
    r = pipeline.convert_any("SecurityEvent | take 1", "spl", source="kql")
    assert r["query"] == "index=wineventlog | head 1"


def test_rule_gap_goes_to_llm_with_base(sources_map, stub_llm):
    calls, queue = stub_llm
    queue.append(answer("index=wineventlog | mvexpand Targets"))
    r = pipeline.convert_any(GAP, "spl", source="kql")
    assert calls == [{"text": GAP, "target": "spl", "source": "kql", "base": "index=wineventlog"}]
    assert r["method"] == "llm" and r["query"] == "index=wineventlog | mvexpand Targets"
    assert any("mv-expand" in n for n in r["no_rule"])
    assert r["validator"] == validate.status()["spl"]
    assert r["warnings"] == ["SPL: LLM translation keeps the KQL table's column names "
                             "(SecurityEvent); map them to your Splunk field names"]
    assert pipeline.status_for(r) == "needs-review"


def test_retry_sends_previous_query_and_exact_errors(sources_map, stub_llm):
    calls, queue = stub_llm
    queue += [answer("index=wineventlog | mv-expand Targets"),          # KQL leaked into SPL
              answer("index=wineventlog | mvexpand Targets")]
    r = pipeline.convert_any(GAP, "spl", source="kql")
    assert len(calls) == 2 and r["method"] == "llm-retry"
    retry = calls[1]["text"]
    assert "index=wineventlog | mv-expand Targets" in retry
    assert "SPL: unknown command 'mv'" in retry
    assert calls[1]["base"] == "index=wineventlog"
    assert not any(w.startswith("validation:") for w in r["warnings"])


def test_still_invalid_after_retries_is_flagged(sources_map, stub_llm):
    calls, queue = stub_llm
    queue += [answer("index=wineventlog | summarize count()")] * (pipeline.MAX_RETRIES + 1)
    r = pipeline.convert_any(GAP, "spl", source="kql")
    assert any(w.startswith("validation: SPL: unknown command 'summarize'") for w in r["warnings"])
    assert pipeline.status_for(r) == "needs-review"


# ---- prompt ------------------------------------------------------------------------------------------

@pytest.fixture
def fake_context(monkeypatch):
    seen = []

    def ctx(text, target, source="spl"):
        seen.append(source)
        return {"docs": [{"url": "https://docs/mvexpand", "text": "mvexpand"}],
                "examples": [{"kql": "T | take 1", "spl": "index=t | head 1"}], "field_map": {}}

    monkeypatch.setattr(llm, "retrieve", ctx)
    return seen


def test_reverse_prompt(fake_context):
    p = llm.build_prompt(GAP, "spl", source="kql", base="index=wineventlog")
    assert p.startswith("Translate this KQL (Microsoft Sentinel / Defender) query to SPL (Splunk).")
    assert GAP in p and "exactly this base search for the table's data: index=wineventlog" in p
    assert "https://docs/mvexpand" in p and "sort 0" in p
    assert fake_context == ["kql"]


def test_forward_prompt_is_unchanged(fake_context):
    """Cached forward answers are keyed by the prompt text: it must not change."""
    p = llm.build_prompt("index=a | stats count", "kql")
    assert p.startswith("Translate this SPL") and "base search for the table" not in p
    assert fake_context == ["spl"]


# ---- gold pairs read backwards ---------------------------------------------------------------------

PAIRS = [
    {"id": "a", "spl": "s1", "kql": "T\n| summarize count() by h\n| sort by c", "verified_by": "x"},
    {"id": "b", "spl": "s2", "kql": "T\n| where x == 1\n| take 5", "verified_by": "x"},
    {"id": "c", "spl": "s3", "kql": "T\n| summarize dcount(u) by h", "verified_by": "x"},
]


def test_similar_reverse_ranks_by_shared_operators():
    got = [p["id"] for _, p in gold.similar_reverse(PAIRS, "U | summarize count() by z", "kql")]
    assert got[0] == "a" and "b" not in got


def test_similar_reverse_leakage_guard():
    q = PAIRS[0]["kql"]
    got = [p["id"] for _, p in gold.similar_reverse(PAIRS, q, "kql", exclude=q)]
    assert "a" not in got


def test_reverse_examples_have_kql_first(monkeypatch):
    monkeypatch.setattr(gold, "load", lambda path=None: PAIRS)
    ex = gold.examples_for_prompt("U | take 1", "spl", source="kql")
    assert ex and list(ex[0])[:2] == ["kql", "spl"]


# ---- retrieval helpers -------------------------------------------------------------------------------

@pytest.mark.parametrize("stage, names", [
    ("extend n = strlen(tolower(x))", ["extend", "strlen", "tolower"]),
    ("sort by c desc", ["sort"]),
    ("summarize count() by h", ["summarize", "count"]),
    ("frobnicate x", ["frobnicate"]),                 # unknown: no docs match, harmless
])
def test_kql_names(stage, names):
    assert retrieve.kql_names(stage) == names


def test_invert_bridge():
    assert retrieve.invert_bridge({"stats": ["summarize"], "eventstats": ["summarize", "join"]}) == \
        {"summarize": ["stats", "eventstats"], "join": ["eventstats"]}


# ---- SPL validator -----------------------------------------------------------------------------------

@pytest.mark.parametrize("q, problem", [
    ("index=a | where x=1 | stats count by h | sort 0 -count", None),
    ("| tstats count where index=a by host", None),
    ("index=a | join type=left h [| inputlookup t.csv | fields h]", None),
    ('index=a | eval s="x | summarize"', None),                       # pipe inside a string
    ("index=a | summarize count()", "unknown command 'summarize'"),
    ("index=a | project h", "unknown command 'project'"),
])
def test_spl_validator(q, problem):
    got = validate.check(q, "spl")
    if problem:
        assert any(problem in g for g in got), got
    else:
        assert got == []


# ---- CLI -------------------------------------------------------------------------------------------------

def test_cli_convert_from_kql_uses_llm_for_gaps(workspace, stub_llm, monkeypatch, capsys):
    calls, queue = stub_llm
    queue.append(answer("index=wineventlog | mvexpand Targets"))
    src = config.SRC_DIR.parent / "kql" / "windows" / "expand.kql"
    src.parent.mkdir(parents=True)
    src.write_text(GAP)
    monkeypatch.setattr("sys.argv", ["siemx", "convert", "--from", "kql", "--workers", "1"])
    cli.main()
    capsys.readouterr()
    meta = json.loads((config.META_DIR / "windows" / "expand.spl.json").read_text())
    assert meta["method"] == "llm" and meta["source"] == "kql"
    assert any("mv-expand" in n for n in meta["no_rule"])
    assert calls[0]["base"] == "index=wineventlog"


# ---- reverse retrieval eval --------------------------------------------------------------------------

def test_reverse_eval_cases_and_scores():
    from types import SimpleNamespace

    from siemx import rag_eval
    cases = rag_eval.reverse_cases([
        {"spl": "index=a | stats count by h | sort - count", "kql": "T | summarize count() by h"},
        {"spl": "index=a", "kql": "T"},                                     # no commands: skipped
        {"spl": "index=a | head 1"},                                        # no KQL: skipped
    ])
    assert cases == [{"query": "T | summarize count() by h", "spl": ["stats", "sort"]}]

    def fake(index, q, target, source):
        assert (target, source) == ("spl", "kql")
        return SimpleNamespace(docs=[{"lang": "kql", "names": ["summarize"]},
                                     {"lang": "spl", "names": ["stats"]}])
    rep = rag_eval.evaluate_reverse(None, cases, fake)
    assert rep["hit"] == 1.0 and rep["recall"] == 0.5 and rep["mrr"] == 1.0
    assert rep["misses"][0]["missing"] == ["sort"]
