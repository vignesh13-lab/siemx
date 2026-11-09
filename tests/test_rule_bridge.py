"""The rule bridge: SPL names -> the target names siemx's own rules emit (retrieve.py)."""
import pytest

from siemx import retrieve as rag
from siemx.chunking import Chunk


@pytest.mark.parametrize("target, spl_name, expected", [
    ("kql", "dc", ["count_distinctif"]),
    ("kql", ".", ["strcat"]),
    ("kql", "lower", ["tolower"]),
    ("kql", "stats", ["summarize", "count"]),
    ("kql", "where", ["where"]),
    ("kql", "head", ["take"]),
    ("kql", "rex", ["extend", "extract"]),
    ("xql", "dc", ["count_distinct"]),
    ("xql", ".", ["concat"]),
    ("xql", "len", ["len"]),                 # same name in both languages: kept
    ("xql", "lookup", ["join", "fields"]),
    ("xql", "where", ["filter"]),
])
def test_rule_bridge_follows_the_rules(target, spl_name, expected):
    assert rag.rule_bridge(target)[spl_name] == expected


def test_null_guards_are_not_bridged():
    for target in ("kql", "xql"):
        for spl_name, names in rag.rule_bridge(target).items():
            if spl_name != "where":
                assert not set(names) & {"isnotempty", "_getwatchlist", "to_string"}, spl_name


def test_concatenation_counts_as_a_name():
    assert rag.spl_names('eval who = user . "@" . host') == ["eval", "."]
    assert rag.spl_names('eval x = "a . b"') == ["eval"]          # inside a string
    assert rag.spl_names("stats count by a.b") == ["stats"]


def chunk(cid, lang, names, text="x"):
    return Chunk(id=cid, lang=lang, kind="function", title=cid, section="s", names=names,
                 url=f"https://x/{cid}", text=text, chars=len(text))


def test_retrieval_uses_the_rule_bridge_and_it_can_be_switched_off():
    index = rag.BM25Index([chunk("kql/strcat#0", "kql", ["strcat"], "strcat joins strings"),
                           chunk("kql/other#0", "kql", ["other"], "unrelated text")])
    spl = 'index=a | eval who = user . "@" . host'
    on = rag.retrieve(index, spl, "kql", opts=rag.Options(mode="bm25"))
    off = rag.retrieve(index, spl, "kql", opts=rag.Options(mode="bm25", use_rule_bridge=False))
    assert any("kql/strcat#0" in t and "bridge" in t for t in on.trace)
    assert not any("bridge" in t for t in off.trace)


def test_reverse_direction_uses_the_inverted_rule_bridge():
    index = rag.BM25Index([chunk("spl/stats#0", "spl", ["stats"], "stats computes aggregates"),
                           chunk("xql/comp#0", "xql", ["comp"], "comp aggregates")])
    r = rag.retrieve(index, "dataset = xdr_data | comp count() as n by a", "spl",
                     opts=rag.Options(mode="bm25"), source="xql")
    assert any("bridge -> SPL 'stats'" in t for t in r.trace)


def test_merged_bridge_keeps_official_entries_first():
    assert rag.merged_bridge({"head": ["limit", "top"]}, {"head": ["take"], "dc": ["x"]}) == {
        "head": ["limit", "top", "take"], "dc": ["x"]}
