"""Roadmap 7 (part 3): XQL -> SPL. Doc references in siemx/reverse_xql.py and siemx/xql_expr.py."""
import json

import pytest

from siemx import cli, config, gold, llm, pipeline, rag_eval, retrieve, reverse_xql, xql_expr
from siemx.kql_expr import Unsupported

D = "dataset = xdr_data\n"


def spl(xql):
    return reverse_xql.convert(xql)


# ---- expressions ------------------------------------------------------------------------------------

@pytest.mark.parametrize("xql, out", [
    ("EventID = 4625", "EventID==4625"),
    ("host != null", "isnotnull(host)"),
    ("host = null", "isnull(host)"),
    ('user = "Admin"', 'lower(user)=="admin"'),                       # XQL default: case-insensitive
    ('lowercase(user) = "adm*"', 'like(lower(user), "adm%")'),        # * is a wildcard in "..."
    ('cmd contains "-ENC"', 'like(lower(cmd), "%-enc%")'),
    ("EventID in (4624, 4625)", "EventID==4624 OR EventID==4625"),
    ('user in ("A", "b")', 'in(lower(user), "a", "b")'),
    ("status >= 400 and bytes > 1000", "status>=400 AND bytes>1000"),
    ("(a = 1 or b = 2) and c = 3", "((a==1 OR b==2)) AND c==3"),
    ('not (user != null and lowercase(user) = "system")',
     'NOT (isnotnull(user) AND lower(user)=="system")'),
    ('xdm.source.user.username = "x"', "lower('xdm.source.user.username')==\"x\""),
])
def test_conditions(xql, out):
    assert xql_expr.condition(xql).text == out


def test_case_sensitive_mode():
    assert xql_expr.condition('user = "Bob"', case_sensitive=True).text == 'user=="Bob"'
    with pytest.raises(Unsupported, match="case-sensitive contains"):
        xql_expr.condition('cmd contains "x"', case_sensitive=True)


@pytest.mark.parametrize("xql, out", [
    ("len(cmd)", "len(cmd)"),
    ('if(status = 200, "ok", "error")', 'if(status==200, "ok", "error")'),
    ("divide(bytes, 1024)", "(bytes / 1024)"),
    ("coalesce(src, dest)", "coalesce(src, dest)"),
    ("uppercase(host)", "upper(host)"),
    ('concat(user, "@", host)', '(user . "@" . host)'),
])
def test_values(xql, out):
    assert xql_expr.value(xql).text == out


@pytest.mark.parametrize("xql, reason", [
    ("a = 1 or b = 2 and c = 3", "precedence is not documented"),
    ('not user = "x"', "'not' without parentheses"),
    ('user ~= "a.*"', "regex dialect"),
    ('ip incidr "10.0.0.0/8"', "incidr"),
    ('x = """a\\tb"""', "triple-quoted"),
    ("a + 1 > 2", "infix arithmetic"),
    ("x = true", "boolean literal"),
    ("a = b", "non-literal"),
    ('name > "m"', "ordering and case"),
    ("foo(x) = 1", "function foo() not supported"),
    ('user = "50%*"', "% or _"),
])
def test_unsupported_expressions(xql, reason):
    with pytest.raises(Unsupported, match=reason.replace("(", r"\(").replace(")", r"\)")):
        xql_expr.condition(xql)


# ---- whole queries ------------------------------------------------------------------------------------

@pytest.mark.parametrize("xql, out", [
    (D + "| filter EventID = 4625 | limit 10", "index=wineventlog | where EventID==4625 | head 10"),
    ("config timeframe = 1d | " + D + "| filter EventID = 4625",
     "index=wineventlog earliest=-1d | where EventID==4625"),
    ("config timeframe = 30M | " + D + "| limit 1", "index=wineventlog earliest=-30m | head 1"),
    ("filter EventID = 1 | limit 1", "index=wineventlog | where EventID==1 | head 1"),   # default
    ("DATASET = XDR_DATA | limit 1", "index=wineventlog | head 1"),       # names case-insensitive
    (D + "| filter host != null | comp count() as count by host | sort desc count | limit 10",
     "index=wineventlog | where isnotnull(host) | stats count AS count by host "
     "| sort 0 -count | head 10"),
    (D + "| comp count_distinct(user) as users, count(cmd) as n",
     "index=wineventlog | stats dc(user) AS users, count(cmd) AS n"),
    (D + "| sort desc bytes, asc host", "index=wineventlog | sort 0 -bytes, +host"),
    (D + "| alter n = len(cmd), m = multiply(n, 2)", "index=wineventlog | eval n = len(cmd), m = (n * 2)"),
    (D + "| fields host, user as u", "index=wineventlog | rename user AS u | table host, u"),
    (D + "| fields - cmd, user", "index=wineventlog | fields - cmd, user"),
    (D + "| dedup host by desc _time", "index=wineventlog | sort 0 -_time | dedup host"),
    ("config case_sensitive = true | " + D + '| filter user = "Bob"',
     'index=wineventlog | where user=="Bob"'),
    (D + '| filter cmd = "a|b" // comment | not a stage\n| limit 1',
     'index=wineventlog | where lower(cmd)=="a|b" | head 1'),
])
def test_queries(sources_map, xql, out):
    r = spl(xql)
    assert not r.get("unsupported"), r["warnings"]
    assert r["query"] == out


@pytest.mark.parametrize("xql, reason, llm", [
    (D + "| comp count() by host", "aggregation count() (supported", True),  # alias required
    (D + "| sort count", "without asc/desc", True),
    (D + "| bin _time span = 1h", "XQL stage 'bin'", True),
    (D + "| join (dataset = x) as y y.a = a", "XQL stage 'join'", True),
    ("config timeframe = 2MO | " + D, "config timeframe = 2MO", False),
    ("dataset in (a, b) | limit 1", "dataset in (a, b)", False),
    ("preset = xdr_process | limit 1", "preset", False),
    ("dataset = panw_ngfw_traffic_raw | limit 1", "no SPL source", False),
    (D + "| frobnicate x", "input is not valid XQL", False),
    (D + '| filter x = "open', "input is not valid XQL", False),
])
def test_unsupported_queries(sources_map, xql, reason, llm):
    r = spl(xql)
    assert r.get("unsupported") and reason in r["warnings"][0], r["warnings"]
    assert bool(r.get("llm_base")) is llm


def test_warnings(sources_map):
    r = spl(D + "| comp count() as n by host")                    # no `host != null` before
    assert any("null groups is not documented" in w for w in r["warnings"])
    r = spl(D + "| filter host != null | comp count() as n by host")
    assert not any("null groups" in w for w in r["warnings"])
    r = spl(D + "| dedup host")
    assert any("arbitrary record" in w for w in r["warnings"])
    assert any("keepempty" in w for w in r["warnings"])
    r = spl(D + "| fields host")
    assert any("system fields" in w for w in r["warnings"])
    cols = [w for w in spl(D + "| alter n = len(cmd) | filter n > 1")["warnings"]
            if "column names are the XQL dataset's" in w][0]
    assert cols.endswith("(no exact reverse mapping for: cmd)")


def test_gold_xql_targets_all_convert(sources_map):
    """Every verified XQL target in gold/pairs.jsonl converts back by rules."""
    pairs = [p for p in gold.load(config.ROOT / "gold" / "pairs.jsonl") if p.get("xql")]
    assert pairs
    for p in pairs:
        r = spl(p["xql"])
        assert not r.get("unsupported"), (p["id"], r["warnings"])


# ---- LLM fallback --------------------------------------------------------------------------------------

def test_rule_gap_goes_to_llm_with_base_and_time(sources_map, monkeypatch):
    calls = []

    def translate(text, target, source="spl", base=None):
        calls.append((source, base))
        return {"query": "index=wineventlog earliest=-1d | bin _time span=1h", "confidence": 0.8,
                "warnings": [], "unsupported": False, "tokens": 1}

    monkeypatch.setattr(llm, "translate", translate)
    q = "config timeframe = 1d | " + D + "| bin _time span = 1h"
    r = pipeline.convert_any(q, "spl", source="xql")
    assert calls == [("xql", "index=wineventlog earliest=-1d")]
    assert r["no_rule"] == ["XQL stage 'bin'"]
    assert "XQL dataset's column names (xdr_data)" in r["warnings"][-1]
    assert pipeline.status_for(r) == "needs-review"


def test_no_llm_for_unmapped_dataset(sources_map, no_llm):
    r = pipeline.convert_any("dataset = other | limit 1", "spl", source="xql")
    assert r["unsupported"]


def test_reverse_prompt_mentions_xql_pitfalls(monkeypatch):
    monkeypatch.setattr(llm, "retrieve", lambda t, tg, source="spl": {"docs": [], "examples": [],
                                                                       "field_map": {}})
    p = llm.build_prompt(D + "| bin _time span = 1h", "spl", source="xql", base="index=x")
    assert p.startswith("Translate this XQL (Palo Alto Cortex XDR/XSIAM) query to SPL (Splunk).")
    assert "case-insensitive unless `config case_sensitive = true`" in p
    assert "KQL sort is descending" not in p


# ---- retrieval / gold helpers ------------------------------------------------------------------------

@pytest.mark.parametrize("stage, names", [
    ("alter n = len(lowercase(x))", ["alter", "len", "lowercase"]),
    ("comp count() as c by h", ["comp", "count"]),
    ("sort desc c", ["sort"]),
])
def test_xql_names(stage, names):
    assert retrieve.xql_names(stage) == names


def test_xql_features_skip_head():
    assert gold.xql_features("config timeframe = 1d | dataset = x | comp count() as c") == \
        {"comp", "count"}


def test_reverse_prompt_coverage():
    from types import SimpleNamespace
    pairs = [{"id": "a", "spl": "index=a | stats count by h", "xql": D + "| comp count() as c by h"},
             {"id": "b", "spl": "index=a | stats sum(x) by h", "xql": D + "| comp sum(x) as s by h"}]

    def no_docs(index, q, target, source):
        return SimpleNamespace(docs=[])
    cov = rag_eval.reverse_prompt_coverage(None, pairs, "xql", no_docs)
    assert cov == {"cases": 2, "examples_hit": 1.0, "examples_recall": 1.0, "covered": 1.0}


# ---- CLI ---------------------------------------------------------------------------------------------------

def test_convert_from_xql(workspace, sources_map, monkeypatch, capsys):
    src = config.SRC_DIR.parent / "xql" / "windows" / "failed.xql"
    src.parent.mkdir(parents=True)
    src.write_text(D + "| filter EventID = 4625 | filter host != null | comp count() as n by host")
    monkeypatch.setattr("sys.argv", ["siemx", "convert", "--from", "xql", "--workers", "1"])
    cli.main()
    capsys.readouterr()
    out = (config.OUT_DIR / "spl" / "windows" / "failed.spl").read_text()
    assert out.startswith("index=wineventlog | where EventID==4625 | where isnotnull(host) "
                          "| stats count AS n by host")
    meta = json.loads((config.META_DIR / "windows" / "failed.spl.json").read_text())
    assert meta["src"] == "detections/xql/windows/failed.xql" and meta["source"] == "xql"
