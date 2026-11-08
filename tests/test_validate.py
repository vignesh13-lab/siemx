"""Roadmap 5: validation of generated queries (official KQL parser, XQL name check)."""
import json
from pathlib import Path

import pytest

from siemx import config, gold, llm, pipeline, rules, validate

REPO = Path(__file__).resolve().parent.parent
needs_parser = pytest.mark.skipif(not validate.KqlValidator.available(),
                                  reason="run: npm ci --prefix tools/kql-validate")


@pytest.fixture
def real_fields(monkeypatch):
    monkeypatch.setattr(config, "FIELDS_FILE", REPO / "mappings" / "fields.json")


# ---- basic checks -----------------------------------------------------------------------------

@pytest.mark.parametrize("query, problems", [
    ("", ["empty output"]),
    ("T | where a == 1", []),
    ('T | where msg == "a(b"', []),                       # bracket inside a string: fine
    ("T | where msg == 'it''s'", []),
    ('T | where (a == "x"', ["unbalanced parentheses"]),
    ('T | where a == "x', ["unbalanced quotes"]),
])
def test_basic_problems(query, problems):
    assert validate.basic_problems(query) == problems


# ---- XQL names -----------------------------------------------------------------------------------

def test_xql_reference_loaded_from_repo():
    ref = validate.xql_reference()
    assert {"dataset", "filter", "alter", "comp", "join", "dedup", "bin"} <= ref["stages"]
    assert {"lowercase", "len", "count", "count_distinct", "regextract", "to_string"} <= ref["functions"]


@pytest.mark.parametrize("query, expected", [
    ('dataset = xdr_data\n| filter lowercase(user) = "adm*"\n| comp count() as count by host', []),
    ("dataset = xdr_data\n| join type = left (dataset = t | fields a as k) as lk lk.k = a", []),
    ('dataset = xdr_data\n| filter not (a = 1) and b in ("x", "y")', []),
    ("dataset = xdr_data\n| where user = 1",
     ["XQL: unknown stage 'where' (not in the official XQL reference)"]),
    ("dataset = xdr_data\n| alter n = strlen(user)",
     ["XQL: unknown function 'strlen' (not in the official XQL reference)"]),
    ('dataset = xdr_data\n| filter msg = "strlen(x)"', []),   # names inside strings ignored
])
def test_xql_problems(query, expected):
    assert validate.xql_problems(query) == expected


def test_all_gold_pairs_validate():
    for p in gold.load(REPO / "gold" / "pairs.jsonl"):
        for t in ("kql", "xql"):
            if p.get(t):
                assert validate.check(p[t], t, scope="rules") == [], (p["id"], t)


# ---- KQL with the official parser -------------------------------------------------------------

@needs_parser
@pytest.mark.parametrize("query, fragment", [
    ("SecurityEvent\n| summarise count() by Computer", "KQL syntax: Query operator expected"),
    ("SecurityEvent\n| extend n = strlength(Account)", "'strlength' does not refer to any known function"),
    ("SecurityEvent\n| where host == 'x'", "'host' does not refer to any known column"),
    ("SecurityEvent\n| where Computer > 5", "not defined for the operand types string and long"),
])
def test_kql_errors_found(real_fields, query, fragment):
    problems = validate.check(query, "kql")
    assert any(fragment in p for p in problems), problems
    assert all("line " in p and "col " in p for p in problems)        # location for the retry


@needs_parser
def test_kql_valid_and_allowed(real_fields):
    ok = ["SecurityEvent\n| where EventID == 4625\n| summarize ['count'] = count() by Computer",
          "SecurityEvent\n| lookup kind=leftouter (_GetWatchlist('vip') | project Account) on Account",
          "CommonSecurityLog\n| where DeviceVendor == 'x'"]          # no schema: syntax only
    for q in ok:
        assert validate.check(q, "kql") == [], q


@needs_parser
def test_kql_rules_scope_skips_columns_but_not_functions(real_fields):
    q = "SecurityEvent\n| extend x = coalesce(src, dest), n = strlength(Account)"
    rules_scope = validate.check(q, "kql", scope="rules")
    assert len(rules_scope) == 1 and "strlength" in rules_scope[0]
    assert any("'src'" in p for p in validate.check(q, "kql", scope="all"))


@needs_parser
def test_kql_untyped_table_reports_only_name_errors(tmp_path, monkeypatch):
    f = tmp_path / "fields.json"
    f.write_text(json.dumps({"kql": {"T": {"fields": ["a", "TimeGenerated"]}}}))
    monkeypatch.setattr(config, "FIELDS_FILE", f)
    q = "T\n| summarize arg_max(TimeGenerated, *) by a\n| where nosuch == 1"
    problems = validate.check(q, "kql")
    assert problems and all("does not refer to any known" in p for p in problems)


@needs_parser
def test_kql_problem_count_is_capped(real_fields):
    assert len(validate.check("SecurityEvent | summarise count( by | | ", "kql")) <= validate.MAX_PROBLEMS


# ---- pipeline ---------------------------------------------------------------------------------------

def test_rule_output_is_validated(sources_map, no_llm, monkeypatch):
    """A rule that produced invalid output (simulated) makes the result needs-review."""
    monkeypatch.setattr(validate, "check", lambda q, t, scope="all": ["KQL syntax: boom"] if scope == "rules" else [])
    res = pipeline.convert_query("index=wineventlog | head 1 | sort - host", "kql")
    assert "validation: KQL syntax: boom" in res["warnings"]
    assert pipeline.status_for(res) == "needs-review"
    assert res["validator"]


def test_retry_gets_previous_query_and_exact_errors(workspace, monkeypatch):
    calls = []

    def translate(spl, target):
        calls.append(spl)
        q = "SecurityEvent | summarise count()" if len(calls) == 1 else "SecurityEvent | summarize count()"
        return {"query": q, "confidence": 0.8, "warnings": [], "unsupported": False}

    monkeypatch.setattr(llm, "translate", translate)
    monkeypatch.setattr(validate, "check",
                        lambda q, t, scope="all": ["KQL syntax: Query operator expected. (line 1 col 17)"]
                        if "summarise" in q else [])
    res = pipeline.convert_query("index=x | transaction host", "kql")
    assert len(calls) == 2 and res["method"] == "llm-retry"
    assert "Your previous KQL translation was:\nSecurityEvent | summarise count()" in calls[1]
    assert "- KQL syntax: Query operator expected. (line 1 col 17)" in calls[1]
    assert not any(w.startswith("validation:") for w in res["warnings"])


def test_status_reports_what_ran():
    s = validate.status()
    assert set(s) == {"kql", "xql"} and s["xql"].startswith("name check")
