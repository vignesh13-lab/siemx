"""KQL / XQL -> Kibana KQL (to_elk.py), directly. KQL syntax is checked by the official
parser only when it is installed; these tests do not depend on it."""
import json

import pytest

from siemx import config, elk, llm, pipeline, to_elk, validate

BS = "\\"


@pytest.fixture(autouse=True)
def no_kql_parser(monkeypatch):
    monkeypatch.setattr(validate.KqlValidator, "available", staticmethod(lambda: False))


@pytest.fixture
def sources(workspace, sources_map):
    sources_map.write_text(json.dumps({"sourcetype=XmlWinEventLog:Security": {
        "kql": "SecurityEvent", "xql": "dataset = xdr_data", "elk": "logs-system.security-*"}}))


def to(text, lang):
    r = pipeline.convert_any(text, "elk", lang)
    if r.get("query"):
        assert elk.problems(r["query"]) == [], r["query"]
    return r


def text_of(r):
    return " | ".join(r["warnings"])


# ---- KQL ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("kql, want", [
    ('SecurityEvent | where EventID == 4625', "EventID: 4625"),
    ('SecurityEvent | where Account == "Bob"', 'Account: "Bob"'),
    ('SecurityEvent | where Account != "Bob"', 'not Account: "Bob"'),
    ('SecurityEvent | where EventID in (4624, 4625)', "EventID: (4624 or 4625)"),
    ('SecurityEvent | where EventID !in (1, 2)', "not EventID: (1 or 2)"),
    ('SecurityEvent | where A == 1 and B > 5', "A: 1 and B > 5"),
    ('SecurityEvent | where A == 1 or B == 2', "A: 1 or B: 2"),
    ('SecurityEvent | where A == 1 and (B == 2 or C == 3)', "A: 1 and (B: 2 or C: 3)"),
    ('SecurityEvent | where not(A == 1)', "not (A: 1)"),
    ('SecurityEvent | where A startswith "svc_"', "A: svc_*"),
    ('SecurityEvent | where A endswith @"\\cmd.exe"', f"A: *{BS}{BS}cmd.exe"),
    ('SecurityEvent | where A contains "(x)"', f"A: *{BS}(x{BS})*"),
    ('SecurityEvent | where A contains "a*b"', f"A: *a{BS}*b*"),
    ('SecurityEvent | where A !contains "x"', "not A: *x*"),
    ('SecurityEvent | where A == "x*y"', 'A: "x*y"'),
    ('SecurityEvent | where isnotempty(A)', "A: *"),
    ('SecurityEvent | where isempty(A)', "not A: *"),
    ('SecurityEvent | where A == 1 | where B == 2', "A: 1 and B: 2"),
])
def test_kql_conditions(sources, kql, want):
    r = to(kql, "kql")
    assert r["query"] == want and r["method"] == "rules"
    assert r["index"] == "logs-system.security-*"


def test_kql_literal_star_in_contains_stays_literal(sources):
    q = to('SecurityEvent | where A contains "a*b"', "kql")["query"]
    assert elk.parse(q)[2] == elk.Lit(f"{elk.WILD}a*b{elk.WILD}", False, "wild")


def test_kql_case_insensitive_operators_are_flagged(sources):
    exact = to('SecurityEvent | where A == "Bob"', "kql")
    assert "case-insensitively" not in text_of(exact)
    for q in ('A =~ "Bob"', 'A !~ "Bob"', 'A contains "Bob"', 'A in~ ("Bob")'):
        r = to(f"SecurityEvent | where {q}", "kql")
        assert "KQL matched A case-insensitively" in text_of(r), q
        assert "keyword fields in Elastic: A" in text_of(r)


def test_kql_time_filter_goes_to_the_rule(sources):
    r = to("SecurityEvent | where TimeGenerated > ago(1d) and EventID == 4625", "kql")
    assert r["query"] == "EventID: 4625"
    assert "time range `TimeGenerated > ago(1d)` dropped" in r["warnings"][0]


def test_kql_isnotempty_empty_string_note(sources):
    assert "also matches an empty string" in text_of(to("SecurityEvent | where isnotempty(A)",
                                                        "kql"))


def test_kql_display_stages_dropped(sources):
    r = to("SecurityEvent | where A == 1 | project A, B | sort by A desc", "kql")
    assert r["query"] == "A: 1" and r["warnings"][0].startswith("ELK: `project`, `sort by` dropped")


def test_kql_project_with_expressions_is_a_transform(sources):
    r = to("SecurityEvent | where A == 1 | project X = tolower(A)", "kql")
    assert r["unsupported"] and r["query"] == "A: 1"


def test_kql_summarize_keeps_the_filter_and_is_unsupported(sources, monkeypatch):
    monkeypatch.setattr(llm, "translate", lambda *a, **k: pytest.fail("no LLM for summarize"))
    r = to("SecurityEvent | where EventID == 4625 | summarize count() by A | where count_ > 10",
           "kql")
    assert r["query"] == "EventID: 4625" and pipeline.status_for(r) == "unsupported"
    assert "`summarize`, `where` have no equivalent" in r["warnings"][0]


def test_kql_condition_gap_goes_to_the_llm(sources, monkeypatch):
    seen = []
    monkeypatch.setattr(llm, "translate", lambda text, target, **k: seen.append((target, k)) or
                        {"query": "CommandLine: mimikatz", "confidence": 0.5, "warnings": []})
    r = to('SecurityEvent | where CommandLine has "mimikatz"', "kql")
    assert seen == [("elk", {"source": "kql", "base": None})]
    assert r["method"] == "llm" and pipeline.status_for(r) == "needs-review"
    assert r["no_rule"] == ["condition"]


def test_kql_unmapped_table_still_converts_but_is_flagged(workspace):
    r = to('Other | where A == 1', "kql")
    assert r["query"] == "A: 1"
    assert "no index pattern for KQL table Other" in r["warnings"][0]


def test_field_names_through_the_splunk_field_map(sources):
    """KQL column -> Splunk field (exact kql entry) -> Elastic field (elk entry)."""
    config.MAPPINGS_DIR.mkdir(parents=True, exist_ok=True)
    (config.MAPPINGS_DIR / "field_map.json").write_text(json.dumps({
        "kql": {"SecurityEvent": {"fields": {"EventCode": {"to": "EventID", "level": "exact"}}}},
        "elk": {"logs-system.security-*": {"fields": {
            "EventCode": {"to": "event.code", "level": "exact"},
            "user": {"to": "user.name", "level": "conditional", "note": "logon events"}}}}}))
    r = to('SecurityEvent | where EventID == 4625 and user == "x"', "kql")
    assert r["query"] == 'event.code: 4625 and user.name: "x"'
    assert "field 'user' mapped to user.name (logon events)" in text_of(r)
    assert "field names kept" not in text_of(r)


# ---- XQL ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("xql, want", [
    ('dataset = xdr_data | filter event_id = 4625', "event_id: 4625"),
    ('dataset = xdr_data | filter a = "PROCESS"', 'a: "PROCESS"'),
    ('dataset = xdr_data | filter a = "*powershell*"', "a: *powershell*"),
    ('dataset = xdr_data | filter a contains "-enc"', "a: *-enc*"),
    ('dataset = xdr_data | filter a in ("x", "y")', 'a: ("x" or "y")'),
    ('dataset = xdr_data | filter a != null', "a: *"),
    ('dataset = xdr_data | filter a = null', "not a: *"),
    ('dataset = xdr_data | filter a = 1 and b > 2', "a: 1 and b > 2"),
    ('dataset = xdr_data | filter (a = 1 or b = 2)', "a: 1 or b: 2"),
    ('dataset = xdr_data | filter a = 1 | filter b = 2 | fields a, b | sort desc a', "a: 1 and b: 2"),
])
def test_xql_conditions(sources, xql, want):
    r = to(xql, "xql")
    assert r["query"] == want and r["method"] == "rules"


def test_xql_case_insensitive_by_default_but_not_with_config(sources):
    assert "XQL matched a case-insensitively" in text_of(
        to('dataset = xdr_data | filter a = "X"', "xql"))
    r = to('config case_sensitive = true | dataset = xdr_data | filter a = "X"', "xql")
    assert "case-insensitively" not in text_of(r) and r["query"] == 'a: "X"'


def test_xql_not_equal_null_handling_is_flagged(sources):
    for q in ('a != "x"', 'a not in ("x")', "not (a = 1)"):
        assert "XQL null handling" in text_of(to(f"dataset = xdr_data | filter {q}", "xql")), q


def test_xql_timeframe_goes_to_the_rule(sources):
    r = to("config timeframe = 7d | dataset = xdr_data | filter a = 1", "xql")
    assert "time range `config timeframe (7d)` dropped" in r["warnings"][0]


def test_xql_default_dataset_and_comp(sources):
    r = to("filter a = 1 | comp count() as n by b", "xql")
    assert r["query"] == "a: 1" and r["unsupported"] and r["index"] == "logs-system.security-*"


@pytest.mark.parametrize("q", ['a contains "x*"', 'a in ("x*")'])
def test_xql_undocumented_star_is_a_gap(sources, monkeypatch, q):
    monkeypatch.setattr(llm, "translate", lambda *a, **k: {"query": "", "unsupported": True,
                                                           "confidence": 0, "warnings": ["n/a"]})
    r = to(f"dataset = xdr_data | filter {q}", "xql")
    assert r["no_rule"] == ["condition"]


def test_invalid_input_never_reaches_the_llm(workspace, monkeypatch):
    monkeypatch.setattr(llm, "translate", lambda *a, **k: pytest.fail("must not call the LLM"))
    assert "must start with a table" in to("| where a == 1", "kql")["warnings"][0]
    assert to("config nope = 1 | filter a = 1", "xql")["unsupported"]


def test_prompt_for_kql_to_elk(workspace):
    p = llm.build_prompt('SecurityEvent | where A has "x"', "elk", source="kql")
    assert "event filter of this KQL" in p and elk.DOC in p and "Drop time ranges" in p
    assert "Start the SPL" not in p


# ---- CLI targets ---------------------------------------------------------------------------------

def test_run_kql_files_to_elk(sources):
    d = config.SRC_DIR.parent / "kql" / "win"
    d.mkdir(parents=True)
    (d / "q.kql").write_text("SecurityEvent | where EventID == 4625\n")
    assert pipeline.run(["elk"], workers=1, source="kql") == {"needs-review": 1}
    assert (config.OUT_DIR / "elk" / "win" / "q.elk").read_text().strip() == "EventID: 4625"
    meta = json.loads((config.META_DIR / "win" / "q.elk.json").read_text())
    assert meta["index"] == "logs-system.security-*" and meta["source"] == "kql"
