"""Kibana KQL (ELK) -> KQL / XQL (from_elk.py), directly. No network, no Node."""
import json

import pytest

from siemx import config, llm, pipeline, validate

BS = "\\"
H = "# index: logs-system.security-*\n"


@pytest.fixture(autouse=True)
def no_kql_parser(monkeypatch):
    monkeypatch.setattr(validate.KqlValidator, "available", staticmethod(lambda: False))


@pytest.fixture
def sources(workspace, sources_map):
    sources_map.write_text(json.dumps({"sourcetype=XmlWinEventLog:Security": {
        "kql": "SecurityEvent", "xql": "dataset = xdr_data", "elk": "logs-system.security-*"}}))


def conv(q, target):
    return pipeline.convert_any(H + q, target, "elk")


def where(r):
    return r["query"].split("\n| ", 1)[1].split(" ", 1)[1] if r["query"] else ""


def text_of(r):
    return " | ".join(r["warnings"])


# ---- ELK -> KQL ---------------------------------------------------------------------------------

@pytest.mark.parametrize("elk, want", [
    ("EventCode: 4625", "EventCode == 4625"),
    ('user: "Bob"', 'user == "Bob"'),
    ("user: Bob", 'user == "Bob"'),
    ('not user: "SYSTEM"', 'not(user == "SYSTEM")'),
    ("EventCode: (4624 or 4625)", "EventCode == 4624 or EventCode == 4625"),
    ("a: 1 and (b: 2 or c: 3)", "a == 1 and (b == 2 or c == 3)"),
    ("a: 1 or b: 2 and c: 3", "a == 1 or (b == 2 and c == 3)"),
    ("p: *-enc*", 'p contains_cs "-enc"'),
    ("p: svc_*", 'p startswith_cs "svc_"'),
    (f"p: *{BS}{BS}cmd.exe", f'p endswith_cs @"{BS}cmd.exe"'),
    ("p: a*b*c", 'p matches regex "^a.*b.*c$"'),
    ('p: "x*y"', 'p == "x*y"'),
    (f"p: x{BS}*y", 'p == "x*y"'),
    ("u: *", "isnotempty(u)"),
    ("bytes > 100 and bytes <= 200", "bytes > 100 and bytes <= 200"),
    ("event.code: 1", "['event.code'] == 1"),
])
def test_elk_to_kql(sources, elk, want):
    r = conv(elk, "kql")
    assert r["query"].startswith("SecurityEvent\n| where ") and where(r) == want
    assert r["method"] == "rules"


def test_kql_string_vs_number_column(sources):
    """A quoted number stays a string; a known string column gets a string."""
    assert where(conv('c: "4625"', "kql")) == 'c == "4625"'
    (config.FIELDS_FILE).write_text(json.dumps({"kql": {"SecurityEvent": {
        "fields": ["Code"], "types": {"Code": "string"}}}}))
    assert where(conv("Code: 4625", "kql")) == 'Code == "4625"'


def test_kql_notes(sources):
    r = conv('u: "Bob" and v: *', "kql")
    t = text_of(r)
    assert "matched words, not whole values: u. Use has / has_cs" in t
    assert "isnotempty() excludes empty strings" in t
    assert "field names kept from Elastic (u, v)" in t
    assert pipeline.status_for(r) == "needs-review"


# ---- ELK -> XQL ---------------------------------------------------------------------------------

@pytest.mark.parametrize("elk, want, cs", [
    ("EventCode: 4625", "EventCode = 4625", False),
    ('user: "Bob"', 'user = "Bob"', True),
    ("p: *powershell*", 'p = "*powershell*"', True),
    (f"p: *{BS}{BS}cmd.exe", f'p = "*{BS}cmd.exe"', True),
    ("EventCode: (1 or 2)", "EventCode = 1 or EventCode = 2", False),
    ("a: 1 or b: 2 and c: 3", "a = 1 or (b = 2 and c = 3)", False),
    ("u: *", "u != null", False),
    ("not a: 1", "not (a = 1)", False),
])
def test_elk_to_xql(sources, elk, want, cs):
    r = conv(elk, "xql")
    head = "config case_sensitive = true\n| dataset = xdr_data" if cs else "dataset = xdr_data"
    assert r["query"] == f"{head}\n| filter {want}"


def test_xql_not_is_flagged(sources):
    assert "XQL null handling" in text_of(conv("not a: 1", "xql"))


def test_xql_dotted_elastic_name_needs_a_mapping(sources, monkeypatch):
    monkeypatch.setattr(llm, "translate", lambda *a, **k: pytest.fail("no LLM: a mapping gap"))
    r = conv("event.code: 1", "xql")
    assert r["unsupported"] and "has no XQL name; map it" in r["warnings"][0]


@pytest.mark.parametrize("q", ['a: "x*y"', 'a: "say \\"hi\\""', f"a: x{BS}*y*"])
def test_xql_values_without_a_rule_go_to_the_llm(sources, monkeypatch, q):
    seen = {}
    monkeypatch.setattr(llm, "translate", lambda text, target, **k: seen.update(k) or
                        {"query": "", "unsupported": True, "confidence": 0, "warnings": ["no"]})
    r = conv(q, "xql")
    assert seen == {"source": "elk", "base": "dataset = xdr_data"} and r["unsupported"]


# ---- shared --------------------------------------------------------------------------------------

def test_field_names_through_the_splunk_field_map(sources):
    """Elastic field -> Splunk field (exact "elk" entry) -> KQL column ("kql" entry)."""
    config.MAPPINGS_DIR.mkdir(parents=True, exist_ok=True)
    (config.MAPPINGS_DIR / "field_map.json").write_text(json.dumps({
        "elk": {"logs-system.security-*": {"fields": {
            "EventCode": {"to": "event.code", "level": "exact"}}}},
        "kql": {"SecurityEvent": {"fields": {"EventCode": {"to": "EventID", "level": "exact"}}}},
        "xql": {"xdr_data": {"fields": {"EventCode": {"to": "action_evtlog_event_id",
                                                      "level": "conditional",
                                                      "note": "Windows events"}}}}}))
    assert where(conv("event.code: 4625", "kql")) == "EventID == 4625"
    r = conv("event.code: 4625", "xql")
    assert r["query"].endswith("filter action_evtlog_event_id = 4625")
    assert "mapped to action_evtlog_event_id (conditional: Windows events)" in text_of(r)


@pytest.mark.parametrize("q, reason", [
    ("free text", "free-text"), ("u: { a: 1 }", "nested"), ('t > "2026-01-01"', "non-number"),
    ("a: null", "null literal"), ("a*: 1", "wildcard"),
])
def test_rule_gaps_go_to_the_llm_with_the_table(sources, monkeypatch, q, reason):
    seen = {}
    monkeypatch.setattr(llm, "translate", lambda text, target, **k: seen.update(k) or
                        {"query": "SecurityEvent | where x", "confidence": 0.5, "warnings": []})
    r = conv(q, "kql")
    assert seen["base"] == "SecurityEvent" and reason in r["no_rule"][0]
    assert r["method"].startswith("llm") and "keeps the Elastic field names" in r["warnings"][-1]


def test_no_table_never_reaches_the_llm(sources, monkeypatch):
    monkeypatch.setattr(llm, "translate", lambda *a, **k: pytest.fail("must not call the LLM"))
    assert "names no index pattern" in pipeline.convert_any("a: 1", "kql", "elk")["warnings"][0]
    r = pipeline.convert_any("# index: logs-x-*\na: 1", "xql", "elk")
    assert "no XQL dataset in mappings/sources.json for the index pattern logs-x-*" in \
        r["warnings"][0]
    assert "invalid Kibana KQL" in conv("a:1 b:2", "kql")["warnings"][0]


def test_prompt(workspace):
    p = llm.build_prompt(H + "free text", "xql", source="elk", base="dataset = xdr_data")
    assert "Query exactly this dataset: dataset = xdr_data" in p
    assert "config case_sensitive = true" in p and "Start the SPL" not in p


def test_run_elk_files_to_kql_and_xql(sources):
    d = config.SRC_DIR.parent / "elk" / "win"
    d.mkdir(parents=True)
    (d / "q.elk").write_text(H + "EventCode: 4625\n")
    assert pipeline.run(["kql", "xql"], workers=1, source="elk") == {"needs-review": 2}
    assert (config.OUT_DIR / "kql" / "win" / "q.kql").read_text().strip() == (
        "SecurityEvent\n| where EventCode == 4625")
    assert (config.OUT_DIR / "xql" / "win" / "q.xql").read_text().strip() == (
        "dataset = xdr_data\n| filter EventCode = 4625")
