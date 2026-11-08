"""The repo's shared mappings (mappings/sources.json, field_map.json): every entry has
evidence, and the Windows Security mapping behaves as documented in mappings/SOURCES.md."""
import json
from pathlib import Path

import pytest

from siemx import config, fieldmap, pipeline, rules, search

REPO = Path(__file__).resolve().parent.parent
FIELD_MAP = json.loads((REPO / "mappings" / "field_map.json").read_text(encoding="utf-8"))
SOURCES = json.loads((REPO / "mappings" / "sources.json").read_text(encoding="utf-8"))
OFFICIAL = ("https://learn.microsoft.com/", "https://github.com/elastic/",
            "https://cortex-docs.paloaltonetworks.com/", "https://www.elastic.co/")


@pytest.mark.parametrize("target, table", [("elk", "logs-system.security-*"),
                                           ("xql", "xdr_data")])
def test_new_sections_have_evidence(target, table):
    section = FIELD_MAP[target][table]
    assert section["sources"] and all(s.startswith(OFFICIAL) for s in section["sources"])
    for name, e in section["fields"].items():
        assert e["level"] in ("conditional", "ambiguous"), name     # never exact when shared
        assert e.get("note"), name
        assert e.get("to") or e.get("candidates"), name


def test_xql_maps_only_documented_columns():
    """EventData lives in action_evtlog_data_fields (a JSON string), not in columns."""
    documented = {"action_evtlog_event_id", "agent_hostname"}
    assert {e["to"] for e in FIELD_MAP["xql"]["xdr_data"]["fields"].values()} <= documented


def test_every_sources_entry_parses_and_names_all_targets():
    for key, v in SOURCES.items():
        if key.startswith("_"):
            continue
        assert search.parse_meta(key) is not None, key
        assert {"kql", "xql"} <= set(v), key


def test_bare_wineventlog_sourcetype_is_not_mapped():
    """WinEventLog / XmlWinEventLog hold every channel; the table depends on the source."""
    keys = {k.lower() for k in SOURCES}
    assert "sourcetype=wineventlog" not in keys and "sourcetype=xmlwineventlog" not in keys


@pytest.fixture
def repo_mappings(monkeypatch, workspace):
    monkeypatch.setattr(rules, "MAP_FILE", REPO / "mappings" / "sources.json")
    monkeypatch.setattr(config, "MAPPINGS_DIR", REPO / "mappings")


@pytest.mark.parametrize("spl", [
    "sourcetype=XmlWinEventLog source=XmlWinEventLog:Security EventCode=4625",
    "index=clienta source=XmlWinEventLog:Security EventCode=4625",
    "sourcetype=WinEventLog source=WinEventLog:Security EventCode=4625",
    "sourcetype=WinEventLog:Security EventCode=4625",
])
def test_security_sources_reach_all_three_targets(repo_mappings, spl):
    assert pipeline.convert_query(spl, "kql")["query"].startswith("SecurityEvent\n| where EventID == 4625")
    assert "action_evtlog_event_id = 4625" in pipeline.convert_query(spl, "xql")["query"]
    r = pipeline.convert_query(spl, "elk")
    assert r["query"] == "event.code: 4625" and r["index"] == "logs-system.security-*"


def test_wildcard_on_an_ip_field_is_flagged(repo_mappings):
    r = pipeline.convert_query("source=WinEventLog:Security Source_Network_Address=10.*", "elk")
    assert r["query"] == "source.ip: 10.*"
    assert any("has the ip type in Elastic" in w for w in r["warnings"])


def test_logon_type_keeps_the_number(repo_mappings):
    r = pipeline.convert_query("source=WinEventLog:Security Logon_Type=3", "elk")
    assert r["query"] == "winlog.event_data.LogonType: 3"


def test_account_name_is_never_guessed(repo_mappings):
    r = pipeline.convert_query('source=WinEventLog:Security Account_Name="bob"', "elk")
    assert r["query"] == 'Account_Name: "bob"'
    assert any("'Account_Name' is ambiguous" in w for w in r["warnings"])


def test_shared_map_is_loaded_by_table(repo_mappings):
    assert fieldmap.table_map("elk", "logs-system.security-*")["EventCode"]["to"] == "event.code"
