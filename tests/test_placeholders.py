"""Unmapped Splunk sources -> editable EDIT_ME_ placeholders (rules.py, mappings.py)."""
import json

import pytest

from siemx import config, llm, mappings, pipeline, rules


@pytest.fixture
def det(workspace, sources_map):
    def write(rel, text):
        f = config.SRC_DIR / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text, encoding="utf-8")
        return f
    return write


def test_placeholder_keeps_the_detections_spelling(sources_map):
    r = rules.first_stage('index=* sourcetype="WinEventLog" EventCode=4104', "kql")
    assert r == "EDIT_ME_WinEventLog\n| where EventCode == 4104"
    assert r.warnings[0] == ("KQL: no table is mapped for sourcetype=wineventlog; the query "
                             "uses the placeholder EDIT_ME_WinEventLog. Replace it here, or set "
                             "it once in mappings/sources.json")


def test_index_only_and_special_characters(sources_map):
    assert rules.first_stage("index=proxy x=1", "xql").startswith("dataset = EDIT_ME_proxy")
    assert rules.first_stage("sourcetype=a:b-c x=1", "kql").startswith("EDIT_ME_a_b_c")
    assert rules.first_stage("index=* x=1", "kql").startswith("EDIT_ME_any")


def test_placeholder_output_is_needs_review_not_llm(det, monkeypatch):
    monkeypatch.setattr(llm, "translate", lambda *a, **k: pytest.fail("rules handle this"))
    r = pipeline.convert_query("sourcetype=wineventlog EventCode=4688 | stats count by host",
                               "kql")
    assert r["method"] == "rules" and r["query"].startswith("EDIT_ME_wineventlog\n")
    assert pipeline.status_for(r) == "needs-review"


def test_elk_records_the_placeholder_index(det):
    r = pipeline.convert_query("sourcetype=wineventlog EventCode=4688", "elk")
    assert r["query"] == "EventCode: 4688" and r["index"] == "EDIT_ME_wineventlog"


def test_llm_is_told_to_use_the_placeholder(det, monkeypatch):
    monkeypatch.setattr(llm, "retrieve", lambda *a, **k: {"docs": [], "examples": [],
                                                          "field_map": {}})
    p = llm.build_prompt("sourcetype=wineventlog | transaction host", "xql")
    assert "start the query with exactly `dataset = EDIT_ME_wineventlog`" in p
    assert "EDIT_ME" not in llm.build_prompt("index=wineventlog | transaction host", "kql")
    seen = {}
    monkeypatch.setattr(llm, "translate", lambda text, target, **k: seen.setdefault("q", text)
                        and {"query": "EDIT_ME_wineventlog | take 1", "confidence": 0.5,
                             "warnings": []})
    r = pipeline.convert_query("sourcetype=wineventlog | transaction host", "kql")
    assert "uses the placeholder EDIT_ME_wineventlog" in r["warnings"][0]


def test_missing_lists_sources_case_insensitively(det):
    det("a/one.spl", "index=* sourcetype=wineventlog EventCode=1")
    det("a/two.spl", "sourcetype=WinEventLog EventCode=2")
    det("b/three.spl", "index=wineventlog EventCode=3")                      # mapped
    det("b/four.spl", "index=proxy url=*")
    found = mappings.missing_sources(sorted(config.SRC_DIR.rglob("*.spl")))
    assert {k: len(v) for k, v in found.items()} == {"sourcetype=wineventlog": 2,
                                                     "index=proxy": 1}


def test_write_adds_placeholders_and_keeps_existing_entries(det, sources_map):
    added = mappings.write_placeholders(["sourcetype=wineventlog", "index=wineventlog"],
                                        sources_map)
    assert added == ["sourcetype=wineventlog"]
    data = json.loads(sources_map.read_text())
    assert data["index=wineventlog"] == {"kql": "SecurityEvent", "xql": "dataset = xdr_data"}
    assert data["sourcetype=wineventlog"] == {"kql": "EDIT_ME_wineventlog",
                                              "xql": "dataset = EDIT_ME_wineventlog",
                                              "elk": "EDIT_ME_wineventlog"}
    assert mappings.write_placeholders(["sourcetype=WINEVENTLOG"], sources_map) == []


def test_written_placeholder_stays_flagged_until_edited(det, sources_map):
    det("w/q.spl", "sourcetype=wineventlog EventCode=1")
    mappings.write_placeholders(["sourcetype=wineventlog"], sources_map)
    assert pipeline.run(["kql"], workers=1) == {"needs-review": 1}
    meta = json.loads((config.META_DIR / "w" / "q.kql.json").read_text())
    assert "uses the placeholder EDIT_ME_wineventlog" in meta["warnings"][0]

    data = json.loads(sources_map.read_text())                               # analyst edits
    data["sourcetype=wineventlog"]["kql"] = "SecurityEvent"
    sources_map.write_text(json.dumps(data))
    assert pipeline.run(["kql"], workers=1) == {"needs-review": 1}            # re-converted
    assert (config.OUT_DIR / "kql" / "w" / "q.kql").read_text().startswith("SecurityEvent\n")
    meta = json.loads((config.META_DIR / "w" / "q.kql.json").read_text())
    assert not any("placeholder" in w for w in meta["warnings"])
