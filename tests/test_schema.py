"""Field-name safety check: unknown fields in rule output -> needs-review."""
import json
from pathlib import Path

import pytest

from siemx import config, pipeline, rules, schema

REPO_FIELDS = Path(__file__).resolve().parent.parent / "mappings" / "fields.json"


@pytest.fixture
def real_fields(monkeypatch):
    monkeypatch.setattr(config, "FIELDS_FILE", REPO_FIELDS)


def convert(spl, target):
    res = pipeline.convert_query(spl, target)
    return pipeline.status_for(res), res["warnings"]


@pytest.mark.parametrize("first, target, table", [
    ("SecurityEvent", "kql", "SecurityEvent"),
    ("dataset = xdr_data", "xql", "xdr_data"),
    ("dataset=xdr_data", "xql", "xdr_data"),
])
def test_table_of(first, target, table):
    assert schema.table_of(first, target) == table


def test_unknown_field_flagged(sources_map, no_llm, real_fields):
    status, warnings = convert("index=wineventlog | stats count by host", "kql")
    assert status == "needs-review"
    assert len(warnings) == 1 and "host" in warnings[0] and "SecurityEvent" in warnings[0]


def test_real_column_names_auto_approved(sources_map, no_llm, real_fields):
    spl = "index=wineventlog | where EventID=4625 | stats count by Computer | sort - count"
    assert convert(spl, "kql") == ("auto-approved", [])


def test_fields_created_in_query_are_known(sources_map, no_llm, real_fields):
    """count comes from stats; host exists after the rename."""
    spl = ("index=wineventlog | stats count by Computer | rename Computer AS host "
           "| where count > 5 | sort - host")
    assert convert(spl, "kql") == ("auto-approved", [])


def test_fields_dropped_by_stats_are_unknown(sources_map, no_llm, real_fields):
    """After stats, only count and the by-fields exist."""
    spl = "index=wineventlog | stats count by Computer | sort - EventID"
    status, warnings = convert(spl, "kql")
    assert status == "needs-review" and "EventID" in warnings[0]


def test_old_name_unknown_after_rename(sources_map, no_llm, real_fields):
    spl = "index=wineventlog | rename Computer AS host | sort - Computer"
    status, warnings = convert(spl, "kql")
    assert status == "needs-review" and "Computer" in warnings[0]


def test_table_keeps_only_listed_fields(sources_map, no_llm, real_fields):
    spl = "index=wineventlog | table Computer | sort - EventID"
    assert "EventID" in convert(spl, "kql")[1][0]


def test_where_fields_checked(sources_map, no_llm, real_fields):
    status, warnings = convert("index=wineventlog | where EventCode=4625", "kql")
    assert status == "needs-review" and "EventCode" in warnings[0]


def test_each_unknown_field_listed_once(sources_map, no_llm, real_fields):
    spl = "index=wineventlog | where a=1 AND b=2 AND a=3 | sort - b"
    warnings = convert(spl, "kql")[1]
    assert len(warnings) == 1
    assert "(mappings/fields.json): a, b. " in warnings[0]


def test_empty_field_list_flags_everything(sources_map, no_llm, real_fields):
    """xdr_data has no field list yet -> every field read is unverified."""
    status, warnings = convert("index=wineventlog | stats count by host", "xql")
    assert status == "needs-review" and "no field list for xdr_data" in warnings[0]


def test_missing_table_flags_everything(sources_map, no_llm, monkeypatch, tmp_path):
    f = tmp_path / "fields.json"
    f.write_text(json.dumps({"kql": {}}))
    monkeypatch.setattr(config, "FIELDS_FILE", f)
    status, warnings = convert("index=wineventlog | sort - Computer", "kql")
    assert status == "needs-review" and "no field list for SecurityEvent" in warnings[0]


def test_query_without_field_reads_has_no_field_warning(sources_map, no_llm, real_fields):
    """head reads no fields; it is flagged only by the order check."""
    for t in ("kql", "xql"):
        status, warnings = convert("index=wineventlog | head 10", t)
        assert status == "needs-review"
        assert len(warnings) == 1 and "no defined order" in warnings[0]


def test_rule_outputs_report_effects():
    out = rules.stage("stats count by a, b", "kql")
    assert (out.reads, out.only) == (["a", "b"], ["count", "a", "b"])
    out = rules.stage("rename a AS b", "kql")
    assert (out.reads, out.drop, out.add) == (["a"], ["a"], ["b"])
    assert rules.stage("where x=1 OR y>2", "kql").reads == ["x", "y"]
    assert rules.stage("sort - n", "xql").reads == ["n"]
    assert rules.stage("table a b", "xql").only == ["a", "b"]


def test_repo_fields_file_is_valid():
    data = json.loads(REPO_FIELDS.read_text())
    se = data["kql"]["SecurityEvent"]
    assert se["source"].startswith("https://learn.microsoft.com/")
    assert {"Computer", "EventID", "TimeGenerated", "Account"} <= set(se["fields"])
    assert "host" not in se["fields"]
    assert len(se["fields"]) == len(set(se["fields"]))
