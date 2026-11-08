"""Starter-rule tests. Each case: SPL stage -> expected KQL and XQL.

These pin current behaviour; they do not prove the mappings are correct.
Doc references for the expected output (verify before relying on a rule):
  KQL project:   https://learn.microsoft.com/kusto/query/project-operator
  KQL take:      https://learn.microsoft.com/kusto/query/take-operator
  KQL summarize: https://learn.microsoft.com/kusto/query/summarize-operator
  KQL sort:      https://learn.microsoft.com/kusto/query/sort-operator
  XQL fields / limit / comp / sort: Cortex XQL reference, "Stages"
"""
import pytest

from siemx import rules


@pytest.mark.parametrize("spl, kql, xql", [
    # table / fields
    ("table host user", "project host, user", "fields host, user"),
    ("table host, user", "project host, user", "fields host, user"),
    ("fields host", "project host", "fields host"),
    # head
    ("head 10", "take 10", "limit 10"),
    # stats count: output column must be named `count`, as in SPL
    ("stats count", "summarize ['count'] = count()", "comp count() as count"),
    ("stats count by host", "summarize ['count'] = count() by host",
     "comp count() as count by host"),
    ("stats count by host, user", "summarize ['count'] = count() by host, user",
     "comp count() as count by host, user"),
    # sort (single field); `count` is a KQL keyword -> quoted
    # sort: SPL default limit 10,000 is explicit (dropped when a smaller head follows)
    ("sort - count", "sort by ['count'] desc\n| take 10000", "sort desc count\n| limit 10000"),
    ("sort -count", "sort by ['count'] desc\n| take 10000", "sort desc count\n| limit 10000"),
    ("sort + host", "sort by host asc\n| take 10000", "sort asc host\n| limit 10000"),
    ("sort host", "sort by host asc\n| take 10000", "sort asc host\n| limit 10000"),
])
def test_stage_rule(spl, kql, xql):
    assert rules.stage(spl, "kql") == kql
    assert rules.stage(spl, "xql") == xql


@pytest.mark.parametrize("spl", [
    "head",                          # bare head (SPL default 10) not mapped yet
    "head count>5",                  # eval-expression form
    "stats count(user) by host",     # field-level count
    'rex field=_raw "(?<u>\\w+)"',
    "transaction host",
    "unknowncmd foo",
])
def test_stage_without_rule_returns_none(spl):
    """No rule -> None so the pipeline falls back to the LLM, never a guess."""
    assert rules.stage(spl, "kql") is None
    assert rules.stage(spl, "xql") is None


def test_where_rule():
    assert rules.stage("where count > 5", "kql") == "where ['count'] > 5"
    assert rules.stage("where count > 5", "xql") == "filter count > 5"
    assert not isinstance(rules.stage("where count > 5", "kql"), rules.Flagged)


def test_where_rule_flags_review_items():
    r = rules.stage('where user="admin"', "xql")
    assert isinstance(r, rules.Flagged) and r == 'filter user = "admin"'
    assert r.warnings
    r = rules.stage("where n != 1", "kql")
    assert isinstance(r, rules.Flagged) and r == "where n != 1"


@pytest.mark.parametrize("spl", ["where", 'where like(ip, "10.%")', "where a=1 b=2"])
def test_where_rule_unsupported(spl):
    assert rules.stage(spl, "kql") is None
    assert rules.stage(spl, "xql") is None


@pytest.mark.parametrize("name, quoted", [
    ("host", "host"),
    ("_time", "_time"),
    ("EventID2", "EventID2"),
    ("count", "['count']"),
    ("Count", "['Count']"),       # keyword check is case-insensitive (conservative)
    ("where", "['where']"),
    ("user-name", "['user-name']"),
    ("src.ip", "['src.ip']"),
    ("1day", "['1day']"),
    ("o'brien", "['o\\'brien']"),
])
def test_kql_name(name, quoted):
    assert rules.kql_name(name) == quoted


def test_kql_names_quoted_in_project_and_by():
    assert rules.stage("table count, host", "kql") == "project ['count'], host"
    assert rules.stage("stats count by where", "kql") == "summarize ['count'] = count() by ['where']"
    assert rules.stage("table count, host", "xql") == "fields count, host"


def test_first_stage_maps_known_source(sources_map):
    assert rules.first_stage("index=wineventlog", "kql") == "SecurityEvent"
    assert rules.first_stage("index=wineventlog", "xql") == "dataset = xdr_data"
    assert rules.first_stage("INDEX=WinEventLog", "kql") == "SecurityEvent"


@pytest.mark.parametrize("stage", [
    "index=wineventlog EventCode=4625",   # leftover terms need translation
    "index=unknown",
    "search index=wineventlog",
])
def test_first_stage_unmapped_returns_none(sources_map, stage):
    assert rules.first_stage(stage, "kql") is None


def test_first_stage_unknown_target(sources_map):
    assert rules.first_stage("index=wineventlog", "esql") is None


def test_first_stage_missing_mapping_file(tmp_path, monkeypatch):
    monkeypatch.setattr(rules, "MAP_FILE", tmp_path / "nope.json")
    assert rules.first_stage("index=wineventlog", "kql") is None
