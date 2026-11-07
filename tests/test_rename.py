"""SPL rename -> KQL project-rename / XQL alter + fields -. Doc links in siemx/rules.py."""
import pytest

from siemx import pipeline, rules


@pytest.mark.parametrize("spl, kql, xql", [
    ("rename _ip AS IPAddress",
     "project-rename IPAddress = _ip",
     "alter IPAddress = _ip\n| fields - _ip"),
    ("rename a as b",                         # lowercase as (input already runs in Splunk)
     "project-rename b = a",
     "alter b = a\n| fields - a"),
    ("rename a AS b, c AS d",
     "project-rename b = a, d = c",
     "alter b = a, d = c\n| fields - a, c"),
    ("rename a AS b c AS d",                  # space-separated pairs
     "project-rename b = a, d = c",
     "alter b = a, d = c\n| fields - a, c"),
    ("rename a AS b,c AS d",
     "project-rename b = a, d = c",
     "alter b = a, d = c\n| fields - a, c"),
])
def test_rename(spl, kql, xql):
    assert rules.stage(spl, "kql") == kql
    assert not isinstance(rules.stage(spl, "kql"), rules.Flagged)
    x = rules.stage(spl, "xql")
    assert x == xql
    assert isinstance(x, rules.Flagged) and x.warnings == [rules.XQL_RENAME_WARNING]


def test_rename_quoted_and_keyword_names_kql():
    assert (rules.stage('rename count AS "Count of Events"', "kql")
            == "project-rename ['Count of Events'] = ['count']")
    assert rules.stage('rename "src ip" AS src_ip', "kql") == "project-rename src_ip = ['src ip']"


def test_rename_special_names_unsupported_xql():
    assert rules.stage('rename count AS "Count of Events"', "xql") is None
    assert rules.stage("rename user-name AS user", "xql") is None


@pytest.mark.parametrize("spl", [
    "rename",
    "rename a",
    "rename a b",                 # missing AS
    "rename a AS",
    "rename AS b",
    "rename usr* AS user*",       # wildcard
    "rename a AS b*",
    "rename a AS b, a AS c",      # one field, two names: invalid SPL
    "rename a AS c, b AS c",      # two fields, one name
    "rename a AS b, b AS c",      # chained: order semantics unclear
    "rename a AS b, b AS a",      # swap
    'rename "" AS b',
])
def test_rename_unsupported(spl):
    assert rules.stage(spl, "kql") is None
    assert rules.stage(spl, "xql") is None


def test_rename_end_to_end(sources_map, no_llm):
    spl = ("index=wineventlog | stats count by host | rename host AS Computer "
           "| sort - count | head 5")
    kql = pipeline.convert_query(spl, "kql")
    assert kql["query"] == ("SecurityEvent\n| summarize ['count'] = count() by host\n"
                            "| project-rename Computer = host\n| sort by ['count'] desc\n| take 5")
    assert pipeline.status_for(kql) == "auto-approved"
    xql = pipeline.convert_query(spl, "xql")
    assert xql["query"] == ("dataset = xdr_data\n| comp count() as count by host\n"
                            "| alter Computer = host\n| fields - host\n| sort desc count\n| limit 5")
    assert pipeline.status_for(xql) == "needs-review"
