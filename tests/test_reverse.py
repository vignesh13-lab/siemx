"""Roadmap 7 (part 1): KQL -> SPL. Doc references in siemx/reverse.py and siemx/kql_expr.py."""
import json

import pytest

from siemx import cli, config, kql_expr, pipeline, reverse

S = "SecurityEvent\n"


def spl(kql):
    return reverse.convert(kql)


# ---- expressions ----------------------------------------------------------------------------------

@pytest.mark.parametrize("kql, out", [
    ("EventID == 4625", "EventID==4625"),
    ("EventID == 1 and LogonType in (3, 10)", "EventID==1 AND (LogonType==3 OR LogonType==10)"),
    ("EventID == 1 or EventID == 2 and LogonType == 3",              # and binds tighter
     "EventID==1 OR (EventID==2 AND LogonType==3)"),
    ('Account =~ "Admin"', 'lower(Account)=="admin"'),
    ('CommandLine contains "-ENC"', 'like(lower(CommandLine), "%-enc%")'),
    ('Computer startswith "dc"', 'like(lower(Computer), "dc%")'),
    ('Computer endswith "$"', 'like(lower(Computer), "%$")'),
    ('Account in~ ("A", "b")', 'in(lower(Account), "a", "b")'),
    ("not(EventID == 1)", "NOT (EventID==1)"),
    ("isnotempty(IpAddress)", 'isnotnull(IpAddress) AND IpAddress!=""'),     # top level
    ("isempty(IpAddress)", 'isnull(IpAddress) OR IpAddress==""'),
    ("isempty(IpAddress) and EventID == 1",                                  # nested: kept
     '(isnull(IpAddress) OR IpAddress=="") AND EventID==1'),
    ("['count'] > 5", "count>5"),
    ("strlen(tolower(CommandLine)) > 100", "len(lower(CommandLine))>100"),
])
def test_conditions(kql, out):
    r = kql_expr.condition(kql)
    assert r.text == out


@pytest.mark.parametrize("kql, out", [
    ('iff(EventID == 4625, "fail", "ok")', 'if(EventID==4625, "fail", "ok")'),
    ('strcat(Account, "@", Computer)', '(Account . "@" . Computer)'),
    ("coalesce(IpAddress, WorkstationName)", "coalesce(IpAddress, WorkstationName)"),
    ("todouble(x) * 8 + 1", "tonumber(x) * 8 + 1"),
    ("(a + b) * c", "(a + b) * c"),
])
def test_values(kql, out):
    assert kql_expr.value(kql).text == out


@pytest.mark.parametrize("kql, warning", [
    ("x != 1", "!= is false when the field is missing"),
    ("a / b > 1", "division is floating point"),
    ('Account !contains "x"', "!= is false"),
])
def test_caveats(kql, warning):
    assert any(warning in w for w in kql_expr.condition(kql).warnings)


@pytest.mark.parametrize("kql, reason", [
    ('Account has "adm"', "'has' has no exact SPL equivalent"),
    ('Process endswith "a_b"', "% or _ in a like() pattern"),
    ('Account contains "50%"', "% or _ in a like() pattern"),
    ("Account =~ OtherColumn", "non-literal"),
    ("foo(x) > 1", "function foo() not supported"),
    ('Path == "C:\\\\x"', "backslash"),
    ("x == true", "boolean literal"),
])
def test_unsupported_expressions(kql, reason):
    with pytest.raises(kql_expr.Unsupported, match=reason.replace("(", r"\(").replace(")", r"\)")):
        kql_expr.condition(kql)


# ---- operators and whole queries -------------------------------------------------------------------

@pytest.mark.parametrize("kql, out", [
    (S + "| where EventID == 4625 | take 10", "index=wineventlog | where EventID==4625 | head 10"),
    (S + "| where TimeGenerated > ago(1d) and EventID == 4625",
     "index=wineventlog earliest=-1d | where EventID==4625"),
    (S + "| where TimeGenerated >= ago(30m)", "index=wineventlog earliest=-30m"),
    (S + "| summarize count() by Computer | sort by count_",                 # KQL sort = desc
     "index=wineventlog | stats count AS count_ by Computer | sort 0 -count_"),
    (S + "| sort by Computer asc, EventID", "index=wineventlog | sort 0 +Computer, -EventID"),
    (S + "| summarize n = count(), u = dcount(TargetUserName), s = sum(EventID)",
     "index=wineventlog | stats count AS n, dc(TargetUserName) AS u, sum(EventID) AS s"),
    (S + "| summarize max(EventID) by Computer",
     "index=wineventlog | stats max(EventID) AS max_EventID by Computer"),
    (S + "| top 5 by EventID", "index=wineventlog | sort 0 -EventID | head 5"),
    (S + "| project Computer, Account", "index=wineventlog | table Computer, Account"),
    (S + "| project-away EventData", "index=wineventlog | fields - EventData"),
    (S + "| project-rename Host = Computer", "index=wineventlog | rename Computer AS Host"),
    (S + "| extend n = strlen(CommandLine), m = n * 2",
     "index=wineventlog | eval n = len(CommandLine), m = n * 2"),
    (S + "| count", "index=wineventlog | stats count AS Count"),
    (S + "| distinct Computer, Account",
     "index=wineventlog | stats count by Computer, Account | fields - count"),
    ("SecurityEvent // comment | not a pipe\n| take 1", "index=wineventlog | head 1"),
])
def test_queries(sources_map, kql, out):
    r = spl(kql)
    assert not r.get("unsupported"), r["warnings"]
    assert r["query"] == out


@pytest.mark.parametrize("kql, reason", [
    ("SecurityEvent | where Account has 'x'", "'has'"),
    ("SecurityEvent | mv-expand x", "KQL operator 'mv-expand'"),
    ("CommonSecurityLog | take 1", "no SPL source in mappings/sources.json maps to CommonSecurityLog"),
    ("SecurityEvent | where TimeGenerated > ago(1d) or EventID == 1", "time expressions"),
    ("SecurityEvent | sort by Computer nulls first", "sort key"),
    ("SecurityEvent | project x = EventID + 1", "expressions or special names"),
    ("SecurityEvent | summarize countif(EventID == 1)", "aggregation"),
    ("let x = 1; SecurityEvent", "must start with a table name"),
])
def test_unsupported_queries(sources_map, kql, reason):
    r = spl(kql)
    assert r.get("unsupported") and reason in r["warnings"][0]
    assert pipeline.status_for(r) == "unsupported"


def test_warnings(sources_map):
    r = spl(S + "| summarize u = dcount(TargetUserName) by Computer")
    assert any("dcount() is an estimate" in w for w in r["warnings"])
    assert any("keeps them as an empty group" in w for w in r["warnings"])
    cols = [w for w in r["warnings"] if "column names are the KQL table's" in w][0]
    assert "Computer, TargetUserName" in cols and "u" not in cols.split(": ")[-1].split(", ")


def test_several_sources_for_a_table(tmp_path, monkeypatch):
    from siemx import rules
    f = tmp_path / "s.json"
    f.write_text(json.dumps({"index=a": {"kql": "SecurityEvent"},
                             "index=b sourcetype=x": {"kql": "SecurityEvent"}}))
    monkeypatch.setattr(rules, "MAP_FILE", f)
    r = spl("SecurityEvent | take 1")
    assert r["query"] == "index=b sourcetype=x | head 1"            # most specific
    assert any("several Splunk sources" in w for w in r["warnings"])


def test_exact_field_mappings_are_reversed(sources_map, tmp_path, monkeypatch):
    mdir = tmp_path / "m"
    (mdir / "clients" / "acme").mkdir(parents=True)
    (mdir / "clients" / "acme" / "field_map.json").write_text(json.dumps({"kql": {"SecurityEvent": {
        "fields": {"user": {"to": "TargetUserName", "level": "exact"},
                   "host": {"to": "Computer", "level": "conditional"}}}}}))
    monkeypatch.setattr(config, "MAPPINGS_DIR", mdir)
    monkeypatch.setattr(config, "CLIENT", "acme")
    r = spl(S + "| summarize count() by TargetUserName, Computer")
    assert r["query"] == "index=wineventlog | stats count AS count_ by user, Computer"
    assert any("no exact reverse mapping for: Computer" in w for w in r["warnings"])


# ---- round trips: KQL -> SPL (reverse) -> KQL (forward) ----------------------------------------------

@pytest.mark.parametrize("kql", [
    "SecurityEvent\n| where EventID == 4625\n| take 10",
    "SecurityEvent\n| project Computer, Account",
    "SecurityEvent\n| project-rename Host = Computer",
    "SecurityEvent\n| extend n = strlen(CommandLine)",
    "SecurityEvent\n| project-away EventData",
])
def test_round_trip_identity(sources_map, no_llm, kql):
    """Where both directions are exact, going there and back gives the original."""
    there = spl(kql)["query"]
    back = pipeline.convert_query(there, "kql")["query"]
    assert back == kql


# ---- pipeline / CLI -------------------------------------------------------------------------------------

def test_convert_from_kql(workspace, monkeypatch, capsys):
    src = config.SRC_DIR.parent / "kql" / "windows" / "failed.kql"
    src.parent.mkdir(parents=True)
    src.write_text("SecurityEvent\n| where EventID == 4625\n| summarize count() by Computer")
    monkeypatch.setattr("sys.argv", ["siemx", "convert", "--from", "kql", "--workers", "1"])
    cli.main()
    assert json.loads(capsys.readouterr().out.strip().splitlines()[-1])["summary"] == {"needs-review": 1}
    out = (config.OUT_DIR / "spl" / "windows" / "failed.spl").read_text()
    assert out.startswith("index=wineventlog | where EventID==4625 | stats count AS count_ by Computer")
    meta = json.loads((config.META_DIR / "windows" / "failed.spl.json").read_text())
    assert meta["src"] == "detections/kql/windows/failed.kql" and meta["source"] == "kql"
    assert pipeline.run(["spl"], workers=1, source="kql") == {"skipped": 1}


def test_split_pipes_respects_strings_and_brackets():
    q = 'T | where a == "x|y" | join (U | where b == 1) on c | extend d = @"p|q"'
    assert reverse.split_pipes(q) == ["T", 'where a == "x|y"', "join (U | where b == 1) on c",
                                      'extend d = @"p|q"']
