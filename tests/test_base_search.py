r"""Base search (first stage) -> table + where/filter. Doc refs in siemx/search.py."""
import json
from pathlib import Path

import pytest

from siemx import config, pipeline, rules, search

REPO_FIELDS = Path(__file__).resolve().parent.parent / "mappings" / "fields.json"


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Real SecurityEvent field list + types; two source mappings."""
    monkeypatch.setattr(config, "FIELDS_FILE", REPO_FIELDS)
    f = tmp_path / "sources.json"
    f.write_text(json.dumps({
        "index=wineventlog": {"kql": "SecurityEvent", "xql": "dataset = xdr_data"},
        "index=main sourcetype=WinEventLog:Security": {"kql": "SecurityEvent",
                                                       "xql": "dataset = xdr_data"},
    }))
    monkeypatch.setattr(rules, "MAP_FILE", f)


W = "index=wineventlog "


@pytest.mark.parametrize("spl, kql", [
    ("index=wineventlog", "SecurityEvent"),
    ("INDEX=WinEventLog", "SecurityEvent"),
    # numeric value on an int column vs a string column (IpPort is string)
    (W + "EventID=4625", "SecurityEvent\n| where EventID == 4625"),
    (W + "IpPort=445", 'SecurityEvent\n| where IpPort =~ "445"'),
    # case-insensitive string match, wildcards
    (W + "Account=admin", 'SecurityEvent\n| where Account =~ "admin"'),
    (W + "Account=adm*", 'SecurityEvent\n| where Account startswith "adm"'),
    (W + "Account=*adm", 'SecurityEvent\n| where Account endswith "adm"'),
    (W + "CommandLine=*mimikatz*", 'SecurityEvent\n| where CommandLine contains "mimikatz"'),
    (W + "CommandLine=*-enc*bypass*",
     'SecurityEvent\n| where CommandLine matches regex @"(?i)^.*\\-enc.*bypass.*$"'),
    (W + "EventID=46*", 'SecurityEvent\n| where tostring(EventID) startswith "46"'),
    (W + 'Account="John Smith"', 'SecurityEvent\n| where Account =~ "John Smith"'),
    (W + "Account=*", "SecurityEvent\n| where isnotempty(Account)"),
    # precedence: NOT > OR > AND, implicit AND
    (W + "EventID=4624 LogonType=3 OR LogonType=10",
     "SecurityEvent\n| where EventID == 4624 and (LogonType == 3 or LogonType == 10)"),
    (W + "(EventID=4624 LogonType=3) OR EventID=4625",
     "SecurityEvent\n| where (EventID == 4624 and LogonType == 3) or EventID == 4625"),
    (W + "EventID=4624 AND LogonType=3",
     "SecurityEvent\n| where EventID == 4624 and LogonType == 3"),
    # != requires the field; NOT keeps events without the field
    (W + "Account!=SYSTEM", 'SecurityEvent\n| where isnotempty(Account) and not(Account =~ "SYSTEM")'),
    (W + "NOT Account=SYSTEM", 'SecurityEvent\n| where not(isnotempty(Account) and Account =~ "SYSTEM")'),
    (W + "NOT EventID>4600", "SecurityEvent\n| where not(isnotempty(EventID) and EventID > 4600)"),
    # IN
    (W + "EventID IN (4624, 4625)", "SecurityEvent\n| where EventID in (4624, 4625)"),
    (W + "Account IN (admin, root)", 'SecurityEvent\n| where Account in~ ("admin", "root")'),
    (W + "Account IN (admin, root*)",
     'SecurityEvent\n| where Account =~ "admin" or Account startswith "root"'),
    (W + "EventID>4600", "SecurityEvent\n| where EventID > 4600"),
    # sourcetype as part of the mapping key
    ("index=main sourcetype=WinEventLog:Security EventID=4625",
     "SecurityEvent\n| where EventID == 4625"),
])
def test_base_search_kql(env, spl, kql):
    r = rules.first_stage(spl, "kql")
    assert r == kql and r.warnings == []
    assert r.table == "SecurityEvent"


@pytest.mark.parametrize("spl, xql", [
    (W + "EventID=4625", "dataset = xdr_data\n| filter EventID = 4625"),
    (W + "Account=Admin*", 'dataset = xdr_data\n| filter lowercase(Account) = "admin*"'),
    (W + "Account!=SYSTEM",
     'dataset = xdr_data\n| filter Account != null and not (lowercase(Account) = "system")'),
    (W + "NOT Account=SYSTEM",
     'dataset = xdr_data\n| filter not (Account != null and lowercase(Account) = "system")'),
    (W + "Account IN (Admin, root)",
     'dataset = xdr_data\n| filter lowercase(Account) in ("admin", "root")'),
    (W + "Account=*", "dataset = xdr_data\n| filter Account != null"),
])
def test_base_search_xql(env, spl, xql):
    r = rules.first_stage(spl, "xql")
    assert r == xql and r.table == "xdr_data"


def test_backslash_value_flagged(env):
    r = rules.first_stage(W + r'NewProcessName="C:\\Windows\\cmd.exe"', "kql")
    assert r == 'SecurityEvent\n| where NewProcessName =~ @"C:\\Windows\\cmd.exe"'
    assert r.warnings == [search.BACKSLASH_WARNING.format(T="KQL")]


@pytest.mark.parametrize("spl", [
    "EventID=4625",                                   # no index: unknown table
    "index=main EventID=4625",                        # mapping key needs sourcetype too
    W + "sourcetype=other",                           # metadata not in the mapping
    W + "mimikatz",                                   # free text searches _raw
    W + '"failed password"',
    W + "earliest=-24h EventID=4625",                 # time modifiers
    W + "(index=x OR EventID=1)",                     # metadata inside OR
    W + "NOT index=x",
    W + "Account!=*",                                 # never matches in SPL
    W + "Account>abc",                                # lexicographic comparison
    W + "CASE(Admin)",
    W + "TERM(10.0.0.1)",
    W + "(EventID=1",                                 # unbalanced
    W + 'Account="unclosed',
    W + "Account IN ()",
    "index=wineventlog index=other",
    "index=wine*",
])
def test_base_search_unsupported(env, spl):
    assert rules.first_stage(spl, "kql") is None
    assert rules.first_stage(spl, "xql") is None


def test_numeric_comparison_on_string_column(env):
    """IpPort is a string column in SecurityEvent -> KQL refuses; XQL has no types yet."""
    assert rules.first_stage(W + "IpPort>400", "kql") is None
    assert rules.first_stage(W + "IpPort>400", "xql") == "dataset = xdr_data\n| filter IpPort > 400"


def test_parse_meta():
    assert search.parse_meta("index=Main sourcetype=WinEventLog:Security") == {
        "index": "main", "sourcetype": "winevenlog:security".replace("winevenlog", "wineventlog")}
    assert search.parse_meta("index=x EventID=1") is None


def test_base_search_reads_are_field_checked(env, no_llm):
    res = pipeline.convert_query(W + "EventCode=4625 | stats count by Computer", "kql")
    assert res["query"] == ("SecurityEvent\n| where EventCode == 4625\n"
                            "| where isnotempty(Computer)\n| summarize ['count'] = count() by Computer")
    assert pipeline.status_for(res) == "needs-review"
    assert "EventCode" in res["warnings"][0] and "not in SecurityEvent" in res["warnings"][0]


def test_base_search_end_to_end_auto_approved(env, no_llm):
    spl = W + "EventID=4625 Account!=*$ | stats count by Computer | where count > 20"
    res = pipeline.convert_query(spl, "kql")
    assert res["query"] == (
        "SecurityEvent\n"
        '| where EventID == 4625 and (isnotempty(Account) and not(Account endswith "$"))\n'
        "| where isnotempty(Computer)\n"
        "| summarize ['count'] = count() by Computer\n"
        "| where ['count'] > 20")
    assert pipeline.status_for(res) == "auto-approved"


def test_join_subsearch_uses_base_search(env, no_llm):
    r = rules.stage("join Computer [search index=wineventlog EventID=4625 | stats count by Computer]",
                    "kql")
    assert "    SecurityEvent\n    | where EventID == 4625\n" in r
