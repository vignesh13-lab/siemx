"""SPL timechart -> KQL summarize by bin() / XQL bin + comp. Doc links in siemx/rules.py."""
import pytest

from siemx import pipeline, rules

KQL = ("summarize ['count'] = count() by _time = bin(TimeGenerated, {s})\n"
       "| sort by _time asc")
XQL = "bin _time span = {s}\n| comp count() as count by _time\n| sort asc _time"


@pytest.mark.parametrize("spl, span", [
    ("timechart span=1h count", "1h"),
    ("timechart span=5m count", "5m"),
    ("timechart span=5min count", "5m"),
    ("timechart span=30s count", "30s"),
    ("timechart span=2hr count", "2h"),
    ("timechart count span=15minutes", "15m"),
    ("timechart span=1d count", "1d"),
    ("timechart span=1H count", "1h"),
])
def test_timechart_output(spl, span):
    assert rules.stage(spl, "kql") == KQL.format(s=span)
    assert rules.stage(spl, "xql") == XQL.format(s=span)


def test_default_cont_is_flagged_for_empty_buckets():
    for t in ("kql", "xql"):
        r = rules.stage("timechart span=1h count", t)
        assert isinstance(r, rules.Flagged)
        assert rules.TC_FILL_WARNING.format(T=t.upper()) in r.warnings


def test_cont_false_kql_clean_xql_still_flagged_for_alignment():
    k = rules.stage("timechart span=1h cont=f count", "kql")
    assert k == KQL.format(s="1h") and not isinstance(k, rules.Flagged)
    x = rules.stage("timechart span=1h cont=false count", "xql")
    assert x.warnings == [rules.XQL_TC_ALIGN_WARNING]


def test_day_span_flagged_for_timezone():
    r = rules.stage("timechart span=1d cont=f count", "kql")
    assert r.warnings == [rules.TC_DAY_WARNING.format(T="KQL")]


def test_timechart_effects():
    r = rules.stage("timechart span=1h count", "kql")
    assert (r.reads, r.only, r.order) == (["TimeGenerated"], ["_time", "count"], {"sorts"})
    assert rules.stage("timechart span=1h count", "xql").reads == ["_time"]


@pytest.mark.parametrize("spl", [
    "timechart",
    "timechart count",                          # no span: depends on the time range
    "timechart span=1h count by host",          # wide output, OTHER/NULL columns
    "timechart span=1h avg(bytes)",
    "timechart span=1h dc(user)",
    "timechart span=1h count limit=5",
    "timechart span=1w count",                  # weeks: alignment differs
    "timechart span=1mon count",
    "timechart span=2d count",                  # multi-day
    "timechart span=7h count",                  # does not divide a day
    "timechart span=0h count",
    "timechart span=1 count",                   # unitless (seconds) not handled
    "timechart span=1h cont=maybe count",
])
def test_timechart_unsupported(spl):
    assert rules.stage(spl, "kql") is None
    assert rules.stage(spl, "xql") is None


def test_timechart_end_to_end(sources_map, no_llm):
    spl = "index=wineventlog | where EventID=4625 | timechart span=1h cont=f count"
    kql = pipeline.convert_query(spl, "kql")
    assert kql["query"] == ("SecurityEvent\n| where EventID == 4625\n"
                            "| summarize ['count'] = count() by _time = bin(TimeGenerated, 1h)\n"
                            "| sort by _time asc")
    assert pipeline.status_for(kql) == "auto-approved"
