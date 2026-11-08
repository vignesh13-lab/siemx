"""stats aggregations, multi-field sort with the SPL 10,000 default, fields -,
and the 'removed by an earlier stage' field warning. Doc links in siemx/rules.py."""
import pytest

from siemx import pipeline, rules


# ---- stats ------------------------------------------------------------------------

@pytest.mark.parametrize("spl, kql, xql", [
    ("stats count", "summarize ['count'] = count()", "comp count() as count"),
    ("stats count by host", "where isnotempty(host)\n| summarize ['count'] = count() by host",
     "filter host != null\n| comp count() as count by host"),
    ("stats count as n by host", "where isnotempty(host)\n| summarize n = count() by host", "filter host != null\n| comp count() as n by host"),
    ("stats c as n", "summarize n = count()", "comp count() as n"),
    ("stats count(user) as n by host", "where isnotempty(host)\n| summarize n = countif(isnotempty(user)) by host",
     "filter host != null\n| comp count(user) as n by host"),
    ("stats sum(bytes) as total by host", "where isnotempty(host)\n| summarize total = sumif(bytes, isnotempty(bytes)) by host",
     "filter host != null\n| comp sum(bytes) as total by host"),
    ("stats avg(dur) as a, min(dur) as lo, max(dur) as hi",
     "summarize a = avgif(dur, isnotempty(dur)), lo = minif(dur, isnotempty(dur)), "
     "hi = maxif(dur, isnotempty(dur))",
     "comp avg(dur) as a, min(dur) as lo, max(dur) as hi"),
    ("stats count, max(t) as last by host, user",
     "where isnotempty(host) and isnotempty(user)\n| summarize ['count'] = count(), last = maxif(t, isnotempty(t)) by host, user",
     "filter host != null and user != null\n| comp count() as count, max(t) as last by host, user"),
    ("stats count BY host", "where isnotempty(host)\n| summarize ['count'] = count() by host",
     "filter host != null\n| comp count() as count by host"),
])
def test_stats_clean(spl, kql, xql):
    k, x = rules.stage(spl, "kql"), rules.stage(spl, "xql")
    assert (k, k.warnings) == (kql, [])
    assert (x, x.warnings) == (xql, [])


def test_stats_dc_kql_flagged_preview():
    k = rules.stage("stats dc(user) as users by host", "kql")
    assert k == "where isnotempty(host)\n| summarize users = count_distinctif(user, isnotempty(user)) by host"
    assert k.warnings == [rules.KQL_DC_WARNING]
    x = rules.stage("stats dc(user) as users by host", "xql")
    assert (x, x.warnings) == ("filter host != null\n| comp count_distinct(user) as users by host", [])


def test_stats_default_names_are_call_text():
    k = rules.stage("stats dc(user) by host", "kql")
    assert k == "where isnotempty(host)\n| summarize ['dc(user)'] = count_distinctif(user, isnotempty(user)) by host"
    assert k.only == ["dc(user)", "host"]
    assert rules.stage("stats sum(bytes)", "kql") == "summarize ['sum(bytes)'] = sumif(bytes, isnotempty(bytes))"
    assert rules.stage("stats dc(user) by host", "xql") is None   # XQL name quoting unverified


def test_stats_effects():
    r = rules.stage("stats count, sum(b) as s by host", "kql")
    assert (r.reads, r.only, r.unique, r.order) == (["host", "b"], ["count", "s", "host"],
                                                    ["host"], {"loses"})


@pytest.mark.parametrize("spl", [
    "stats",
    "stats count(user) by host",            # default name of count(X) not documented
    "stats values(user) by host",
    "stats list(user)",
    "stats estdc(user) as n",
    "stats perc95(x) as p",
    "stats count as n, dc(u) as n",         # duplicate output name
    "stats count as host by host",          # clashes with by field
    "stats count by host, host",
    "stats count by 'odd name'",
    "stats sum(a+b) as s",
    "stats count as",
])
def test_stats_unsupported(spl):
    assert rules.stage(spl, "kql") is None
    assert rules.stage(spl, "xql") is None


# ---- sort -------------------------------------------------------------------------

@pytest.mark.parametrize("spl, kql, xql", [
    ("sort - count, host", "sort by ['count'] desc, host asc\n| take 10000",
     "sort desc count, asc host\n| limit 10000"),
    ("sort -a, +b, c", "sort by a desc, b asc, c asc\n| take 10000",
     "sort desc a, asc b, asc c\n| limit 10000"),
    ("sort 100 -count", "sort by ['count'] desc\n| take 100", "sort desc count\n| limit 100"),
    ("sort 0 -count", "sort by ['count'] desc", "sort desc count"),       # 0 = all
    ("sort _time, -host", "sort by _time asc, host desc\n| take 10000",
     "sort asc _time, desc host\n| limit 10000"),
])
def test_sort(spl, kql, xql):
    assert rules.stage(spl, "kql") == kql
    assert rules.stage(spl, "xql") == xql


@pytest.mark.parametrize("spl", [
    "sort", "sort -", "sort - -a", "sort a, a", "sort num(size)", "sort a desc",
    "sort -str(url)", "sort a*",
])
def test_sort_unsupported(spl):
    assert rules.stage(spl, "kql") is None


def test_sort_limit_dropped_before_smaller_head(sources_map, no_llm):
    res = pipeline.convert_query("index=wineventlog | sort - EventID | head 5", "kql")
    assert res["query"] == "SecurityEvent\n| sort by EventID desc\n| take 5"
    res = pipeline.convert_query("index=wineventlog | sort 3 - EventID | head 5", "kql")
    assert res["query"] == "SecurityEvent\n| sort by EventID desc\n| take 3\n| take 5"
    res = pipeline.convert_query("index=wineventlog | sort - EventID", "xql")
    assert res["query"] == "dataset = xdr_data\n| sort desc EventID\n| limit 10000"


# ---- fields - / fields + -----------------------------------------------------------

def test_fields_minus():
    k = rules.stage("fields - EventData, Channel", "kql")
    assert (k, k.drop) == ("project-away EventData, Channel", ["EventData", "Channel"])
    x = rules.stage("fields - EventData", "xql")
    assert x == "fields - EventData" and x.warnings == [rules.XQL_FIELDS_MINUS_WARNING]


def test_fields_plus_and_bad_names():
    assert rules.stage("fields + a, b", "kql") == "project a, b"
    for spl in ("fields - a*", "fields - 'x y'", "fields a*", "fields -", "fields - a, a"):
        assert rules.stage(spl, "kql") is None, spl


# ---- field warning wording ----------------------------------------------------------

def test_removed_field_warning(sources_map, no_llm):
    res = pipeline.convert_query("index=wineventlog | stats count by Computer | where EventID=4625", "kql")
    assert res["warnings"] == [
        "KQL: field(s) used after an earlier stage removed them (e.g. stats, table, rename): "
        "EventID; verify"]


def test_removed_and_unknown_reported_separately(sources_map, no_llm):
    res = pipeline.convert_query(
        "index=wineventlog | rename Computer AS h | where Computer=1 AND nosuch=2", "kql")
    assert any("removed them" in w and "Computer" in w for w in res["warnings"])
    assert any("not in SecurityEvent" in w and "nosuch" in w for w in res["warnings"])
