"""SPL dedup -> KQL arg_max / XQL dedup by desc _time, plus the row-order check.
Doc links in siemx/rules.py and siemx/schema.py."""
import pytest

from siemx import pipeline, rules


@pytest.mark.parametrize("spl, kql, xql", [
    ("dedup host",
     "where isnotempty(host)\n| summarize arg_max(TimeGenerated, *) by host",
     "filter host != null\n| dedup host by desc _time"),
    ("dedup host user",
     "where isnotempty(host) and isnotempty(user)\n"
     "| summarize arg_max(TimeGenerated, *) by host, user",
     "filter host != null and user != null\n| dedup host, user by desc _time"),
    ("dedup host, user",
     "where isnotempty(host) and isnotempty(user)\n"
     "| summarize arg_max(TimeGenerated, *) by host, user",
     "filter host != null and user != null\n| dedup host, user by desc _time"),
])
def test_dedup(spl, kql, xql):
    k = rules.stage(spl, "kql")
    assert k == kql and not isinstance(k, rules.Flagged)
    x = rules.stage(spl, "xql")
    assert x == xql
    assert isinstance(x, rules.Flagged) and x.warnings == [rules.XQL_DEDUP_WARNING]


def test_dedup_keyword_and_dotted_names_kql():
    assert rules.stage("dedup count", "kql") == (
        "where isnotempty(['count'])\n| summarize arg_max(TimeGenerated, *) by ['count']")
    assert rules.stage("dedup src.ip", "kql") == (
        "where isnotempty(['src.ip'])\n| summarize arg_max(TimeGenerated, *) by ['src.ip']")
    assert rules.stage("dedup src.ip", "xql") is None   # XQL quoting not verified


def test_dedup_effects():
    k = rules.stage("dedup host", "kql")
    assert k.reads == ["host", "TimeGenerated"] and k.only is None   # all columns kept
    assert k.order == {"keeps_first", "loses"}
    assert rules.stage("dedup host", "xql").reads == ["host", "_time"]


@pytest.mark.parametrize("spl", [
    "dedup",
    "dedup 3 host",                      # count form
    "dedup host keepempty=true",
    "dedup host keepevents=true",
    "dedup consecutive=true host",
    "dedup host sortby -_time",
    "dedup host host",
    'dedup "my field"',
])
def test_dedup_unsupported(spl):
    assert rules.stage(spl, "kql") is None
    assert rules.stage(spl, "xql") is None


# ---- order check ---------------------------------------------------------------

def status(spl, target="kql"):
    res = pipeline.convert_query(spl, target)
    return pipeline.status_for(res), res["warnings"]


def test_dedup_end_to_end(sources_map, no_llm):
    s, w = status("index=wineventlog | dedup Computer")
    assert (s, w) == ("auto-approved", [])
    s, w = status("index=wineventlog | dedup Computer", "xql")
    assert s == "needs-review" and rules.XQL_DEDUP_WARNING in w


@pytest.mark.parametrize("spl", [
    "index=wineventlog | head 10",                                  # search order
    "index=wineventlog | stats count by host | head 5",             # after stats
    "index=wineventlog | dedup host | head 5",                      # after dedup
    "index=wineventlog | sort - host | stats count by host | head 5",
])
@pytest.mark.parametrize("target", ["kql", "xql"])
def test_head_without_defined_order_flagged(sources_map, no_llm, spl, target):
    s, w = status(spl, target)
    assert s == "needs-review"
    assert any("no defined order" in x for x in w)


@pytest.mark.parametrize("spl", [
    "index=wineventlog | sort - host | head 5",
    "index=wineventlog | stats count by host | sort - count | head 5",
    "index=wineventlog | dedup host | sort host | head 5",
    "index=wineventlog | sort - host | where host=1 | head 5",      # where keeps order
])
def test_head_after_sort_ok(sources_map, no_llm, spl):
    assert status(spl) == ("auto-approved", [])


@pytest.mark.parametrize("spl", [
    "index=wineventlog | sort - user | dedup host",
    "index=wineventlog | stats count by host | dedup host",
])
def test_dedup_after_reorder_flagged(sources_map, no_llm, spl):
    s, w = status(spl)
    assert s == "needs-review"
    assert any("dedup keeps the newest row" in x for x in w)


def test_order_warnings_not_duplicated(sources_map, no_llm):
    s, w = status("index=wineventlog | head 10 | head 5")
    assert len([x for x in w if "no defined order" in x]) == 1
