"""SPL top -> KQL summarize + top / XQL comp + sort + limit. Doc links in siemx/rules.py."""
import pytest

from siemx import pipeline, rules


@pytest.mark.parametrize("spl, kql, xql", [
    ("top 5 user showperc=f",
     "where isnotempty(user)\n| summarize ['count'] = count() by user\n| top 5 by ['count'] desc",
     "filter user != null\n| comp count() as count by user\n| sort desc count\n| limit 5"),
    ("top user showperc=false",                          # default limit 10
     "where isnotempty(user)\n| summarize ['count'] = count() by user\n| top 10 by ['count'] desc",
     "filter user != null\n| comp count() as count by user\n| sort desc count\n| limit 10"),
    ("top limit=3 user showperc=0",
     "where isnotempty(user)\n| summarize ['count'] = count() by user\n| top 3 by ['count'] desc",
     "filter user != null\n| comp count() as count by user\n| sort desc count\n| limit 3"),
    ("top limit=0 user showperc=f",                      # limit=0: all values
     "where isnotempty(user)\n| summarize ['count'] = count() by user\n| sort by ['count'] desc",
     "filter user != null\n| comp count() as count by user\n| sort desc count"),
    ("top 3 user countfield=total showperc=f",
     "where isnotempty(user)\n| summarize total = count() by user\n| top 3 by total desc",
     "filter user != null\n| comp count() as total by user\n| sort desc total\n| limit 3"),
    ("top showperc=f 2 user",                            # N must come first
     None, None),
])
def test_top_without_percent(spl, kql, xql):
    for t, want in (("kql", kql), ("xql", xql)):
        r = rules.stage(spl, t)
        assert r == want
        if want is not None:
            assert not isinstance(r, rules.Flagged)


@pytest.mark.parametrize("spl", ["top user", "top 5 user", "top limit=20 user showperc=t"])
def test_top_with_percent_flagged(spl):
    for t in ("kql", "xql"):
        r = rules.stage(spl, t)
        assert isinstance(r, rules.Flagged)
        assert r.warnings == [rules.TOP_PERCENT_WARNING.format(T=t.upper())]


def test_top_kql_dotted_field_xql_rejected():
    assert rules.stage("top src.ip showperc=f", "kql") == (
        "where isnotempty(['src.ip'])\n| summarize ['count'] = count() by ['src.ip']\n| top 10 by ['count'] desc")
    assert rules.stage("top src.ip showperc=f", "xql") is None


@pytest.mark.parametrize("spl", [
    "top",
    "top action by referer",       # per-group top: not handled yet
    "top a b",                     # multi-field: only last lexicographic value (odd)
    "top user useother=t",
    "top user showcount=f",
    "top user percentfield=p",
    "top user showperc=maybe",
    "top limit=x user",
    "top count",                   # field clashes with the count column
    "top user countfield=user",
    "top user countfield=a-b",
])
def test_top_unsupported(spl):
    assert rules.stage(spl, "kql") is None
    assert rules.stage(spl, "xql") is None


def test_top_effects():
    r = rules.stage("top 5 user countfield=n showperc=f", "kql")
    assert (r.reads, r.only, r.order) == (["user"], ["user", "n"], {"sorts"})


def test_top_end_to_end(sources_map, no_llm):
    spl = "index=wineventlog | top 5 Computer showperc=f | head 3"
    kql = pipeline.convert_query(spl, "kql")
    assert kql["query"] == ("SecurityEvent\n| where isnotempty(Computer)\n| summarize ['count'] = count() by Computer\n"
                            "| top 5 by ['count'] desc\n| take 3")
    assert pipeline.status_for(kql) == "auto-approved"   # top output is sorted


def test_top_percent_used_later_is_flagged_twice(sources_map, no_llm):
    res = pipeline.convert_query("index=wineventlog | top Computer | where percent > 5", "kql")
    assert pipeline.status_for(res) == "needs-review"
    assert any("percent column" in w for w in res["warnings"])
    assert any("percent" in w and "not in SecurityEvent" in w for w in res["warnings"])
