"""SPL lookup -> KQL lookup on a Sentinel watchlist / XQL left join on a lookup dataset.
Always flagged for review. Doc links in siemx/rules.py."""
import pytest

from siemx import pipeline, rules


@pytest.mark.parametrize("spl, kql, xql", [
    ("lookup usertogroup user AS local_user OUTPUT group AS user_group",
     "lookup kind=leftouter (_GetWatchlist('usertogroup') | project user, user_group = group) "
     "on $left.local_user == $right.user",
     "join type = left (dataset = usertogroup | fields user as lookup_key_1, group as user_group) "
     "as lk lk.lookup_key_1 = local_user\n| fields - lookup_key_1"),
    ("lookup prices_lookup Code OUTPUT product_name",
     "lookup kind=leftouter (_GetWatchlist('prices_lookup') | project Code, product_name) on Code",
     "join type = left (dataset = prices_lookup | fields Code as lookup_key_1, product_name) "
     "as lk lk.lookup_key_1 = Code\n| fields - lookup_key_1"),
    ("lookup assets.csv ip OUTPUT owner, site",               # .csv stripped
     "lookup kind=leftouter (_GetWatchlist('assets') | project ip, owner, site) on ip",
     "join type = left (dataset = assets | fields ip as lookup_key_1, owner, site) "
     "as lk lk.lookup_key_1 = ip\n| fields - lookup_key_1"),
    ("lookup t a, b as bb output c",                           # two keys, lowercase keywords
     "lookup kind=leftouter (_GetWatchlist('t') | project a, b, c) on a, $left.bb == $right.b",
     "join type = left (dataset = t | fields a as lookup_key_1, b as lookup_key_2, c) "
     "as lk lk.lookup_key_1 = a and lk.lookup_key_2 = bb\n| fields - lookup_key_1, lookup_key_2"),
])
def test_lookup_always_flagged(spl, kql, xql):
    for t, want in (("kql", kql), ("xql", xql)):
        r = rules.stage(spl, t)
        assert r == want
        assert isinstance(r, rules.Flagged) and len(r.warnings) == 1
        assert "must exist as" in r.warnings[0]


def test_lookup_warning_names_the_table_and_columns():
    w = rules.stage("lookup assets.csv ip OUTPUT owner", "kql").warnings[0]
    assert "'assets.csv'" in w and "watchlist 'assets'" in w and "ip, owner" in w


def test_lookup_kql_keyword_columns_quoted():
    r = rules.stage("lookup t count OUTPUT from", "kql")
    assert r == "lookup kind=leftouter (_GetWatchlist('t') | project ['count'], ['from']) on ['count']"


def test_lookup_effects():
    r = rules.stage("lookup t user AS u OUTPUT g AS grp, h", "kql")
    assert (r.reads, r.add) == (["u"], ["grp", "h"])


@pytest.mark.parametrize("spl", [
    "lookup",
    "lookup t",
    "lookup t user",                         # no OUTPUT: unknown columns
    "lookup t user OUTPUTNEW g",             # fill-only-if-missing semantics
    "lookup t user OUTPUT",
    "lookup t OUTPUT g",
    "lookup t user AS OUTPUT g",
    "lookup local=true t user OUTPUT g",     # options
    "lookup t user OUTPUT g update=true",
    "lookup t user OUTPUT user",             # same name as key
    "lookup t a, a OUTPUT g",
    "lookup t user OUTPUT g AS x, h AS x",
    "lookup bad/name user OUTPUT g",
    "lookup t 'odd field' OUTPUT g",
])
def test_lookup_unsupported(spl):
    assert rules.stage(spl, "kql") is None
    assert rules.stage(spl, "xql") is None


def test_lookup_hyphenated_alias_kql_only():
    assert rules.stage("lookup my-list ip OUTPUT owner", "kql").startswith(
        "lookup kind=leftouter (_GetWatchlist('my-list')")
    assert rules.stage("lookup my-list ip OUTPUT owner", "xql") is None


def test_lookup_end_to_end_needs_review(sources_map, no_llm):
    spl = "index=wineventlog | lookup admins Computer OUTPUT owner | stats count by owner"
    kql = pipeline.convert_query(spl, "kql")
    assert kql["method"] == "rules"
    assert pipeline.status_for(kql) == "needs-review"
    assert not any("owner" in w and "not in SecurityEvent" in w for w in kql["warnings"])
