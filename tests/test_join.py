"""SPL join [subsearch] -> KQL join / XQL join. Always flagged. Doc links in siemx/rules.py."""
import json

import pytest

from siemx import pipeline, rules, schema


@pytest.fixture
def two_sources(tmp_path, monkeypatch):
    f = tmp_path / "sources.json"
    f.write_text(json.dumps({
        "index=wineventlog": {"kql": "SecurityEvent", "xql": "dataset = xdr_data"},
        "index=proxy": {"kql": "CommonSecurityLog", "xql": "dataset = proxy_raw"},
    }))
    monkeypatch.setattr(rules, "MAP_FILE", f)


STATS_SUB = "[search index=proxy | stats count by host]"


def test_join_inner_kql(two_sources):
    r = rules.stage(f"join host {STATS_SUB}", "kql")
    assert r == ("join kind=inner (\n"
                 "    CommonSecurityLog\n"
                 "    | where isnotempty(host)\n"
                 "    | summarize ['count'] = count() by host\n"
                 ") on host")
    assert isinstance(r, rules.Flagged)
    assert r.warnings[0] == rules.JOIN_WARNING.format(T="KQL", conflict=rules.JOIN_KQL_CONFLICT)


def test_join_inner_xql(two_sources):
    r = rules.stage(f"join host {STATS_SUB}", "xql")
    assert r == ("join type = inner (dataset = proxy_raw\n"
                 "    | filter host != null\n"
                 "    | comp count() as count by host\n"
                 "    | alter join_key_1 = host\n"
                 "    | fields - host) as sub sub.join_key_1 = host\n"
                 "| fields - join_key_1")
    assert r.warnings[0] == rules.JOIN_WARNING.format(T="XQL", conflict=rules.JOIN_XQL_CONFLICT)


@pytest.mark.parametrize("opt, kql_kind, xql_type", [
    ("type=inner", "inner", "inner"),
    ("type=left", "leftouter", "left"),
    ("type=outer", "leftouter", "left"),          # SPL: outer == left
])
def test_join_types(two_sources, opt, kql_kind, xql_type):
    assert rules.stage(f"join {opt} host {STATS_SUB}", "kql").startswith(f"join kind={kql_kind} (")
    assert rules.stage(f"join {opt} host {STATS_SUB}", "xql").startswith(f"join type = {xql_type} (")


def test_join_max0_any_subsearch(two_sources):
    r = rules.stage("join max=0 host [search index=proxy | where a=1]", "kql")
    assert r == "join kind=inner (\n    CommonSecurityLog\n    | where a == 1\n) on host"
    assert r.multiplies is True


@pytest.mark.parametrize("sub", [
    "[search index=proxy | stats count by host]",
    "[search index=proxy | dedup host]",
    "[search index=proxy | top host showperc=f]",
    "[search index=proxy | stats count]",                         # one row
    "[search index=proxy | stats count by host | where count > 5 | sort - count]",
    "[search index=proxy | stats count by host | eval n = count * 2]",
    "[index=proxy | stats count by host]",                         # no leading 'search'
])
def test_join_max1_unique_subsearch_ok(two_sources, sub):
    assert rules.stage(f"join host {sub}", "kql") is not None
    assert rules.stage(f"join host {sub}", "xql") is not None


@pytest.mark.parametrize("sub", [
    "[search index=proxy | where a=1]",                            # many rows per key
    "[search index=proxy | stats count by host, user]",            # unique on (host,user)
    "[search index=proxy | stats count by host | eval host = lower(host)]",
    "[search index=proxy | stats count by host | rename host AS h]",
    "[search index=proxy | stats count by host | lookup t host OUTPUT g]",
])
def test_join_max1_not_unique_is_none(two_sources, sub):
    assert rules.stage(f"join host {sub}", "kql") is None
    assert rules.stage(f"join host {sub}", "xql") is None


def test_join_two_keys(two_sources):
    r = rules.stage("join host, user [search index=proxy | stats count by host, user]", "kql")
    assert r.endswith(") on host, user")
    x = rules.stage("join host user [search index=proxy | stats count by host, user]", "xql")
    assert "sub.join_key_1 = host and sub.join_key_2 = user" in x
    assert x.endswith("| fields - join_key_1, join_key_2")


def test_join_subsearch_warnings_propagate(two_sources):
    r = rules.stage('join max=0 host [search index=proxy | where u="x"]', "xql")
    assert any(w.startswith("subsearch: XQL: case sensitivity") for w in r.warnings)


def test_join_effects(two_sources):
    r = rules.stage(f"join host {STATS_SUB}", "kql")
    assert r.reads == ["host"] and r.add == ["count"] and r.order == {"loses"}
    assert r.multiplies is False


@pytest.mark.parametrize("spl", [
    "join host",                                                   # no subsearch
    f"join {STATS_SUB}",                                           # no field list
    f"join usetime=true host {STATS_SUB}",
    f"join earlier=false host {STATS_SUB}",
    f"join overwrite=false host {STATS_SUB}",
    f"join max=5 host {STATS_SUB}",
    f"join type=right host {STATS_SUB}",
    f"join left=L right=R where L.a=R.b {STATS_SUB}",
    f"join host {STATS_SUB} | head 5",
    "join host [search index=unknown | stats count by host]",     # unmapped source
    'join host [search index=proxy | rex "(?<a>x)" | stats count by host]',
    "join host [search index=proxy | stats count by host",         # unbalanced
    f"join host, host {STATS_SUB}",
])
def test_join_unsupported(two_sources, spl):
    assert rules.stage(spl, "kql") is None
    assert rules.stage(spl, "xql") is None


def test_split_subsearch():
    assert rules.split_subsearch('a [search x "]" | y]') == ("a ", 'search x "]" | y')
    assert rules.split_subsearch("a [x [y] z]") == ("a ", "x [y] z")
    assert rules.split_subsearch("a [x] b") is None
    assert rules.split_subsearch("a x") is None


def test_unique_after():
    st = rules.stage("stats count by a", "kql")
    assert schema.unique_after(["T", st]) == {"a"}
    assert schema.unique_after(["T", st, rules.stage("head 5", "kql")]) == {"a"}
    assert schema.unique_after(["T", st, rules.stage("table count", "kql")]) is None
    assert schema.unique_after(["T", rules.stage("where a=1", "kql")]) is None


def test_join_with_untranslatable_subsearch_goes_to_llm(two_sources, monkeypatch):
    """`stats values()` has no rule -> the whole query falls back to the LLM."""
    calls = []

    def stub(spl, target):
        calls.append(target)
        return {"query": "", "confidence": 0.0, "unsupported": True, "warnings": [], "tokens": 0}

    monkeypatch.setattr(pipeline.llm, "translate", stub)
    spl = ("index=wineventlog | stats count by host | join type=left host "
           "[search index=proxy | stats values(user) as u by host]")
    res = pipeline.convert_query(spl, "kql")
    assert calls == ["kql"] and res["method"] == "llm"


def test_join_end_to_end_rules(two_sources, no_llm):
    spl = ("index=wineventlog | stats count by host | sort - count "
           f"| join type=left host {STATS_SUB}")
    res = pipeline.convert_query(spl, "kql")
    assert res["method"] == "rules"
    assert res["query"] == ("SecurityEvent\n| where isnotempty(host)\n| summarize ['count'] = count() by host\n"
                            "| sort by ['count'] desc\n| take 10000\n"
                            "| join kind=leftouter (\n"
                            "    CommonSecurityLog\n"
                            "    | where isnotempty(host)\n"
                            "    | summarize ['count'] = count() by host\n"
                            ") on host")
    assert pipeline.status_for(res) == "needs-review"
