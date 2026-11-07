r"""SPL rex -> KQL extract() / XQL regextract(). Doc links in siemx/rules.py."""
import pytest

from siemx import pipeline, rules


@pytest.mark.parametrize("spl, kql, xql", [
    (r'rex field=cmd "user=(?<user>\w+)"',
     r'extend user = extract(@"user=(\w+)", 1, cmd)',
     r'alter user = regextract(cmd, "user=(\w+)")'),
    # two named groups: KQL by index, XQL one capturing group per call
    (r'rex field=cmd "(?<user>\w+);(?<app>\w+)"',
     r'extend user = extract(@"(\w+);(\w+)", 1, cmd), app = extract(@"(\w+);(\w+)", 2, cmd)',
     r'alter user = regextract(cmd, "(\w+);(?:\w+)"), app = regextract(cmd, "(?:\w+);(\w+)")'),
    # unnamed group before a named one shifts the index
    (r'rex field=cmd "(\d+)-(?<code>\d+)"',
     r'extend code = extract(@"(\d+)-(\d+)", 2, cmd)',
     r'alter code = regextract(cmd, "(?:\d+)-(\d+)")'),
    # parentheses inside a character class or escaped are not groups
    (r'rex field=cmd "[(](?<a>\d+)\)"',
     r'extend a = extract(@"[(](\d+)\)", 1, cmd)',
     r'alter a = regextract(cmd, "[(](\d+)\)")'),
    # non-capturing groups and inline flags are kept
    (r'rex field=cmd "(?i)(?:x|y)(?P<a>\d+)"',
     r'extend a = extract(@"(?i)(?:x|y)(\d+)", 1, cmd)',
     r'alter a = regextract(cmd, "(?i)(?:x|y)(\d+)")'),
    (r'rex field=cmd max_match=1 "(?<a>\d+)"',
     r'extend a = extract(@"(\d+)", 1, cmd)',
     r'alter a = regextract(cmd, "(\d+)")'),
])
def test_rex(spl, kql, xql):
    k = rules.stage(spl, "kql")
    assert k == kql and not isinstance(k, rules.Flagged)
    x = rules.stage(spl, "xql")
    assert x == xql
    assert isinstance(x, rules.Flagged) and x.warnings == [rules.XQL_REX_WARNING]


def test_rex_quote_in_regex():
    """SPL \" inside the regex -> KQL verbatim string doubles it; XQL rejected."""
    spl = r'rex field=cmd "say \"(?<q>\w+)\""'
    assert rules.stage(spl, "kql") == r'extend q = extract(@"say ""(\w+)""", 1, cmd)'
    assert rules.stage(spl, "xql") is None


def test_rex_keyword_group_names_quoted_in_kql():
    r = rules.stage(r'rex field=msg "From: <(?<from>.*)> To: <(?<to>.*)>"', "kql")
    assert r.startswith("extend ['from'] = extract(") and ", ['to'] = extract(" in r


def test_rex_effects():
    r = rules.stage(r'rex field=cmd "(?<user>\w+);(?<app>\w+)"', "kql")
    assert (r.reads, r.add) == (["cmd"], ["user", "app"])


@pytest.mark.parametrize("spl", [
    "rex",
    r'rex "user=(?<user>\w+)"',                        # default field _raw
    r'rex field=_raw "user=(?<user>\w+)"',
    r'rex field=cmd "user=(\w+)"',                     # no named group
    r'rex field=cmd max_match=0 "(?<a>\w+)"',
    r'rex field=cmd mode=sed "s/a/b/g"',
    r'rex field=cmd offset_field=o "(?<a>\w+)"',
    r'rex field=cmd "(?<=x)(?<a>\w+)"',                # lookbehind
    r'rex field=cmd "(?<!x)(?<a>\w+)"',
    r'rex field=cmd "(?=x)(?<a>\w+)"',                 # lookahead
    r'rex field=cmd "(?!x)(?<a>\w+)"',
    r'rex field=cmd "(?<a>\w)\1"',                     # backreference
    r'rex field=cmd "(?<a>\w)\k<a>"',
    r'rex field=cmd "(?>(?<a>\w+))"',                  # atomic group
    r'rex field=cmd "(?<a>\w++)"',                     # possessive
    r'rex field=cmd "(?<a>\w+)\Z"',
    r'rex field=cmd "(?<a>a\\b)"',                     # \\ escaping ambiguous
    r'rex field=cmd "(?<a>x)(?<a>y)"',                 # duplicate name
    r'rex field=cmd "(?<cmd>\w+) (?<b>\w+)"',          # overwrites source while reading
    r'rex field=cmd "[(?<a>x)"',                       # unclosed character class
    r'rex field=cmd user=(?<user>\w+)',                # unquoted regex
])
def test_rex_unsupported(spl):
    assert rules.stage(spl, "kql") is None
    assert rules.stage(spl, "xql") is None


def test_rex_end_to_end(sources_map, no_llm, monkeypatch):
    spl = (r'index=wineventlog | rex field=Computer "^(?<site>[a-z]+)-" '
           "| stats count by site | sort - count")
    kql = pipeline.convert_query(spl, "kql")
    assert kql["query"] == ("SecurityEvent\n"
                            "| extend site = extract(@\"^([a-z]+)-\", 1, Computer)\n"
                            "| summarize ['count'] = count() by site\n"
                            "| sort by ['count'] desc")
    assert pipeline.status_for(kql) == "auto-approved"   # site is known after rex
