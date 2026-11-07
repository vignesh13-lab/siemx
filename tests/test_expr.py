"""SPL eval-expression subset -> KQL / XQL. See siemx/expr.py for doc references."""
import pytest

from siemx import expr


@pytest.mark.parametrize("spl, kql, xql", [
    # comparisons; = and == are both equality in SPL
    ("count > 5", "['count'] > 5", "count > 5"),
    ("n >= 2.5", "n >= 2.5", "n >= 2.5"),
    ("n<10", "n < 10", "n < 10"),
    ("n <= 10", "n <= 10", "n <= 10"),
    ("EventCode=4625", "EventCode == 4625", "EventCode = 4625"),
    ("EventCode==4625", "EventCode == 4625", "EventCode = 4625"),
    # precedence: NOT > AND > OR; mixed groups are parenthesized explicitly
    ("a=1 AND b=2", "a == 1 and b == 2", "a = 1 and b = 2"),
    ("a=1 OR b=2 OR c=3", "a == 1 or b == 2 or c == 3", "a = 1 or b = 2 or c = 3"),
    ("a=1 AND b=2 OR c=3", "(a == 1 and b == 2) or c == 3", "(a = 1 and b = 2) or c = 3"),
    ("a=1 OR b=2 AND c=3", "a == 1 or (b == 2 and c == 3)", "a = 1 or (b = 2 and c = 3)"),
    ("(a=1 OR b=2) AND c=3", "(a == 1 or b == 2) and c == 3", "(a = 1 or b = 2) and c = 3"),
    ("NOT a=1", "not(a == 1)", "not (a = 1)"),
    ("NOT (a=1 OR b=2)", "not(a == 1 or b == 2)", "not (a = 1 or b = 2)"),
    ("NOT a=1 AND b=2", "not(a == 1) and b == 2", "not (a = 1) and b = 2"),
    ("((a=1))", "a == 1", "a = 1"),
    # single-quoted SPL field names
    ("'user-name'=5", "['user-name'] == 5", None),   # XQL quoting unverified
    ("'n'>1", "n > 1", "n > 1"),
])
def test_translate_no_warnings(spl, kql, xql):
    k = expr.translate(spl, "kql")
    assert k is not None and k.text == kql and k.warnings == []
    x = expr.translate(spl, "xql")
    if xql is None:
        assert x is None
    else:
        assert x is not None and x.text == xql and x.warnings == []


def test_string_literal_kql_clean_xql_flagged():
    k = expr.translate('user="admin"', "kql")
    assert (k.text, k.warnings) == ('user == "admin"', [])
    x = expr.translate('user="admin"', "xql")
    assert x.text == 'user = "admin"'
    assert len(x.warnings) == 1 and "case sensitivity" in x.warnings[0]


def test_string_escapes_kept_for_kql():
    assert expr.translate(r'msg="say \"hi\""', "kql").text == r'msg == "say \"hi\""'


@pytest.mark.parametrize("spl", ['u="a*b"', r'u="a\\b"', r'u="say \"hi\""'])
def test_xql_rejects_wildcard_and_escapes(spl):
    """XQL "..." treats * as a wildcard and only triple quotes process escapes."""
    assert expr.translate(spl, "xql") is None
    assert expr.translate(spl, "kql") is not None


def test_not_equal_flagged_for_null_semantics():
    for t in ("kql", "xql"):
        r = expr.translate("n != 5", t)
        assert r.text == "n != 5"
        assert any("null" in w for w in r.warnings)


def test_field_to_field():
    """Unquoted RHS is a field in SPL, not a string."""
    assert expr.translate("src=dest", "kql").text == "src == dest"
    assert expr.translate("src=dest", "xql") is None   # not verified for XQL


def test_warnings_not_duplicated():
    r = expr.translate('a!="x" AND b!="y"', "xql")
    assert len(r.warnings) == len(set(r.warnings)) == 2


@pytest.mark.parametrize("spl", [
    "",
    'like(ip, "10.%")',          # function
    "isnull(user)",
    "a % b > 5",                 # modulo not supported (a+b > 5 is: see test_eval)
    "n > -1",                    # negative numbers unsupported
    "a=1 XOR b=2",
    "a=1 and b=2",               # lowercase boolean words: ambiguous
    "a=1 AND",                   # dangling
    "(a=1",                      # unbalanced
    "a=1)",
    "a",                         # no comparison
    "a = = 1",
    "a=1 b=2",                   # implicit AND is search syntax, not where
    "n > 1.2.3",
    "a=1 | b",
    "ip = 10.0.0.1",
])
def test_unsupported_returns_none(spl):
    assert expr.translate(spl, "kql") is None
    assert expr.translate(spl, "xql") is None
