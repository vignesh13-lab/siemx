"""SPL eval -> KQL extend / XQL alter, and value expressions in where.
Doc references in siemx/expr.py and siemx/rules.py."""
import pytest

from siemx import expr, pipeline, rules

W = {  # warning markers
    "plus": "assumed numeric",
    "concat": "concatenation with fields",
    "div": "division by a field",
}


@pytest.mark.parametrize("spl, kql, xql", [
    # arithmetic; * / bind tighter than + -
    ("eval x = a * 2", "extend x = a * 2", "alter x = multiply(a, 2)"),
    ("eval x = a - 1", "extend x = a - 1", "alter x = subtract(a, 1)"),
    ("eval x = a + 1", "extend x = a + 1", "alter x = add(a, 1)"),
    ("eval x = a + 2 * b", "extend x = a + (2 * b)", "alter x = add(a, multiply(2, b))"),
    ("eval x = (a + 1) * b", "extend x = (a + 1) * b", "alter x = multiply(add(a, 1), b)"),
    ("eval x = a - 1 - 2", "extend x = (a - 1) - 2", "alter x = subtract(subtract(a, 1), 2)"),
    # division: SPL is floating point; KQL int/int truncates -> todouble()
    ("eval kb = bytes / 1024", "extend kb = todouble(bytes) / 1024",
     "alter kb = divide(bytes, 1024)"),
    ("eval h = 7 / 2", "extend h = todouble(7) / 2", "alter h = divide(7, 2)"),
    # functions
    ("eval u = lower(user)", "extend u = tolower(user)", "alter u = lowercase(user)"),
    ("eval u = upper(user)", "extend u = toupper(user)", "alter u = uppercase(user)"),
    ("eval n = len(cmd)", "extend n = strlen(cmd)", "alter n = len(cmd)"),
    ("eval ip = coalesce(src, dst)", "extend ip = coalesce(src, dst)",
     "alter ip = coalesce(src, dst)"),
    ("eval ip = coalesce(src, dst, other)", "extend ip = coalesce(src, dst, other)",
     "alter ip = coalesce(src, dst, other)"),
    ("eval big = if(n > 100, 1, 0)", "extend big = iff(n > 100, 1, 0)",
     "alter big = if(n > 100, 1, 0)"),
    ("eval b = if(n > 1 AND m < 2, n * 2, 0)", "extend b = iff(n > 1 and m < 2, n * 2, 0)",
     "alter b = if(n > 1 and m < 2, multiply(n, 2), 0)"),
    ("eval n = len(lower(cmd))", "extend n = strlen(tolower(cmd))",
     "alter n = len(lowercase(cmd))"),
    # literals and several independent assignments -> one stage
    ("eval a = 1, b = \"x\"", 'extend a = 1, b = "x"', 'alter a = 1, b = "x"'),
    ("eval c = d", "extend c = d", "alter c = d"),
])
def test_eval_clean(spl, kql, xql):
    k, x = rules.stage(spl, "kql"), rules.stage(spl, "xql")
    assert (k, getattr(k, "warnings", [])) == (kql, [])
    assert (x, getattr(x, "warnings", [])) == (xql, [])


def test_eval_dependent_assignments_split_into_stages():
    spl = "eval u = lower(user), n = len(u), z = 1"
    assert rules.stage(spl, "kql") == "extend u = tolower(user)\n| extend n = strlen(u), z = 1"
    assert rules.stage(spl, "xql") == "alter u = lowercase(user)\n| alter n = len(u), z = 1"


def test_eval_overwrite_same_field():
    assert rules.stage("eval a = a * 2", "kql") == "extend a = a * 2"


@pytest.mark.parametrize("spl, kql, xql, warn", [
    ("eval s = a + b", "extend s = a + b", "alter s = add(a, b)", "plus"),
    ('eval m = "u=" . user', 'extend m = strcat("u=", user)',
     'alter m = concat("u=", to_string(user))', "concat"),
    ('eval m = "u=" + user', 'extend m = strcat("u=", user)',
     'alter m = concat("u=", to_string(user))', "concat"),
    ('eval m = a . ":" . b', 'extend m = strcat(a, ":", b)',
     'alter m = concat(to_string(a), ":", to_string(b))', "concat"),
    ('eval m = lower(a) . "x"', 'extend m = strcat(tolower(a), "x")',
     'alter m = concat(lowercase(a), "x")', "concat"),
    ("eval r = a / b", "extend r = todouble(a) / b", "alter r = divide(a, b)", "div"),
])
def test_eval_flagged(spl, kql, xql, warn):
    for t, want in (("kql", kql), ("xql", xql)):
        r = rules.stage(spl, t)
        assert r == want
        assert isinstance(r, rules.Flagged)
        assert any(W[warn] in w for w in r.warnings)


def test_concat_of_literals_only_not_flagged():
    assert rules.stage('eval m = "a" . "b"', "kql") == 'extend m = strcat("a", "b")'
    assert rules.stage('eval m = "a" . 1', "xql") == 'alter m = concat("a", to_string(1))'
    assert not isinstance(rules.stage('eval m = "a" . "b"', "kql"), rules.Flagged)


def test_eval_quoted_names():
    assert rules.stage("eval 'out field' = 'in-field' * 2", "kql") == (
        "extend ['out field'] = ['in-field'] * 2")
    assert rules.stage("eval count = 1", "kql") == "extend ['count'] = 1"
    assert rules.stage("eval 'out field' = a", "xql") is None
    assert rules.stage("eval x = 'in-field'", "xql") is None


@pytest.mark.parametrize("spl", [
    "eval",
    "eval x",
    "eval x =",
    "eval = 1",
    "eval x == 1",
    "eval x = a . b + c",            # . mixed with + : precedence not documented
    "eval x = -a",                   # unary minus
    "eval x = a % 2",                # modulo
    "eval x = a / 0",                # literal division by zero
    "eval x = substr(a, 1, 2)",      # function not supported yet
    "eval x = if(a > 1, 2)",         # SPL if needs 3 arguments
    "eval x = coalesce(a)",          # needs 2 or more for KQL
    "eval x = len(a, b)",
    "eval x = LOWER(a)",             # SPL function names are lowercase
    "eval x = (a + 1",
    "eval x = a, y",
    'eval x = "a*b"',                # XQL wildcard (and KQL is fine) -> see below
])
def test_eval_unsupported(spl):
    if spl == 'eval x = "a*b"':
        assert rules.stage(spl, "kql") == 'extend x = "a*b"'
        assert rules.stage(spl, "xql") is None
        return
    assert rules.stage(spl, "kql") is None
    assert rules.stage(spl, "xql") is None


def test_eval_effects():
    r = rules.stage("eval u = lower(user), n = len(u) + x", "kql")
    assert r.reads == ["user", "x"]          # u is created inside the eval
    assert r.add == ["u", "n"]


def test_split_top_level():
    assert rules.split_top_level('a = f(x, y), b = "1,2"') == ['a = f(x, y)', ' b = "1,2"']
    assert rules.split_top_level("a = (1") is None
    assert rules.split_top_level("a = 1)") is None


# ---- where with value expressions ----------------------------------------------

@pytest.mark.parametrize("spl, kql, xql", [
    ("len(user) > 5", "strlen(user) > 5", "len(user) > 5"),
    ("a * 2 >= b", "(a * 2) >= b", "multiply(a, 2) >= b"),
    ("(a + 1) > 5 AND c=1", "(a + 1) > 5 and c == 1", "add(a, 1) > 5 and c = 1"),
])
def test_where_with_values(spl, kql, xql):
    assert expr.translate(spl, "kql").text == kql
    assert expr.translate(spl, "xql").text == xql


def test_where_lower_compared_to_string_flagged_for_xql():
    r = expr.translate('lower(user) = "admin"', "xql")
    assert r.text == 'lowercase(user) = "admin"'
    assert any("case sensitivity" in w for w in r.warnings)


# ---- end to end -----------------------------------------------------------------

def test_eval_end_to_end(sources_map, no_llm):
    spl = ("index=wineventlog | eval kb = EventID / 1024 | where kb > 1 "
           "| stats count by Computer | sort - count | head 5")
    kql = pipeline.convert_query(spl, "kql")
    assert kql["query"] == ("SecurityEvent\n| extend kb = todouble(EventID) / 1024\n"
                            "| where kb > 1\n| where isnotempty(Computer)\n| summarize ['count'] = count() by Computer\n"
                            "| sort by ['count'] desc\n| take 5")
    assert pipeline.status_for(kql) == "auto-approved"   # kb is known after eval


def test_eval_unknown_input_field_flagged(sources_map, no_llm):
    res = pipeline.convert_query("index=wineventlog | eval x = nosuchfield * 2", "kql")
    assert pipeline.status_for(res) == "needs-review"
    assert "nosuchfield" in res["warnings"][0]
