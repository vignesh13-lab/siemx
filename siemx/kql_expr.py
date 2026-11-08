"""Roadmap 7: KQL expressions -> SPL eval/where expressions (reverse of expr.py).

Supported KQL (anything else -> None, never guessed):
  literals: "x" 'x' @"x", numbers, true/false; columns: Name, ['Name']
  comparisons: == != < <= > >= =~ !~
  string operators: contains !contains startswith endswith (case-insensitive in KQL),
                    in (...) !in (...) in~ (...)
  logic: and, or, not(...)          arithmetic: + - * /
  functions: tolower toupper strlen strcat iff/iif coalesce todouble/toreal tolong toint
             tostring isnull isnotnull isempty isnotempty
Not supported: has (term matching has no exact SPL equivalent), matches regex, datetime /
timespan arithmetic (ago() is handled by reverse.py only as a time filter), dynamic.

SPL notes (help.splunk.com evaluation functions; search-commands/where):
  - where/eval expressions are case-sensitive: ==, != match KQL ==, !=
  - like(str, pattern): % and _ wildcards; case sensitivity and escaping NOT documented,
    so case-insensitive KQL operators become like(lower(x), "<lowercased pattern>"), and
    values containing % or _ are not translated
  - in(): case sensitivity NOT documented, so KQL `in` (case-sensitive) becomes
    (x=="a" OR x=="b"); in~ becomes in(lower(x), "a", "b") with lowercased values
  - isnotempty(x) -> (isnotnull(x) AND x!="") because SPL does not document whether ""
    counts as null; this form is right either way
Caveats returned as warnings: != (KQL true for null, SPL false), division (KQL int/int
truncates, SPL is floating point).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_TOKEN = re.compile(r"""
    (?P<ws>\s+)
  | (?P<vstr>@"(?:[^"]|"")*"|@'(?:[^']|'')*')
  | (?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
  | (?P<qname>\[\s*(?:'[^']*'|"[^"]*")\s*\])
  | (?P<num>\d+(?:\.\d+)?(?![\w.]))
  | (?P<op>==|!=|=~|!~|<=|>=|<|>)
  | (?P<arith>[-+*/])
  | (?P<lp>\()
  | (?P<rp>\))
  | (?P<comma>,)
  | (?P<word>!?[A-Za-z_][A-Za-z0-9_]*~?)
""", re.VERBOSE)

STRING_OPS = {"contains", "!contains", "startswith", "endswith", "in", "!in", "in~"}
FUNCS = {   # KQL -> (SPL name, arg count; None = 1 or more)
    "tolower": ("lower", 1), "toupper": ("upper", 1), "strlen": ("len", 1),
    "coalesce": ("coalesce", None), "todouble": ("tonumber", 1), "toreal": ("tonumber", 1),
    "tolong": ("tonumber", 1), "toint": ("tonumber", 1), "tostring": ("tostring", 1),
    "isnull": ("isnull", 1), "isnotnull": ("isnotnull", 1),
}
W_NE = "SPL: != is false when the field is missing; KQL != is true for null; verify"
W_DIV = ("SPL: division is floating point; KQL int/int division truncates (7/2 = 3); "
         "verify the operand types")


@dataclass
class Rendered:
    text: str
    warnings: list[str] = field(default_factory=list)
    columns: list[str] = field(default_factory=list)


class Unsupported(ValueError):
    pass


def tokenize(s: str) -> list[tuple[str, str]]:
    out, pos = [], 0
    while pos < len(s):
        m = _TOKEN.match(s, pos)
        if not m:
            raise Unsupported(f"cannot read KQL at: {s[pos:pos + 20]!r}")
        pos = m.end()
        kind, val = m.lastgroup, m.group()
        if kind == "ws":
            continue
        if kind == "word" and val.lower() in ("and", "or"):
            kind = val.lower()
        out.append((kind, val))
    return out


def _string_value(tok: str) -> str:
    if tok.startswith("@"):
        q = tok[1]
        return tok[2:-1].replace(q + q, q)
    body = tok[1:-1]
    return re.sub(r"\\(.)", lambda m: {"n": "\n", "t": "\t"}.get(m.group(1), m.group(1)), body)


class _Parser:
    def __init__(self, toks):
        self.t, self.i = toks, 0

    def peek(self, k=0):
        j = self.i + k
        return self.t[j] if j < len(self.t) else (None, None)

    def take(self, kind=None, value=None):
        k, v = self.peek()
        if (kind and k != kind) or (value and v != value):
            raise Unsupported(f"expected {value or kind}, got {v}")
        self.i += 1
        return v

    def expr(self):
        node = self.and_expr()
        while self.peek()[0] == "or":
            self.i += 1
            node = ("or", node, self.and_expr())
        return node

    def and_expr(self):
        node = self.cmp()
        while self.peek()[0] == "and":
            self.i += 1
            node = ("and", node, self.cmp())
        return node

    def cmp(self):
        left = self.add()
        k, v = self.peek()
        if k == "op":
            self.i += 1
            return ("cmp", v, left, self.add())
        if k == "word" and v.lower() in STRING_OPS:
            self.i += 1
            if v.lower() in ("in", "!in", "in~"):
                self.take("lp")
                items = [self.add()]
                while self.peek()[0] == "comma":
                    self.i += 1
                    items.append(self.add())
                self.take("rp")
                return ("in", v.lower(), left, items)
            return ("strop", v.lower(), left, self.add())
        if k == "word" and v.lower() in ("has", "!has", "has_cs", "matches", "between"):
            raise Unsupported(f"KQL '{v}' has no exact SPL equivalent")
        return left

    def add(self):
        node = self.mul()
        while self.peek()[0] == "arith" and self.peek()[1] in "+-":
            op = self.take()
            node = ("arith", op, node, self.mul())
        return node

    def mul(self):
        node = self.primary()
        while self.peek()[0] == "arith" and self.peek()[1] in "*/":
            op = self.take()
            node = ("arith", op, node, self.primary())
        return node

    def primary(self):
        k, v = self.peek()
        if k == "lp":
            self.i += 1
            node = self.expr()
            self.take("rp")
            return ("paren", node)
        if k in ("str", "vstr"):
            self.i += 1
            return ("str", _string_value(v))
        if k == "num":
            self.i += 1
            return ("num", v)
        if k == "qname":
            self.i += 1
            return ("col", re.sub(r"^\[\s*['\"]|['\"]\s*\]$", "", v))
        if k == "word":
            self.i += 1
            if self.peek()[0] == "lp":
                return self.call(v)
            if v in ("true", "false"):
                return ("bool", v)
            return ("col", v)
        raise Unsupported(f"unexpected {v!r}")

    def call(self, name):
        self.take("lp")
        args = []
        if self.peek()[0] != "rp":
            args.append(self.expr())
            while self.peek()[0] == "comma":
                self.i += 1
                args.append(self.expr())
        self.take("rp")
        return ("call", name.lower(), args)


def parse(text: str):
    p = _Parser(tokenize(text))
    node = p.expr()
    if p.i != len(p.t):
        raise Unsupported(f"unexpected {p.t[p.i][1]!r}")
    return node


# ---- render to SPL -----------------------------------------------------------------------------

_SPL_PLAIN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class _Render:
    def __init__(self, rename=None):
        self.warnings: list[str] = []
        self.columns: list[str] = []
        self.rename = rename or {}

    def warn(self, w):
        if w not in self.warnings:
            self.warnings.append(w)

    def col(self, name):
        name = self.rename.get(name, name)
        if name not in self.columns:
            self.columns.append(name)
        return name if _SPL_PLAIN.fullmatch(name) else f"'{name}'"

    @staticmethod
    def string(value):
        if '"' in value or "\\" in value:
            raise Unsupported("quote or backslash inside a string: SPL escaping not verified")
        return f'"{value}"'

    def lower_literal(self, node):
        if node[0] != "str":
            raise Unsupported("case-insensitive comparison with a non-literal")
        return self.string(node[1].lower())

    def like(self, target, pattern_value, shape):
        if "%" in pattern_value or "_" in pattern_value:
            raise Unsupported("% or _ in a like() pattern: SPL escaping not documented")
        pat = shape.format(pattern_value.lower())
        return f"like(lower({self.value(target)}), {self.string(pat)})"

    def value(self, n):
        k = n[0]
        if k == "col":
            return self.col(n[1])
        if k == "str":
            return self.string(n[1])
        if k == "num":
            return n[1]
        if k == "bool":
            raise Unsupported("boolean literal")
        if k == "paren":
            return f"({self.value(n[1])})"
        if k == "arith":
            if n[1] == "/":
                self.warn(W_DIV)
            return f"{self.value(n[2])} {n[1]} {self.value(n[3])}"
        if k == "call":
            return self.call(n)
        return self.cond(n)

    def call(self, n):
        _, name, args = n
        if name in ("iff", "iif"):
            if len(args) != 3:
                raise Unsupported("iff needs 3 arguments")
            return f"if({self.cond(args[0])}, {self.value(args[1])}, {self.value(args[2])})"
        if name == "strcat":
            if not args:
                raise Unsupported("strcat()")
            return "(" + " . ".join(self.value(a) for a in args) + ")"
        if name == "isnotempty":
            x = self.value(args[0])
            return f"(isnotnull({x}) AND {x}!=\"\")"
        if name == "isempty":
            x = self.value(args[0])
            return f"(isnull({x}) OR {x}==\"\")"
        if name not in FUNCS:
            raise Unsupported(f"function {name}() not supported")
        spl, n_args = FUNCS[name]
        if (n_args is None and not args) or (n_args is not None and len(args) != n_args):
            raise Unsupported(f"{name}: wrong number of arguments")
        return f"{spl}({', '.join(self.value(a) for a in args)})"

    def cond(self, n):
        k = n[0]
        if k in ("and", "or"):
            op = " AND " if k == "and" else " OR "
            return f"({self.cond(n[1])}{op}{self.cond(n[2])})"
        if k == "paren":
            return f"({self.cond(n[1])})"
        if k == "call" and n[1] == "not":
            if len(n[2]) != 1:
                raise Unsupported("not() takes one argument")
            return f"NOT ({self.cond(n[2][0])})"
        if k == "call":
            return self.call(n)
        if k == "cmp":
            _, op, a, b = n
            if op == "=~":
                return f"lower({self.value(a)})=={self.lower_literal(b)}"
            if op == "!~":
                self.warn(W_NE)
                return f"lower({self.value(a)})!={self.lower_literal(b)}"
            if op == "!=":
                self.warn(W_NE)
            return f"{self.value(a)}{op}{self.value(b)}"
        if k == "strop":
            _, op, a, b = n
            if b[0] != "str":
                raise Unsupported(f"{op} with a non-literal")
            shape = {"contains": "%{}%", "!contains": "%{}%", "startswith": "{}%",
                     "endswith": "%{}"}[op]
            text = self.like(a, b[1], shape)
            if op.startswith("!"):
                self.warn(W_NE)
                return f"NOT {text}"
            return text
        if k == "in":
            _, op, a, items = n
            if op == "in~":
                vals = ", ".join(self.lower_literal(i) for i in items)
                return f"in(lower({self.value(a)}), {vals})"
            x = self.value(a)
            alts = " OR ".join(f"{x}=={self.value(i)}" for i in items)
            if op == "!in":
                self.warn(W_NE)
                return f"NOT ({alts})"
            return f"({alts})"
        raise Unsupported(f"not a condition: {k}")


def _strip(text: str) -> str:
    """Remove one outer pair of parentheses added for safety."""
    if text.startswith("(") and text.endswith(")"):
        depth = 0
        for i, ch in enumerate(text):
            depth += ch == "("
            depth -= ch == ")"
            if depth == 0 and i < len(text) - 1:
                return text
        return text[1:-1]
    return text


def to_spl_condition(kql: str, rename=None) -> Rendered | None:
    try:
        r = _Render(rename)
        return Rendered(_strip(r.cond(parse(kql))), r.warnings, r.columns)
    except Unsupported:
        return None


def to_spl_value(kql: str, rename=None) -> Rendered | None:
    try:
        r = _Render(rename)
        return Rendered(r.value(parse(kql)), r.warnings, r.columns)
    except Unsupported:
        return None


def condition(kql: str, rename=None) -> Rendered:
    """Like to_spl_condition but raises Unsupported with the reason."""
    r = _Render(rename)
    return Rendered(_strip(r.cond(parse(kql))), r.warnings, r.columns)


def value(kql: str, rename=None) -> Rendered:
    """Like to_spl_value but raises Unsupported with the reason."""
    r = _Render(rename)
    return Rendered(r.value(parse(kql)), r.warnings, r.columns)
