"""Parse a safe subset of SPL eval-expressions and render KQL / XQL.

Conditions (where, if):  value (= == != < <= > >=) value, AND / OR / NOT, ( ).
Values (eval, comparison operands):
  bare field, 'quoted field', "string", unsigned number, ( value ),
  + - * /  and  . (concatenation), functions lower upper len coalesce if.
Anything else (other functions, unary minus, %, XOR, lowercase and/or/not,
mixing . with + or - without parentheses) -> None, so the caller falls back
to review instead of guessing.

SPL (help.splunk.com, search-commands/where, search-commands/eval, evaluation
functions: comparison-and-conditional, text):
  - unquoted word = field name; "double quotes" = string; 'single quotes' = field
  - precedence: () > NOT > AND > OR; * / before + -
  - + adds numbers OR concatenates strings; . concatenates strings and numbers
  - numbers are double precision (7/2 = 3.5); division by zero -> null
  - coalesce: first non-null; len: UTF-8 code points
KQL (learn.microsoft.com/kusto): where-operator, logical-operators, not-function,
  numerical-operators (int/int truncates -> todouble()), strcat (converts args to
  string), coalesce, iff, strlen (code points), tolower/toupper
  - `!=` is true when an operand is null (SPL: false) -> flagged
XQL (cortex-docs .../xql-command-reference-guide/readme): stages/filter, functions
  add/subtract/multiply/divide (divide returns decimals), concat (no implicit
  conversion -> to_string(); NULL if any arg is NULL), if, len, lowercase,
  uppercase, coalesce
  - "..." treats `*` as a wildcard; escapes only in triple quotes
  - case sensitivity of string `=` is not documented -> flagged
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_TOKEN = re.compile(r"""
    (?P<ws>\s+)
  | (?P<str>"(?:[^"\\]|\\.)*")
  | (?P<qfield>'(?:[^'\\]|\\.)*')
  | (?P<num>\d+(?:\.\d+)?(?![\w.]))
  | (?P<op>==|!=|<=|>=|=|<|>)
  | (?P<arith>[-+*/])
  | (?P<dot>\.)
  | (?P<lp>\()
  | (?P<rp>\))
  | (?P<comma>,)
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
""", re.VERBOSE)

_BOOL_WORDS = {"AND", "OR", "NOT", "XOR"}
# SPL function -> (KQL name, XQL name, arg count; None = 2 or more)
FUNCS = {
    "lower": ("tolower", "lowercase", 1),
    "upper": ("toupper", "uppercase", 1),
    "len": ("strlen", "len", 1),
    "coalesce": ("coalesce", "coalesce", None),
    "if": ("iff", "if", 3),
}
_XQL_ARITH = {"+": "add", "-": "subtract", "*": "multiply", "/": "divide"}
_PLAIN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

W_PLUS = ("{T}: SPL + adds numbers or joins strings; operand types unknown, "
          "assumed numeric; verify")
W_CONCAT = "{T}: concatenation with fields; SPL null handling is not documented; verify"
W_DIV = ("{T}: division by a field; SPL returns null on division by zero, "
         "target behaviour not verified; verify")
W_NE = ("{T}: != null handling may differ from SPL "
        "(SPL drops events where the field is missing); verify")
W_XQL_STR = "XQL: case sensitivity of string comparison is not documented; verify"


@dataclass
class Rendered:
    text: str
    warnings: list[str] = field(default_factory=list)


class _Unsupported(ValueError):
    pass


def tokenize(s: str) -> list[tuple[str, str]] | None:
    out, pos = [], 0
    while pos < len(s):
        m = _TOKEN.match(s, pos)
        if not m:
            return None
        pos = m.end()
        kind = m.lastgroup
        if kind == "ws":
            continue
        val = m.group()
        if kind == "ident" and val.upper() in _BOOL_WORDS:
            if val != val.upper() or val == "XOR":
                return None   # lowercase and/or/not are ambiguous; XOR unsupported
            kind = val
        out.append((kind, val))
    return out


# ---- parser ------------------------------------------------------------------

class _Parser:
    def __init__(self, toks):
        self.t, self.i = toks, 0

    def peek(self, k=0):
        j = self.i + k
        return self.t[j][0] if j < len(self.t) else None

    def take(self, kind):
        if self.peek() != kind:
            raise _Unsupported(f"expected {kind}")
        self.i += 1
        return self.t[self.i - 1][1]

    # conditions
    def or_expr(self):
        parts = [self.and_expr()]
        while self.peek() == "OR":
            self.i += 1
            parts.append(self.and_expr())
        return parts[0] if len(parts) == 1 else ("or", parts)

    def and_expr(self):
        parts = [self.not_expr()]
        while self.peek() == "AND":
            self.i += 1
            parts.append(self.not_expr())
        return parts[0] if len(parts) == 1 else ("and", parts)

    def not_expr(self):
        if self.peek() == "NOT":
            self.i += 1
            return ("not", self.not_expr())
        start = self.i
        try:                       # `(a+b) > 1` is a comparison, not a group
            return self.comparison()
        except _Unsupported:
            self.i = start
        if self.peek() == "lp":
            self.i += 1
            node = self.or_expr()
            self.take("rp")
            return node
        raise _Unsupported("expected condition")

    def comparison(self):
        left = self.value()
        op = self.take("op")
        return ("cmp", left, op, self.value())

    # values
    def value(self):
        node = self.term()
        ops_seen = set()
        while self.peek() in ("arith", "dot") and self.t[self.i][1] in "+-.":
            op = self.t[self.i][1]
            ops_seen.add("." if op == "." else "+-")
            if len(ops_seen) > 1:
                raise _Unsupported("mixing . with + or - needs parentheses")
            self.i += 1
            node = ("bin", op, node, self.term())
        return node

    def term(self):
        node = self.factor()
        while self.peek() == "arith" and self.t[self.i][1] in "*/":
            op = self.t[self.i][1]
            self.i += 1
            node = ("bin", op, node, self.factor())
        return node

    def factor(self):
        kind = self.peek()
        if kind == "ident" and self.peek(1) == "lp":
            return self.call()
        if kind == "ident":
            return ("field", self.take("ident"))
        if kind == "qfield":
            raw = self.take("qfield")[1:-1]
            return ("field", re.sub(r"\\(.)", r"\1", raw))
        if kind == "str":
            return ("str", self.take("str")[1:-1])   # inner text, escapes kept
        if kind == "num":
            return ("num", self.take("num"))
        if kind == "lp":
            self.i += 1
            node = self.value()
            self.take("rp")
            return ("paren", node)
        raise _Unsupported("expected value")

    def call(self):
        name = self.take("ident")
        if name not in FUNCS:
            raise _Unsupported(f"function {name} not supported")
        self.take("lp")
        args = [self.or_expr() if name == "if" else self.value()]
        while self.peek() == "comma":
            self.i += 1
            args.append(self.value())
        self.take("rp")
        n = FUNCS[name][2]
        if (n is None and len(args) < 2) or (n is not None and len(args) != n):
            raise _Unsupported(f"{name}: wrong number of arguments")
        return ("call", name, args)


def _parse(s: str, rule: str):
    toks = tokenize(s)
    if not toks:
        return None
    p = _Parser(toks)
    try:
        node = p.or_expr() if rule == "cond" else p.value()
    except _Unsupported:
        return None
    return node if p.i == len(toks) else None


def parse(s: str):
    """Parse a condition (where). None if outside the supported subset."""
    return _parse(s, "cond")


def parse_value(s: str):
    """Parse a value expression (eval right-hand side)."""
    return _parse(s, "value")


# ---- rendering ---------------------------------------------------------------

class _Renderer:
    def __init__(self, target: str):
        self.target, self.T = target, target.upper()
        self.warnings: list[str] = []

    def warn(self, msg: str):
        msg = msg.format(T=self.T)
        if msg not in self.warnings:
            self.warnings.append(msg)

    # types: "num", "str" or "?" (unknown, e.g. a field)
    def typeof(self, n) -> str:
        k = n[0]
        if k in ("num", "str"):
            return k
        if k == "paren":
            return self.typeof(n[1])
        if k == "bin":
            if n[1] == ".":
                return "str"
            if n[1] == "+":
                types = {self.typeof(n[2]), self.typeof(n[3])}
                return "str" if "str" in types else "num"
            return "num"
        if k == "call":
            if n[1] in ("lower", "upper"):
                return "str"
            if n[1] == "len":
                return "num"
            branches = n[2][1:] if n[1] == "if" else n[2]
            known = [self.typeof(b) for b in branches if self.typeof(b) != "?"]
            return known[0] if known else "?"
        return "?"

    def field(self, name: str) -> str:
        if self.target == "kql":
            from .rules import kql_name   # local import: rules imports this module
            return kql_name(name)
        if not _PLAIN.fullmatch(name):
            raise _Unsupported("XQL quoting of special field names not verified")
        return name

    def string(self, raw: str) -> str:
        if self.target == "xql" and ("*" in raw or "\\" in raw):
            raise _Unsupported("XQL treats * as wildcard / escapes differ")
        return f'"{raw}"'

    def concat_parts(self, n) -> list:
        """Flatten a concatenation chain into its operands."""
        if n[0] == "bin" and (n[1] == "." or (n[1] == "+" and self.typeof(n) == "str")):
            return self.concat_parts(n[2]) + self.concat_parts(n[3])
        return [n]

    def value(self, n) -> str:
        k = n[0]
        if k == "num":
            return n[1]
        if k == "str":
            return self.string(n[1])
        if k == "field":
            return self.field(n[1])
        if k == "paren":
            return self.value(n[1])
        if k == "call":
            return self.call(n)
        if k == "bin":
            return self.binary(n)
        raise _Unsupported(k)

    def binary(self, n) -> str:
        _, op, left, right = n
        if op == "." or (op == "+" and self.typeof(n) == "str"):
            parts = self.concat_parts(n)
            if any(p[0] not in ("str", "num") for p in parts):
                self.warn(W_CONCAT)
            if self.target == "kql":
                return f"strcat({', '.join(self.value(p) for p in parts)})"
            rendered = [self.value(p) if self.typeof(p) == "str" else f"to_string({self.value(p)})"
                        for p in parts]
            return f"concat({', '.join(rendered)})"
        if op == "+" and self.typeof(left) == "?" and self.typeof(right) == "?":
            self.warn(W_PLUS)
        if op == "/" and right[0] != "num":
            self.warn(W_DIV)
        if op == "/" and right[0] == "num" and float(right[1]) == 0:
            raise _Unsupported("division by literal zero")
        if self.target == "xql":
            return f"{_XQL_ARITH[op]}({self.value(left)}, {self.value(right)})"
        lt, rt = self.operand(left), self.operand(right)
        if op == "/":
            lt = f"todouble({self.value(left)})"   # avoid KQL integer division
        return f"{lt} {op} {rt}"

    def operand(self, n) -> str:
        """KQL infix operand: parenthesize nested binary expressions.
        (XQL arithmetic is rendered as function calls, so no parentheses needed.)"""
        text = self.value(n)
        if self.target == "xql":
            return text
        inner = n[1] if n[0] == "paren" else n
        return f"({text})" if inner[0] == "bin" and not text.startswith(("strcat(", "concat(")) else text

    def call(self, n) -> str:
        _, name, args = n
        kql_fn, xql_fn, _ = FUNCS[name]
        fn = kql_fn if self.target == "kql" else xql_fn
        if name == "if":
            rendered = [self.cond(args[0])] + [self.value(a) for a in args[1:]]
        else:
            rendered = [self.value(a) for a in args]
        return f"{fn}({', '.join(rendered)})"

    # conditions
    def cond(self, n, parent=None) -> str:
        kind = n[0]
        if kind == "cmp":
            _, left, op, right = n
            if self.target == "xql" and left[0] == "field" and right[0] == "field":
                raise _Unsupported("XQL field-to-field comparison not verified")
            if op == "!=":
                self.warn(W_NE)
            if self.target == "xql" and "str" in (self.typeof(left), self.typeof(right)):
                self.warn(W_XQL_STR)
            if op in ("=", "=="):
                op = "==" if self.target == "kql" else "="
            return f"{self.operand(left)} {op} {self.operand(right)}"
        if kind == "not":
            inner = self.cond(n[1], "not")
            return f"not({inner})" if self.target == "kql" else f"not ({inner})"
        # and / or: parenthesize nested boolean groups of a different kind
        text = f" {kind} ".join(self.cond(c, kind) for c in n[1])
        return f"({text})" if parent in ("and", "or") and parent != kind else text


def render(node, target: str) -> Rendered | None:
    """Render a parsed condition."""
    r = _Renderer(target)
    try:
        return Rendered(r.cond(node), r.warnings)
    except _Unsupported:
        return None


def render_value(node, target: str) -> Rendered | None:
    r = _Renderer(target)
    try:
        return Rendered(r.value(node), r.warnings)
    except _Unsupported:
        return None


def translate(spl_expr: str, target: str) -> Rendered | None:
    """SPL condition -> KQL / XQL condition."""
    node = parse(spl_expr)
    return render(node, target) if node is not None else None


def translate_value(spl_expr: str, target: str) -> Rendered | None:
    """SPL value expression -> KQL / XQL expression."""
    node = parse_value(spl_expr)
    return render_value(node, target) if node is not None else None


def fields_in(node) -> list[str]:
    """Field names referenced by a parsed condition or value, in first-seen order."""
    out: list[str] = []

    def walk(n):
        k = n[0]
        if k == "field":
            if n[1] not in out:
                out.append(n[1])
        elif k in ("str", "num"):
            return
        elif k == "cmp":
            walk(n[1])
            walk(n[3])
        elif k in ("not", "paren"):
            walk(n[1])
        elif k == "bin":
            walk(n[2])
            walk(n[3])
        elif k == "call":
            for a in n[2]:
                walk(a)
        else:                       # and / or
            for c in n[1]:
                walk(c)

    if node is not None:
        walk(node)
    return out
