"""Parse a small, safe subset of SPL eval-expressions and render KQL / XQL.

Supported:  operand (= == != < <= > >=) operand, AND / OR / NOT, parentheses.
Operands:   bare field, 'quoted field', "string", unsigned number.
Anything else (functions, arithmetic, XOR, lowercase and/or/not, negative
numbers) -> parse() returns None and the caller falls back to review.

SPL rules (help.splunk.com, search-commands/where):
  - unquoted word = field name; "double quotes" = string; 'single quotes' = field
  - the eval-expression is case-sensitive
  - precedence: () > NOT > AND > OR (> XOR, unsupported here)
KQL: where-operator, logical-operators, not-function (learn.microsoft.com/kusto)
  - `and` binds tighter than `or`; `not(expr)` is a function
  - `!=` is true when an operand is null (SPL: false) -> flagged
XQL: xql-command-reference-guide/readme/stages/filter.md
  - = != < <= > >=, and / or / not, parentheses
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
  | (?P<lp>\()
  | (?P<rp>\))
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
""", re.VERBOSE)

_BOOL_WORDS = {"AND", "OR", "NOT", "XOR"}


@dataclass
class Rendered:
    text: str
    warnings: list[str] = field(default_factory=list)


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


class _Parser:
    def __init__(self, toks):
        self.t, self.i = toks, 0

    def peek(self):
        return self.t[self.i][0] if self.i < len(self.t) else None

    def take(self, kind):
        if self.peek() != kind:
            raise ValueError(f"expected {kind}")
        self.i += 1
        return self.t[self.i - 1][1]

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
        if self.peek() == "lp":
            self.i += 1
            node = self.or_expr()
            self.take("rp")
            return node
        return self.comparison()

    def comparison(self):
        left = self.operand()
        op = self.take("op")
        return ("cmp", left, op, self.operand())

    def operand(self):
        kind = self.peek()
        if kind == "ident":
            return ("field", self.take("ident"))
        if kind == "qfield":
            raw = self.take("qfield")[1:-1]
            return ("field", re.sub(r"\\(.)", r"\1", raw))
        if kind == "str":
            return ("str", self.take("str")[1:-1])   # inner text, escapes kept
        if kind == "num":
            return ("num", self.take("num"))
        raise ValueError("expected operand")


def parse(s: str):
    """Return an AST, or None if the expression is outside the supported subset."""
    toks = tokenize(s)
    if not toks:
        return None
    p = _Parser(toks)
    try:
        node = p.or_expr()
    except ValueError:
        return None
    return node if p.i == len(toks) else None


# ---- rendering ---------------------------------------------------------------

def render(node, target: str) -> Rendered | None:
    from .rules import kql_name   # local import: rules imports this module
    warnings: list[str] = []

    def operand(o):
        kind, val = o
        if kind == "num":
            return val
        if kind == "field":
            if target == "kql":
                return kql_name(val)
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", val):
                raise ValueError("XQL quoting of special field names not verified")
            return val
        # string literal
        if target == "xql":
            if "*" in val or "\\" in val:
                raise ValueError("XQL treats * as wildcard / escapes differ")
            _warn("XQL: case sensitivity of string comparison is not documented; verify")
        return f'"{val}"'

    def _warn(msg):
        if msg not in warnings:
            warnings.append(msg)

    def walk(n, parent=None):
        kind = n[0]
        if kind == "cmp":
            _, left, op, right = n
            if target == "xql" and left[0] == "field" and right[0] == "field":
                raise ValueError("XQL field-to-field comparison not verified")
            if op == "!=":
                _warn(f"{target.upper()}: != null handling may differ from SPL "
                      "(SPL drops events where the field is missing); verify")
            if op in ("=", "=="):
                op = "==" if target == "kql" else "="
            return f"{operand(left)} {op} {operand(right)}"
        if kind == "not":
            inner = walk(n[1], "not")
            return f"not({inner})" if target == "kql" else f"not ({inner})"
        # and / or: parenthesize nested boolean groups of a different kind
        text = f" {kind} ".join(walk(c, kind) for c in n[1])
        return f"({text})" if parent in ("and", "or") and parent != kind else text

    try:
        return Rendered(walk(node), warnings)
    except ValueError:
        return None


def translate(spl_expr: str, target: str) -> Rendered | None:
    node = parse(spl_expr)
    return render(node, target) if node is not None else None
