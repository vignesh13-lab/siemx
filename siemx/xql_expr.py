"""Roadmap 7 (part 3): XQL expressions -> SPL where/eval expressions.

There is no official XQL parser we can run, so this reads a small, documented subset and
rejects everything else (the reason goes into the warning; the LLM fallback may try).

Supported XQL (cortex-docs .../xql-command-reference-guide/readme):
  literals: "x" (plain double quotes; * is a wildcard there), numbers, null
  fields:   name, dotted.name
  compare:  = != < <= > >=      x = null / x != null      in (...) / not in (...)
  strings:  contains
  logic:    and, or, not (...)  - mixing and/or without parentheses is rejected:
            the XQL docs do not state their precedence
  functions: lowercase uppercase len coalesce if concat add subtract multiply divide
             to_string to_number
Not supported: triple-quoted strings, ~= / !~= (regex dialect differs), incidr/incidr6,
arrays/JSON functions, true/false literals, infix arithmetic.

Case: XQL string comparison is case-INSENSITIVE unless `config case_sensitive = true`
(stages/config.md); SPL where/eval comparison is case-sensitive. So by default a string
`=` becomes lower(x)=="<lowercased value>" and `in` becomes in(lower(x), ...). With
case_sensitive = true, `=` is plain ==; wildcard and contains matches are rejected there
because SPL like() case sensitivity is not documented.
"""
from __future__ import annotations

import re

from .kql_expr import Rendered, Unsupported, _Render, _strip

_TOKEN = re.compile(r"""
    (?P<ws>\s+)
  | (?P<tstr>\"\"\")
  | (?P<str>"[^"]*")
  | (?P<num>\d+(?:\.\d+)?(?![\w.]))
  | (?P<op>!~=|~=|!=|<=|>=|=|<|>)
  | (?P<arith>[-+*/])
  | (?P<lp>\()
  | (?P<rp>\))
  | (?P<comma>,)
  | (?P<word>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)
""", re.VERBOSE)

FUNCS = {   # XQL -> (SPL name, arg count; None = 1 or more)
    "lowercase": ("lower", 1), "uppercase": ("upper", 1), "len": ("len", 1),
    "coalesce": ("coalesce", None), "to_string": ("tostring", 1), "to_number": ("tonumber", 1),
}
ARITH = {"add": "+", "subtract": "-", "multiply": "*", "divide": "/"}
W_NE = ("SPL: != is false when the field is missing; XQL null handling for != / not is "
        "not documented; verify")
W_CONCAT = ("SPL: concatenation with . ; XQL concat() returns null if any argument is null, "
            "SPL behaviour with a missing field is not documented; verify")


def tokenize(s: str) -> list[tuple[str, str]]:
    out, pos = [], 0
    while pos < len(s):
        m = _TOKEN.match(s, pos)
        if not m:
            raise Unsupported(f"cannot read XQL at: {s[pos:pos + 20]!r}")
        pos = m.end()
        kind, val = m.lastgroup, m.group()
        if kind == "ws":
            continue
        if kind == "tstr":
            raise Unsupported('XQL triple-quoted strings (regex / escapes)')
        if kind == "arith":
            raise Unsupported("infix arithmetic (XQL uses add()/subtract()/...)")
        if kind == "word" and val.lower() in ("and", "or", "not", "in", "contains", "null",
                                              "incidr", "incidr6", "true", "false"):
            kind = val.lower()
        out.append((kind, val))
    return out


class _Parser:
    def __init__(self, toks):
        self.t, self.i = toks, 0

    def peek(self, k=0):
        j = self.i + k
        return self.t[j] if j < len(self.t) else (None, None)

    def take(self, kind):
        k, v = self.peek()
        if k != kind:
            raise Unsupported(f"expected {kind}, got {v}")
        self.i += 1
        return v

    def expr(self):
        """a and b and c / a or b or c; mixed without parentheses -> Unsupported."""
        node = self.unary()
        ops = set()
        while self.peek()[0] in ("and", "or"):
            op = self.take(self.peek()[0])
            ops.add(op.lower())
            if len(ops) > 1:
                raise Unsupported("'and' and 'or' mixed without parentheses: XQL precedence "
                                  "is not documented")
            node = (op.lower(), node, self.unary())
        return node

    def unary(self):
        if self.peek()[0] == "not":
            self.i += 1
            if self.peek()[0] != "lp":
                raise Unsupported("'not' without parentheses: XQL precedence is not documented")
            return ("not", self.primary())
        return self.cmp()

    def cmp(self):
        left = self.primary()
        k, v = self.peek()
        if k == "op":
            if v in ("~=", "!~="):
                raise Unsupported(f"XQL '{v}' (regex dialect differs from SPL)")
            self.i += 1
            if self.peek()[0] == "null":
                self.i += 1
                if v not in ("=", "!="):
                    raise Unsupported(f"null with {v}")
                return ("null", v, left)
            return ("cmp", v, left, self.primary())
        if k == "not" and self.peek(1)[0] == "in":
            self.i += 2
            return ("in", "not in", left, self.items())
        if k == "in":
            self.i += 1
            return ("in", "in", left, self.items())
        if k == "contains":
            self.i += 1
            return ("contains", left, self.primary())
        if k in ("incidr", "incidr6"):
            raise Unsupported(f"XQL '{v}'")
        return left

    def items(self):
        self.take("lp")
        out = [self.primary()]
        while self.peek()[0] == "comma":
            self.i += 1
            out.append(self.primary())
        self.take("rp")
        return out

    def primary(self):
        k, v = self.peek()
        if k == "lp":
            self.i += 1
            node = self.expr()
            self.take("rp")
            return ("paren", node)
        if k == "str":
            self.i += 1
            return ("str", v[1:-1])
        if k == "num":
            self.i += 1
            return ("num", v)
        if k == "word":
            self.i += 1
            if self.peek()[0] == "lp":
                return self.call(v)
            return ("col", v)
        if k in ("true", "false"):
            raise Unsupported("boolean literal")
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


class _XqlRender(_Render):
    def __init__(self, rename=None, case_sensitive=False):
        super().__init__(rename)
        self.cs = case_sensitive

    def value(self, n):
        if n[0] in ("null", "in", "contains", "not") or (n[0] == "cmp"):
            return self.cond(n)
        return super().value(n)

    def call(self, n):
        _, name, args = n
        if name == "if":
            if len(args) != 3:
                raise Unsupported("if needs 3 arguments")
            return f"if({self.cond(args[0])}, {self.value(args[1])}, {self.value(args[2])})"
        if name == "concat":
            if len(args) < 2:
                raise Unsupported("concat() needs two or more arguments")
            if any(a[0] != "str" for a in args):
                self.warn(W_CONCAT)
            return "(" + " . ".join(self.value(a) for a in args) + ")"
        if name in ARITH:
            if len(args) != 2:
                raise Unsupported(f"{name}() takes two arguments")
            return f"({self.value(args[0])} {ARITH[name]} {self.value(args[1])})"
        if name not in FUNCS:
            raise Unsupported(f"function {name}() not supported")
        spl, n_args = FUNCS[name]
        if (n_args is None and not args) or (n_args is not None and len(args) != n_args):
            raise Unsupported(f"{name}: wrong number of arguments")
        return f"{spl}({', '.join(self.value(a) for a in args)})"

    def _lowered(self, node):
        """lower(x), without wrapping an explicit lowercase() twice."""
        if node[0] == "call" and node[1] == "lowercase":
            return self.value(node)
        return f"lower({self.value(node)})"

    def cond(self, n):
        k = n[0]
        if k in ("and", "or"):
            op = " AND " if k == "and" else " OR "
            return f"({self.cond(n[1])}{op}{self.cond(n[2])})"
        if k == "paren":
            return f"({self.cond(n[1])})"
        if k == "not":
            self.warn(W_NE)
            inner = n[1][1] if n[1][0] == "paren" else n[1]
            return f"NOT ({_strip(self.cond(inner))})"
        if k == "null":
            _, op, a = n
            return f"{'isnull' if op == '=' else 'isnotnull'}({self.value(a)})"
        if k == "cmp":
            return self.compare(*n[1:])
        if k == "in":
            return self.in_list(*n[1:])
        if k == "contains":
            _, a, b = n
            if b[0] != "str" or "*" in b[1]:
                raise Unsupported("contains needs a plain string literal")
            if self.cs:
                raise Unsupported("case-sensitive contains: SPL like() case sensitivity "
                                  "is not documented")
            return self.like(a, b[1], "%{}%")
        if k == "call":
            return self.call(n)
        raise Unsupported(f"not a condition: {k}")

    def compare(self, op, a, b):
        if a[0] in ("str", "num"):
            raise Unsupported("literal on the left of a comparison")
        eq = {"=": "==", "!=": "!="}.get(op)
        if b[0] == "num":
            if op == "!=":
                self.warn(W_NE)
            return f"{self.value(a)}{eq or op}{b[1]}"
        if b[0] != "str":
            raise Unsupported("comparison with a non-literal (types and case are unknown)")
        if eq is None:
            raise Unsupported(f"string {op}: ordering and case rules are not verified")
        if op == "!=":
            self.warn(W_NE)
        if "*" in b[1]:                                   # documented wildcard in "..."
            if self.cs:
                raise Unsupported("case-sensitive wildcard: SPL like() case sensitivity "
                                  "is not documented")
            if "%" in b[1] or "_" in b[1]:
                raise Unsupported("% or _ in a like() pattern: SPL escaping not documented")
            pat = self.string(b[1].lower().replace("*", "%"))
            text = f"like({self._lowered(a)}, {pat})"
            return text if op == "=" else f"NOT {text}"
        if self.cs:
            return f"{self.value(a)}{eq}{self.string(b[1])}"
        return f"{self._lowered(a)}{eq}{self.string(b[1].lower())}"

    def in_list(self, op, a, items):
        kinds = {i[0] for i in items}
        if kinds == {"num"}:
            x = self.value(a)
            alts = " OR ".join(f"{x}=={i[1]}" for i in items)
        elif kinds == {"str"} and not any("*" in i[1] for i in items):
            if self.cs:
                x = self.value(a)
                alts = " OR ".join(f"{x}=={self.string(i[1])}" for i in items)
            else:
                vals = ", ".join(self.string(i[1].lower()) for i in items)
                text = f"in({self._lowered(a)}, {vals})"
                if op == "not in":
                    self.warn(W_NE)
                    return f"NOT {text}"
                return text
        else:
            raise Unsupported("in-list must be all numbers or all plain strings")
        if op == "not in":
            self.warn(W_NE)
            return f"NOT ({alts})"
        return f"({alts})"


def condition(xql: str, rename=None, case_sensitive=False) -> Rendered:
    r = _XqlRender(rename, case_sensitive)
    return Rendered(_strip(r.cond(parse(xql))), r.warnings, r.columns)


def value(xql: str, rename=None, case_sensitive=False) -> Rendered:
    r = _XqlRender(rename, case_sensitive)
    return Rendered(r.value(parse(xql)), r.warnings, r.columns)
