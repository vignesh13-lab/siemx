"""Translate the SPL base search (first pipeline stage) into a table + filter.

SPL search semantics (help.splunk.com .../search-commands/search):
  - precedence: ( ) > NOT > OR > AND; AND is implied between terms
  - field values are case-insensitive by default (CASE() makes them sensitive)
  - * is a wildcard in values
  - field!=value: the field exists and is not value
    NOT field=value: also returns events where the field does not exist
  - < > <= >= compare numerically for numbers, lexicographically otherwise
  - a term without a field searches _raw (no equivalent here -> None)
KQL (learn.microsoft.com/kusto/query/datatypes-string-operators):
  =~ !~ in~ startswith endswith contains are case-insensitive; == and
  matches regex are case-sensitive, so regexes get (?i).
XQL (cortex-docs .../stages/filter.md): "..." with * is a wildcard match;
  lowercase() on the field + a lowercased value makes matching case-insensitive
  without relying on XQL's (undocumented) case sensitivity.

Supported terms: field=value, field!=value, field<op>number, field IN (v, ...),
field=* ; index/sourcetype/source only as top-level AND terms (matched against
mappings/sources.json). Anything else -> None.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

META = ("index", "sourcetype", "source")
_TOKEN = re.compile(r"""
    (?P<ws>\s+)
  | (?P<lp>\()
  | (?P<rp>\))
  | (?P<term>[A-Za-z_][A-Za-z0-9_.]*\s*(?:!=|<=|>=|=|<|>)\s*(?:"(?:[^"\\]|\\.)*"|[^\s()"]+))
  | (?P<in>[A-Za-z_][A-Za-z0-9_.]*\s+IN\s*\((?:[^()"]|"(?:[^"\\]|\\.)*")*\))
  | (?P<word>[^\s()]+)
""", re.VERBOSE)
_TERM = re.compile(r'([A-Za-z_][A-Za-z0-9_.]*)\s*(!=|<=|>=|=|<|>)\s*("(?:[^"\\]|\\.)*"|[^\s()"]+)')
_NUM = re.compile(r"-?\d+(?:\.\d+)?")
_NUMERIC_TYPES = {"int", "long", "real", "decimal"}
BACKSLASH_WARNING = ("{T}: base-search value contains a backslash; SPL search escaping "
                     "(\\\\ vs \\) was read as \\\\ = one backslash; verify the value")


@dataclass
class Rendered:
    text: str
    reads: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class _Unsupported(ValueError):
    pass


def _value(raw: str) -> str:
    if raw.startswith('"'):
        return re.sub(r'\\(["\\])', r"\1", raw[1:-1])
    return raw


def tokenize(s: str):
    out, pos = [], 0
    while pos < len(s):
        m = _TOKEN.match(s, pos)
        if not m:
            raise _Unsupported("unbalanced quotes")
        pos = m.end()
        kind, val = m.lastgroup, m.group()
        if kind == "ws":
            continue
        if kind == "word":
            if val in ("AND", "OR", "NOT"):
                kind = val
            else:
                raise _Unsupported(f"free-text term or directive: {val}")
        out.append((kind, val))
    return out


class _Parser:
    def __init__(self, toks):
        self.t, self.i = toks, 0

    def peek(self):
        return self.t[self.i][0] if self.i < len(self.t) else None

    def and_expr(self, stop=None):
        parts = []
        while self.peek() not in (None, stop):
            if self.peek() == "AND":
                self.i += 1
                continue
            parts.append(self.or_expr())
        if not parts:
            raise _Unsupported("empty expression")
        return parts[0] if len(parts) == 1 else ("and", parts)

    def or_expr(self):
        parts = [self.not_expr()]
        while self.peek() == "OR":
            self.i += 1
            parts.append(self.not_expr())
        return parts[0] if len(parts) == 1 else ("or", parts)

    def not_expr(self):
        if self.peek() == "NOT":
            self.i += 1
            return ("not", self.not_expr())
        kind = self.peek()
        if kind == "lp":
            self.i += 1
            node = self.and_expr(stop="rp")
            if self.peek() != "rp":
                raise _Unsupported("unbalanced parentheses")
            self.i += 1
            return node
        if kind == "term":
            m = _TERM.fullmatch(self.t[self.i][1])
            self.i += 1
            return ("term", m.group(1), m.group(2), _value(m.group(3)))
        if kind == "in":
            raw = self.t[self.i][1]
            self.i += 1
            f, inner = re.fullmatch(r"(\S+)\s+IN\s*\((.*)\)", raw, re.S).groups()
            vals = [_value(v.strip()) for v in re.findall(r'"(?:[^"\\]|\\.)*"|[^,\s]+', inner)]
            if not vals:
                raise _Unsupported("empty IN list")
            return ("in", f, vals)
        raise _Unsupported(f"unexpected {kind}")


def parse(text: str):
    """-> (metadata dict, filter AST or None). Raises _Unsupported."""
    toks = tokenize(text)
    if not toks:
        raise _Unsupported("empty search")
    p = _Parser(toks)
    ast = p.and_expr()
    if p.i != len(toks):
        raise _Unsupported("trailing tokens")
    items = ast[1] if ast[0] == "and" else [ast]
    meta, rest = {}, []
    for node in items:
        if node[0] == "term" and node[1].lower() in META:
            key = node[1].lower()
            # wildcards only for index (a storage location; see rules.match_source)
            if node[2] != "=" or key in meta or ("*" in node[3] and key != "index"):
                raise _Unsupported("unsupported metadata term")
            meta[key] = node[3].lower()
        else:
            rest.append(node)
    _check_no_meta(rest)
    if not rest:
        return meta, None
    return meta, rest[0] if len(rest) == 1 else ("and", rest)


def _check_no_meta(nodes):
    for n in nodes:
        if n[0] in ("term", "in"):
            if n[1].lower() in META or n[1].lower() in ("earliest", "latest"):
                raise _Unsupported("metadata/time term inside OR/NOT")
        elif n[0] == "not":
            _check_no_meta([n[1]])
        else:
            _check_no_meta(n[1])


def parse_meta(key: str) -> dict | None:
    """'index=wineventlog sourcetype=x' (a sources.json key) -> {'index': ..., ...}."""
    try:
        meta, ast = parse(key)
    except _Unsupported:
        return None
    return meta if ast is None else None


# ---- rendering -------------------------------------------------------------------

class _Renderer:
    def __init__(self, target, field_type):
        self.target, self.field_type = target, field_type
        self.reads: list[str] = []
        self.warnings: list[str] = []

    def name(self, f):
        if f.lower() in ("earliest", "latest"):
            raise _Unsupported("time modifiers")
        if f not in self.reads:
            self.reads.append(f)
        if self.target == "kql":
            from .rules import kql_name
            return kql_name(f)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", f):
            raise _Unsupported("XQL quoting of special field names not verified")
        return f

    def numeric(self, f, v):
        """Compare as number? Needs a numeric value; for KQL also a non-string column."""
        if not _NUM.fullmatch(v):
            return False
        t = self.field_type(f)
        return t is None or t in _NUMERIC_TYPES

    def kql_str(self, v):
        if '"' in v or "\\" in v:
            return '@"' + v.replace('"', '""') + '"'
        return f'"{v}"'

    def xql_str(self, v):
        if '"' in v:
            raise _Unsupported("double quote in XQL string")
        return f'"{v.lower()}"'

    # positive match of one value (case-insensitive, * wildcards)
    def match(self, f, v):
        n = self.name(f)
        if "\\" in v and BACKSLASH_WARNING.format(T=self.target.upper()) not in self.warnings:
            self.warnings.append(BACKSLASH_WARNING.format(T=self.target.upper()))
        if v == "*":
            return f"isnotempty({n})" if self.target == "kql" else f"{n} != null"
        if self.target == "xql":
            if self.numeric(f, v):
                return f"{n} = {v}"
            return f"lowercase({n}) = {self.xql_str(v)}"
        if "*" not in v:
            return f"{n} == {v}" if self.numeric(f, v) else f"{n} =~ {self.kql_str(v)}"
        if self.field_type(f) in _NUMERIC_TYPES:
            n = f"tostring({n})"
        core = v.strip("*")
        if "*" in core or not core:
            rx = "(?i)^" + ".*".join(re.escape(p) for p in v.split("*")) + "$"
            return f"{n} matches regex {self.kql_str(rx)}"
        if v.startswith("*") and v.endswith("*"):
            return f"{n} contains {self.kql_str(core)}"
        if v.endswith("*"):
            return f"{n} startswith {self.kql_str(core)}"
        return f"{n} endswith {self.kql_str(core)}"

    def exists(self, f):
        n = self.name(f)
        return f"isnotempty({n})" if self.target == "kql" else f"{n} != null"

    def node(self, n, negated=False):
        kind = n[0]
        if kind == "term":
            _, f, op, v = n
            if op == "=":
                m = self.match(f, v)
                # under NOT, guard so events without the field are kept (SPL)
                if negated and v != "*":
                    return f"({self.exists(f)} and {m})"
                return m
            if op == "!=":
                if v == "*":
                    raise _Unsupported("field!=* never matches")
                neg = self.match(f, v)
                body = f"not({neg})" if self.target == "kql" else f"not ({neg})"
                return f"({self.exists(f)} and {body})"
            if not _NUM.fullmatch(v) or (self.field_type(f) not in (None, *_NUMERIC_TYPES)):
                raise _Unsupported("lexicographic comparison")
            cmp = f"{self.name(f)} {op} {v}"
            return f"({self.exists(f)} and {cmp})" if negated else cmp
        if kind == "in":
            _, f, vals = n
            if any("*" in v for v in vals):
                return self.node(("or", [("term", f, "=", v) for v in vals]), negated)
            nm = self.name(f)
            if all(self.numeric(f, v) for v in vals):
                body = f"{nm} in ({', '.join(vals)})"
            elif self.target == "kql":
                body = f"{nm} in~ ({', '.join(self.kql_str(v) for v in vals)})"
            else:
                body = f"lowercase({nm}) in ({', '.join(self.xql_str(v) for v in vals)})"
            return f"({self.exists(f)} and {body})" if negated else body
        if kind == "not":
            inner = self.node(n[1], not negated)
            if inner.startswith("(") and _balanced_outer(inner):
                inner = inner[1:-1]
            return f"not({inner})" if self.target == "kql" else f"not ({inner})"
        sep = f" {kind} "
        return "(" + sep.join(self.node(c, negated) for c in n[1]) + ")"


def render(ast, target: str, field_type) -> Rendered | None:
    r = _Renderer(target, field_type)
    try:
        text = r.node(ast)
    except _Unsupported:
        return None
    if text.startswith("(") and _balanced_outer(text):
        text = text[1:-1]
    return Rendered(text, r.reads, r.warnings)


def _balanced_outer(text: str) -> bool:
    """True if the first '(' closes at the very end (outer parens removable)."""
    depth, quote = 0, None
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch == '"':
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and i != len(text) - 1:
                return False
    return True
