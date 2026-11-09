"""Elastic: Kibana Query Language (called "elk" in siemx, so it is never confused with
Microsoft's KQL). SPL -> ELK here; ELK -> SPL in reverse_elk.py.

Sources (checked 2026-11-08):
  DOC      https://www.elastic.co/docs/reference/query-languages/kql
  GRAMMAR  Kibana's own parser grammar (kbn-es-query/src/kuery/grammar/grammar.peggy);
           the parser below is a port of it (without the autocomplete cursor rules).

Facts used (from DOC unless marked GRAMMAR):
  - Kibana KQL only FILTERS events. No pipes, no stats/eval/table: an SPL pipeline that
    transforms events has no Kibana KQL equivalent (Elastic threshold rules or ES|QL do).
  - field: value. On keyword/numeric/date/boolean fields the value must match exactly,
    "including punctuation and case"; the Kibana query bar has no case-insensitive option.
    On text fields the value is analyzed (matches words). SPL field=value is
    case-insensitive -> flagged for review.
  - Only * is a wildcard, and only unquoted; "an asterisk inside quotation marks is a
    literal asterisk".  field: * matches any indexed value, including an empty string.
  - Escape \\():<>"*{} outside quotes (GRAMMAR: SpecialCharacter); inside quotes only "
    and \\.  AND/OR/NOT are case-insensitive keywords; as values they are escaped or
    quoted. GRAMMAR: \\n \\t \\r are whitespace escapes, so `\\not` is a newline + "ot";
    a keyword inside a wildcard value is written with a \\uXXXX escape instead.
  - Precedence differs between the Kibana bar (NOT, AND, OR) and the Query DSL / ES|QL
    KQL() (AND and OR equal, right to left) -> every and/or group is parenthesized.
  - Ranges: < <= > >=.  There is no implicit AND (GRAMMAR).
  - NOT field: value is a bool must_not, so documents without the field match; that is
    SPL's `NOT field=value`. SPL `field!=value` needs the field -> (field: * and not ...).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

DOC = "https://www.elastic.co/docs/reference/query-languages/kql"
GRAMMAR = ("https://github.com/elastic/kibana/blob/main/src/platform/packages/shared/"
           "kbn-es-query/src/kuery/grammar/grammar.peggy")

SPECIAL = set('\\():<>"*{}')
SPACE = " \t\r\n "
WILD = ""            # a parsed (unescaped) wildcard; an escaped \* stays a literal *
RANGE_OPS = ("<=", ">=", "<", ">")


class ParseError(ValueError):
    pass


@dataclass(frozen=True)
class Lit:
    text: str              # WILD marks wildcards
    quoted: bool
    kind: str              # str | wild | null | true | false


# ---- parser (port of grammar.peggy; each rule returns (node, pos) or None) ----------------------

class _Parser:
    def __init__(self, s: str):
        self.s, self.n = s, len(s)
        self.far = 0                                   # furthest position reached (errors)

    def at(self, i: int) -> str:
        return self.s[i] if i < self.n else ""

    def spaces(self, i: int) -> int:
        while i < self.n and self.s[i] in SPACE:
            i += 1
        return i

    def _word(self, i: int, w: str) -> bool:
        return self.s[i:i + len(w)].lower() == w

    def kw(self, i: int, w: str):                      # Or / And: Space+ word Space+
        if self.at(i) == "" or self.s[i] not in SPACE:
            return None
        j = self.spaces(i)
        if not self._word(j, w):
            return None
        j += len(w)
        if self.at(j) == "" or self.s[j] not in SPACE:
            return None
        return self.spaces(j)

    def not_kw(self, i: int):                          # Not: 'not'i Space+
        if self._word(i, "not") and self.at(i + 3) != "" and self.s[i + 3] in SPACE:
            return self.spaces(i + 3)
        return None

    def keyword_at(self, i: int) -> bool:              # Keyword (stops an unquoted literal)
        if self.s[i] in SPACE:
            for w in ("or", "and"):
                j = i + 1 + len(w)
                if self._word(i + 1, w) and self.at(j) != "" and self.s[j] in SPACE:
                    return True
        return self.not_kw(i) is not None

    def _join(self, kind, sub, sep, i):
        first = sub(i)
        if first is None:
            return None
        nodes, pos = [first[0]], first[1]
        while True:
            j = self.kw(pos, sep)
            nxt = sub(j) if j is not None else None
            if nxt is None:
                break
            nodes.append(nxt[0])
            pos = nxt[1]
        return (nodes[0] if len(nodes) == 1 else (kind, nodes)), pos

    # -- queries
    def or_query(self, i):
        return self._join("or", self.and_query, "or", i)

    def and_query(self, i):
        return self._join("and", self.not_query, "and", i)

    def not_query(self, i):
        j = self.not_kw(i)
        if j is not None:
            r = self.sub_query(j)
            if r is not None:
                return ("not", r[0]), r[1]
        return self.sub_query(i)

    def sub_query(self, i):
        if self.at(i) == "(":
            r = self.or_query(self.spaces(i + 1))
            if r is not None:
                k = self.spaces(r[1])
                if self.at(k) == ")":
                    return r[0], k + 1
        return self.nested_query(i)

    def nested_query(self, i):
        f = self.literal(i)
        if f is not None:
            j = self.spaces(f[1])
            if self.at(j) == ":":
                j = self.spaces(j + 1)
                if self.at(j) == "{":
                    r = self.or_query(self.spaces(j + 1))
                    if r is not None:
                        k = self.spaces(r[1])
                        if self.at(k) == "}":
                            return ("nested", f[0], r[0]), k + 1
        return self.expression(i)

    def expression(self, i):
        f = self.literal(i)
        if f is not None:
            j = self.spaces(f[1])
            for op in RANGE_OPS:                       # FieldRangeExpression
                if self.s.startswith(op, j):
                    v = self.literal(self.spaces(j + len(op)))
                    if v is not None:
                        return ("range", f[0], op, v[0]), v[1]
                    break
            if self.at(j) == ":":                      # FieldValueExpression
                r = self.list_of_values(self.spaces(j + 1))
                if r is not None:
                    return _with_field(r[0], f[0]), r[1]
        v = self.value(i)                              # ValueExpression (free text)
        if v is not None:
            return ("is", None, v[0]), v[1]
        return None

    # -- value lists: field: (a or b and not c)
    def list_of_values(self, i):
        if self.at(i) == "(":
            r = self.or_values(self.spaces(i + 1))
            if r is not None:
                k = self.spaces(r[1])
                if self.at(k) == ")":
                    return r[0], k + 1
        v = self.value(i)
        return (("v", v[0]), v[1]) if v is not None else None

    def or_values(self, i):
        return self._join("or", self.and_values, "or", i)

    def and_values(self, i):
        return self._join("and", self.not_values, "and", i)

    def not_values(self, i):
        j = self.not_kw(i)
        if j is not None:
            r = self.list_of_values(j)
            if r is not None:
                return ("not", r[0]), r[1]
        return self.list_of_values(i)

    # -- literals
    def value(self, i):
        return self.quoted(i) or self.unquoted(i)

    literal = value                                    # Field and Literal: same rule

    def quoted(self, i):
        if self.at(i) != '"':
            return None
        out, j = [], i + 1
        while j < self.n:
            c = self.s[j]
            if c == '"':
                return Lit("".join(out), True, "str"), j + 1
            if c == "\\":
                nxt = self.at(j + 1)
                if nxt in ("t", "r", "n"):
                    out.append({"t": "\t", "r": "\r", "n": "\n"}[nxt])
                    j += 2
                    continue
                u = self._unicode(j)
                if u is not None:
                    out.append(u)
                    j += 6
                    continue
                if nxt in ('\\', '"') and nxt:
                    out.append(nxt)
                    j += 2
                    continue
            out.append(c)
            j += 1
        self.far = max(self.far, j)
        return None                                    # unterminated string

    def _unicode(self, j):
        m = re.match(r"\\u([0-9a-fA-F]{4})", self.s[j:j + 6])
        return chr(int(m.group(1), 16)) if m else None

    def unquoted(self, i):
        out, j, wild = [], i, False
        while j < self.n:
            c = self.s[j]
            if c == "\\":
                nxt = self.at(j + 1)
                if nxt in ("t", "r", "n") and nxt:
                    out.append({"t": "\t", "r": "\r", "n": "\n"}[nxt])
                    j += 2
                    continue
                if nxt and nxt in SPECIAL:
                    out.append(nxt)
                    j += 2
                    continue
                u = self._unicode(j)
                if u is not None:
                    out.append(u)
                    j += 6
                    continue
                w = next((w for w in ("or", "and", "not") if self._word(j + 1, w)), None)
                if w:
                    out.append(self.s[j + 1:j + 1 + len(w)])
                    j += 1 + len(w)
                    continue
                break
            if c == "*":
                out.append(WILD)
                wild = True
                j += 1
                continue
            if c in SPECIAL or self.keyword_at(j):
                break
            out.append(c)
            j += 1
        self.far = max(self.far, j)
        if not out:
            return None
        seq = "".join(out).strip(SPACE)
        if seq in ("null", "true", "false"):
            return Lit(seq, False, seq), j
        return Lit(seq, False, "wild" if wild else "str"), j


def _with_field(tree, field: Lit):
    """('v', lit) leaves of a value list -> ('is', field, lit)."""
    if tree[0] == "v":
        return ("is", field, tree[1])
    if tree[0] == "not":
        return ("not", _with_field(tree[1], field))
    return (tree[0], [_with_field(t, field) for t in tree[1]])


def parse(text: str):
    """Kibana KQL -> AST. Raises ParseError."""
    p = _Parser(text)
    i = p.spaces(0)
    if i == len(text):
        raise ParseError("empty query (in Kibana it matches every document)")
    r = p.or_query(i)
    if r is None or p.spaces(r[1]) != len(text):
        pos = max(p.far, r[1] if r else 0)
        raise ParseError(f"not valid Kibana KQL near character {pos + 1}: "
                         f"{text[pos:pos + 20]!r}")
    return r[0]


def literals(node):
    """Every (field, value) literal in an AST (for checks)."""
    kind = node[0]
    if kind == "is":
        yield node[1], node[2]
    elif kind == "range":
        yield node[1], node[3]
    elif kind == "not":
        yield from literals(node[1])
    elif kind == "nested":
        yield None, node[1]
        yield from literals(node[2])
    else:
        for c in node[1]:
            yield from literals(c)


def problems(query: str) -> list[str]:
    """Validator: Kibana's grammar, plus two likely mistakes it accepts silently."""
    if not query.strip():
        return ["empty output"]
    try:
        ast = parse(query)
    except ParseError as e:
        return [f"ELK syntax: {e}"]
    out = []
    for _, lit in literals(ast):
        if lit is None or lit.quoted:
            continue
        if "|" in lit.text:
            out.append(f"ELK: unquoted '|' in {lit.text!r}: Kibana KQL has no pipeline "
                       "stages (quote the value if the | is part of it)")
        elif lit.kind == "str" and any(c in SPACE for c in lit.text):   # wildcards cannot be quoted
            out.append(f"ELK: unquoted value with spaces {lit.text.replace(WILD, '*')!r} is "
                       "read as one value; quote it, or join separate conditions with and/or")
    return out


# ---- SPL base search AST (search.py) -> Kibana KQL ------------------------------------------------

_NUM = re.compile(r"-?\d+(?:\.\d+)?")
_FIELD = re.compile(r"[A-Za-z_@][A-Za-z0-9_.@-]*")
KEYWORDS = ("or", "and", "not")


class Unsupported(ValueError):
    pass


def quote(v: str) -> str:
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


def unquoted_wild(v: str) -> str:
    """A value with * wildcards, unquoted (quotes would make * literal)."""
    if v != v.strip(SPACE):
        raise Unsupported("wildcard value with leading or trailing space")
    out = []
    for c in v:
        if c == "*":
            out.append("*")
        elif c in SPECIAL:
            out.append("\\" + c)
        elif c in "\t\r\n":
            out.append({"\t": "\\t", "\r": "\\r", "\n": "\\n"}[c])
        else:
            out.append(c)
    text = "".join(out)
    # keywords inside the value: \uXXXX for their first letter (\not would be \n + "ot")
    return re.sub(r"(?i)\b(or|and|not)\b",
                  lambda m: f"\\u{ord(m.group(1)[0]):04x}{m.group(1)[1:]}", text)


W_CASE = ("ELK: Kibana KQL matches keyword fields exactly and case-sensitively (the Kibana "
          "query bar has no case-insensitive option) and text fields by words; SPL matched "
          "these whole values case-insensitively: {fields}. Check how the values are stored")
W_NO_INDEX = ("ELK: no index pattern for {meta} in mappings/sources.json (add \"elk\": "
              "\"<index pattern>\" to that entry); the Elastic rule must search the right data")
W_NO_SOURCE = ("ELK: the SPL names no index or sourcetype; choose the index pattern in the "
               "Elastic rule")
W_FIELDS = ("ELK: field names kept from Splunk ({fields}); map them to your Elastic (ECS) "
            "field names in mappings/field_map.json under \"elk\"")
W_WILD_TYPE = ("ELK: {field} has the {type} type in Elastic, and Kibana KQL fails with an error "
               "on a wildcard there (KQL docs); rewrite the value (for an ip field, a CIDR range)")
W_DISPLAY = ("ELK: {cmds} dropped: they choose or order columns, which Kibana KQL cannot do "
             "(set the columns in Discover / the rule); the events matched are the same")
W_TRANSFORM = ("ELK: Kibana KQL only selects events; {cmds} {verb} no equivalent. {what}"
               "Rebuild the rest in Elastic (a threshold rule for `stats count by ... | where "
               "count > N`, otherwise ES|QL)")


class _Render:
    def __init__(self, field_map: dict):
        self.field_map = field_map
        self.warnings: list[str] = []
        self.case_fields: list[str] = []
        self.unmapped: list[str] = []
        self.applied: dict[str, str] = {}

    def name(self, f: str) -> str:
        if f.lower() in ("earliest", "latest"):
            raise Unsupported("time modifiers")
        e = self.field_map.get(f) or {}
        level = e.get("level")
        if level in ("exact", "conditional") and e.get("to"):
            if level == "conditional":
                w = f"ELK: field '{f}' mapped to {e['to']} (conditional: {e.get('note', '')}); verify"
                if w not in self.warnings:
                    self.warnings.append(w)
            self.applied[f] = e["to"]
            f = e["to"]
        elif level == "ambiguous":
            w = (f"ELK: field '{f}' is ambiguous: one of {', '.join(e.get('candidates', []))}; "
                 "choose the right field")
            if w not in self.warnings:
                self.warnings.append(w)
        elif f not in self.unmapped:
            self.unmapped.append(f)
        if not _FIELD.fullmatch(f) or f.lower() in KEYWORDS:
            raise Unsupported(f"field name {f!r} would need escaping")
        return f

    def value(self, f: str, v: str) -> str:
        from .search import BACKSLASH_WARNING
        if "\\" in v and BACKSLASH_WARNING.format(T="ELK") not in self.warnings:
            self.warnings.append(BACKSLASH_WARNING.format(T="ELK"))
        if v == "*":
            return "*"
        if re.search(r"[A-Za-z]", v) and f not in self.case_fields:
            self.case_fields.append(f)
        if "*" in v:
            ftype = (self.field_map.get(f) or {}).get("type")
            if ftype and ftype not in ("keyword", "text", "wildcard"):
                w = W_WILD_TYPE.format(field=self.applied.get(f, f), type=ftype)
                if w not in self.warnings:
                    self.warnings.append(w)
            return unquoted_wild(v)
        return v if _NUM.fullmatch(v) else quote(v)

    def match(self, f, v):
        return f"{self.name(f)}: {self.value(f, v)}"

    def node(self, n) -> str:
        kind = n[0]
        if kind == "term":
            _, f, op, v = n
            if op == "=":
                return self.match(f, v)
            if op == "!=":
                if v == "*":
                    raise Unsupported("field!=* never matches")
                name = self.name(f)
                return f"({name}: * and not {name}: {self.value(f, v)})"
            if not _NUM.fullmatch(v):
                raise Unsupported("lexicographic comparison")
            return f"{self.name(f)} {op} {v}"
        if kind == "in":
            _, f, vals = n
            name = self.name(f)
            return f"{name}: ({' or '.join(self.value(f, v) for v in vals)})"
        if kind == "not":
            return f"not {_paren(self.node(n[1]))}"
        return "(" + f" {kind} ".join(self.node(c) for c in n[1]) + ")"

    def finish(self) -> list[str]:
        w = list(self.warnings)
        if self.case_fields:
            w.append(W_CASE.format(fields=", ".join(self.applied.get(f, f)
                                                    for f in self.case_fields)))
        if self.unmapped:
            w.append(W_FIELDS.format(fields=", ".join(self.unmapped)))
        return w


def _paren(text: str) -> str:
    from .search import _balanced_outer
    return text if text.startswith("(") and _balanced_outer(text) else f"({text})"


def render(ast, field_map: dict) -> tuple[str, list[str], dict] | None:
    r = _Render(field_map)
    try:
        text = r.node(ast)
    except Unsupported:
        return None
    from .search import _balanced_outer
    if text.startswith("(") and _balanced_outer(text):
        text = text[1:-1]
    return text, r.finish(), r.applied


# ---- SPL pipeline -> Kibana KQL ------------------------------------------------------------------

FILTER = ("search", "where")          # select events; `where` has no rule yet (LLM)
DISPLAY = ("table", "fields", "sort")  # choose / order columns only


def _plan(spl: str):
    """-> (base, filter stages, display commands, transforming commands)."""
    from . import triage
    stages = triage.split_stages(spl)
    later = [(triage.command_of(s), s) for s in stages[1:]]
    cut = next((i for i, (c, _) in enumerate(later) if c not in FILTER), len(later))
    rest = [c for c, _ in later[cut:]]
    if all(c in DISPLAY for c in rest):
        return stages[0], later[:cut], rest, []
    return stages[0], later[:cut], [], rest


def _filter(base: str, extra: list[tuple[str, str]]):
    """Base search + later `search` stages -> dict, or (None, reason) for a rule gap."""
    from . import fieldmap, rules, search
    try:
        meta, ast = search.parse(base)
        nodes = [ast] if ast is not None else []
        for cmd, st in extra:
            if cmd != "search":
                return None, cmd
            m2, a2 = search.parse(st.strip()[len(cmd):].strip())
            if m2:
                return None, "search"
            nodes.append(a2)
    except search._Unsupported:
        return None, "search"
    if not nodes:
        return None, "search"
    warnings, index = [], None
    matched = rules.match_source(meta, "elk") if meta else None
    if matched:
        index, dropped, by = matched
        warnings += rules.placeholder_warnings(meta, index, "elk")
        if dropped:
            warnings.append(rules.INDEX_DROPPED_WARNING.format(T="ELK", index=dropped, by=by))
    elif meta:                             # the query needs no index: placeholder in the meta
        index = rules.placeholder_for(meta, "elk", base)
        warnings += rules.placeholder_warnings(meta, index, "elk")
    else:
        warnings.append(W_NO_SOURCE)
    ast = nodes[0] if len(nodes) == 1 else ("and", nodes)
    r = render(ast, fieldmap.table_map("elk", index) if index else {})
    if r is None:
        return None, "search"
    text, w, applied = r
    return {"query": text, "confidence": 0.9, "method": "rules", "warnings": warnings + w,
            "tokens": 0, "index": index, "field_map": applied}, None


def convert(spl: str) -> dict | None:
    """SPL -> Kibana KQL by rules. None = a rule gap the LLM may try (only when nothing
    in the pipeline transforms events; a model cannot express stats in a filter either)."""
    base, filters, display, transforms = _plan(spl)
    res, _ = _filter(base, filters)
    if transforms:
        cmds = ", ".join(f"`{c}`" for c in dict.fromkeys(transforms))
        what = ("The file holds only the event filter (the stages before it). " if res
                else "")
        out = res or {"query": "", "confidence": 0.0, "method": "rules", "warnings": [],
                      "tokens": 0}
        verb = "has" if len(set(transforms)) == 1 else "have"
        out["warnings"] = [W_TRANSFORM.format(cmds=cmds, verb=verb, what=what)] + out["warnings"]
        out["unsupported"] = True
        out["no_rule"] = list(dict.fromkeys(transforms))
        return out
    if res is None:
        return None
    if display:
        res["warnings"].insert(0, W_DISPLAY.format(cmds=", ".join(f"`{c}`" for c in display)))
    return res


def missing_rules(spl: str) -> list[str]:
    """For the report: which SPL command stopped the rules."""
    base, filters, _, transforms = _plan(spl)
    res, gap = _filter(base, filters)
    return transforms or ([] if res else [gap or "search"])


# ---- for the LLM prompt (own summary of DOC + GRAMMAR; no copied doc text) -----------------------

REFERENCE = {
    "source": DOC, "lang": "elk", "title": "Kibana Query Language (KQL) syntax",
    "text": (
        "Kibana KQL filters documents; it has no pipes, no aggregation, no field creation, "
        "no column selection. Syntax: `field: value`; several values `field: (a or b)`; "
        "`field: *` = the field has any value; ranges `field > 10`, `<`, `<=`, `>=`; "
        "`and`, `or`, `not` (case-insensitive); parentheses group. There is no implicit "
        "AND: write `and` between conditions. Quoted values \"...\" are exact phrases and * "
        "inside quotes is a literal asterisk. Unquoted values may use * as a wildcard "
        "(string fields only). Outside quotes escape \\ ( ) : < > \" * { } with a "
        "backslash; inside quotes escape only \" and \\. keyword fields match exactly and "
        "case-sensitively; text fields match words. Without parentheses the Kibana bar reads "
        "NOT, then AND, then OR, but other Elastic entry points do not: always parenthesize "
        "mixed and/or. Nested fields: `field: { a: 1 and b: 2 }`."),
}
