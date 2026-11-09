"""KQL (Sentinel) and XQL (Cortex) -> Kibana KQL (ELK), directly, not through SPL.

Input is read with the existing parsers (kql_expr.py, xql_expr.py; pipes and heads from
reverse.py / reverse_xql.py). Output rules and their sources: elk.py.

Kibana KQL only filters, so (as for SPL -> ELK):
  where / filter stages              -> the filter
  project / project-away / sort      -> dropped with a note (columns only)
  (KQL)  fields / sort (XQL)
  anything else (summarize, extend,  -> unsupported; the file keeps the filter part
  comp, alter, dedup, limit, ...)
  a condition without a rule          -> the LLM (only when nothing transforms events)

Semantics that differ (from the docs cited in kql_expr.py / xql_expr.py and elk.py):
  KQL == != in are case-sensitive; =~ !~ in~ contains startswith endswith are not.
  XQL string comparison is case-insensitive unless `config case_sensitive = true`;
      in XQL "..." a * is a wildcard.
  Kibana KQL keyword fields match exactly and case-sensitively; text fields by words.
  Kibana `field: *` also matches an empty string; KQL isnotempty() does not.
  Time ranges (TimeGenerated > ago(), config timeframe) belong to the Elastic rule's
  look-back, not to the query -> dropped with a note.
"""
from __future__ import annotations

import re

from . import elk, fieldmap, kql_expr, reverse, reverse_xql, rules, validate, xql_expr

W_CI = ("ELK: {lang} matched {fields} case-insensitively; Kibana KQL matches keyword fields "
        "case-sensitively (the Kibana query bar has no case-insensitive option). Check how "
        "the values are stored")
W_TEXT = ("ELK: on text fields Kibana KQL matches words, not whole values or substrings; "
          "for the same result these must be keyword fields in Elastic: {fields}")
W_XQL_NOT = ("ELK: `not` also matches events without the field; XQL null handling for != / "
             "not in is not documented; verify")
W_EMPTY = ("ELK: `{field}: *` also matches an empty string; KQL isnotempty()/isempty() treat "
           "\"\" as empty; verify")
W_TIME = ("ELK: time range `{expr}` dropped: set it as the Elastic rule's look-back (or the "
          "Discover time picker)")
W_NO_INDEX = ("ELK: no index pattern for {lang} {kind} {table} in mappings/sources.json (add "
              "\"elk\" to the entry that maps it); the Elastic rule must search the right data")
W_MANY_INDEX = "ELK: several index patterns map to {table} ({all}); used {used}; verify"
W_FIELDS = ("ELK: field names kept from {lang} ({fields}); map them to your Elastic (ECS) field "
            "names in mappings/field_map.json under \"elk\"")
W_DISPLAY = ("ELK: {ops} dropped: they choose or order columns, which Kibana KQL cannot do "
             "(set the columns in Discover / the rule); the events matched are the same")
W_TRANSFORM = ("ELK: Kibana KQL only selects events; {ops} {verb} no equivalent. {what}"
               "Rebuild the rest in Elastic (a threshold rule for counts per field, "
               "otherwise ES|QL)")

LIT_STAR = ""           # placeholder for a literal * while building a wildcard value
_KQL_TIME = re.compile(r"^\s*TimeGenerated\s*(>=|>)\s*ago\(\s*\d+[dhms]\s*\)\s*$")
_PLAIN_NAMES = re.compile(r"\s*-?\s*[A-Za-z_][\w.]*(\s*,\s*[A-Za-z_][\w.]*)*\s*")


class Gap(ValueError):
    """No rule; the LLM may try (when nothing in the query transforms events)."""


# ---- index pattern and field names --------------------------------------------------------------

def index_for(table: str, lang: str) -> tuple[str | None, list[str]]:
    want = table.lower() if lang == "xql" else table
    found = []
    for v in rules._load_sources().values():
        if (isinstance(v, dict) and v.get("elk")
                and reverse.source_name(v.get(lang), lang) == want and v["elk"] not in found):
            found.append(v["elk"])
    kind = "table" if lang == "kql" else "dataset"
    if not found:
        return None, [W_NO_INDEX.format(lang=lang.upper(), kind=kind, table=table)]
    if len(found) > 1:
        return found[0], [W_MANY_INDEX.format(table=table, all=", ".join(found), used=found[0])]
    return found[0], []


def field_names(table: str, lang: str, index: str | None) -> tuple[dict, list[str]]:
    """Source column -> Elastic field, through the Splunk name: the source's EXACT
    entries (column -> SPL field), then the "elk" entries for the index pattern."""
    if not index:
        return {}, []
    to_spl = reverse.reverse_field_names(table, lang)
    elk_map = fieldmap.table_map("elk", index)
    out, warnings = {}, []
    for spl_name, e in elk_map.items():
        if e.get("level") not in ("exact", "conditional") or not e.get("to"):
            continue
        cols = [c for c, s in to_spl.items() if s == spl_name] or [spl_name]
        for c in cols:
            out[c] = e["to"]
            if e["level"] == "conditional":
                warnings.append(f"ELK: field '{c}' mapped to {e['to']} "
                                f"(conditional: {e.get('note', '')}); verify")
    return out, warnings


# ---- conditions -----------------------------------------------------------------------------------

class _Cond:
    def __init__(self, lang: str, rename: dict, case_sensitive: bool = False):
        self.lang, self.rename, self.cs = lang, rename, case_sensitive
        self.warnings: list[str] = []
        self.ci: list[str] = []          # fields compared case-insensitively in the source
        self.text: list[str] = []        # fields compared as strings
        self.unmapped: list[str] = []

    def warn(self, w):
        if w not in self.warnings:
            self.warnings.append(w)

    def field(self, n) -> str:
        if n[0] != "col":
            raise Gap("comparison on an expression, not a field")
        name = self.rename.get(n[1])
        if name is None:
            name = n[1]
            if name not in self.unmapped:
                self.unmapped.append(name)
        if not elk._FIELD.fullmatch(name) or name.lower() in elk.KEYWORDS:
            raise Gap(f"field name {name!r} would need escaping")
        return name

    def _string(self, f, ci):
        if f not in self.text:
            self.text.append(f)
        if ci and f not in self.ci:
            self.ci.append(f)

    def eq(self, f: str, v, ci: bool, wildcards: bool = False) -> str:
        if v[0] == "num":
            return f"{f}: {v[1]}"
        if v[0] != "str":
            raise Gap("comparison with a non-literal")
        s = v[1]
        self._string(f, ci and bool(re.search(r"[A-Za-z]", s)))
        if wildcards and "*" in s:
            if s == "*":
                raise Gap('"*" alone (any value or a literal star?)')
            return f"{f}: {elk.unquoted_wild(s)}"
        return f"{f}: {elk.quote(s)}"

    def pattern(self, f: str, v, shape: str, ci: bool) -> str:
        """contains / startswith / endswith -> an unquoted wildcard value."""
        if v[0] != "str" or not v[1]:
            raise Gap("pattern with a non-literal or empty value")
        self._string(f, ci and bool(re.search(r"[A-Za-z]", v[1])))
        full = shape.format(v[1].replace("*", LIT_STAR))         # a literal * stays literal
        return f"{f}: {elk.unquoted_wild(full).replace(LIT_STAR, chr(92) + '*')}"

    def join(self, kind, parts) -> str:
        return "(" + f" {kind} ".join(parts) + ")"

    def flat(self, n, kind):
        if n[0] == kind:
            return self.flat(n[1], kind) + self.flat(n[2], kind)
        return [n]

    # -- KQL
    def kql(self, n) -> str:
        k = n[0]
        if k in ("and", "or"):
            return self.join(k, [self.kql(c) for c in self.flat(n, k)])
        if k == "paren":
            return self.kql(n[1])
        if k == "call" and n[1] == "not" and len(n[2]) == 1:
            return f"not {elk._paren(self.kql(n[2][0]))}"
        if k == "call" and n[1] in ("isnotempty", "isempty", "isnotnull", "isnull") \
                and len(n[2]) == 1:
            f = self.field(n[2][0])
            if n[1] in ("isnotempty", "isempty"):
                self.warn(W_EMPTY.format(field=f))
            return f"{f}: *" if n[1] in ("isnotempty", "isnotnull") else f"not {f}: *"
        if k == "cmp":
            _, op, a, b = n
            f = self.field(a)
            if op in ("==", "=~"):
                return self.eq(f, b, ci=op == "=~")
            if op in ("!=", "!~"):
                return f"not {self.eq(f, b, ci=op == '!~')}"
            if op in ("<", "<=", ">", ">=") and b[0] == "num":
                return f"{f} {op} {b[1]}"
            raise Gap(f"KQL comparison {op} with {b[0]}")
        if k == "strop":
            _, op, a, b = n
            shape = {"contains": "*{}*", "startswith": "{}*", "endswith": "*{}"}[op.lstrip("!")]
            text = self.pattern(self.field(a), b, shape, ci=True)
            return f"not {text}" if op.startswith("!") else text
        if k == "in":
            _, op, a, items = n
            f = self.field(a)
            vals = [self.eq(f, i, ci=op == "in~").split(": ", 1)[1] for i in items]
            text = f"{f}: ({' or '.join(vals)})"
            return f"not {text}" if op == "!in" else text
        raise Gap(f"KQL {k} {n[1] if len(n) > 1 else ''}".strip())

    # -- XQL
    def xql(self, n) -> str:
        k, ci = n[0], not self.cs
        if k in ("and", "or"):
            return self.join(k, [self.xql(c) for c in self.flat(n, k)])
        if k == "paren":
            return self.xql(n[1])
        if k == "not":
            self.warn(W_XQL_NOT)
            return f"not {elk._paren(self.xql(n[1]))}"
        if k == "null":
            f = self.field(n[2])
            return f"not {f}: *" if n[1] == "=" else f"{f}: *"
        if k == "cmp":
            _, op, a, b = n
            f = self.field(a)
            if op == "=":
                return self.eq(f, b, ci=ci, wildcards=True)
            if op == "!=":
                self.warn(W_XQL_NOT)
                return f"not {self.eq(f, b, ci=ci, wildcards=True)}"
            if op in ("<", "<=", ">", ">=") and b[0] == "num":
                return f"{f} {op} {b[1]}"
            raise Gap(f"XQL comparison {op} with {b[0]}")
        if k == "contains":
            if n[2][0] == "str" and "*" in n[2][1]:
                raise Gap("* inside an XQL contains value (wildcard or literal: not documented)")
            return self.pattern(self.field(n[1]), n[2], "*{}*", ci=ci)
        if k == "in":
            _, op, a, items = n
            f = self.field(a)
            if any(i[0] == "str" and "*" in i[1] for i in items):
                raise Gap("* inside an XQL in-list (wildcard or literal: not documented)")
            vals = [self.eq(f, i, ci=ci).split(": ", 1)[1] for i in items]
            text = f"{f}: ({' or '.join(vals)})"
            if op == "not in":
                self.warn(W_XQL_NOT)
                return f"not {text}"
            return text
        raise Gap(f"XQL {k}")

    def finish(self) -> list[str]:
        w = list(self.warnings)
        if self.ci:
            w.append(W_CI.format(lang=self.lang.upper(), fields=", ".join(self.ci)))
        if self.text:
            w.append(W_TEXT.format(fields=", ".join(self.text)))
        if self.unmapped:
            w.append(W_FIELDS.format(lang=self.lang.upper(), fields=", ".join(self.unmapped)))
        return w


# ---- whole query ---------------------------------------------------------------------------------

def _split(stages, op_of, filter_ops, display):
    """-> (filter args, display ops, transforming ops), cut at the first non-filter stage."""
    ops = [op_of(s) for s in stages]
    cut = next((i for i, (op, _) in enumerate(ops) if op not in filter_ops), len(ops))
    rest = ops[cut:]
    filters = [arg for _, arg in ops[:cut]]
    if all(display(op, arg) for op, arg in rest):
        return filters, [op for op, _ in rest], []
    return filters, [], [op for op, _ in rest]


def _kql_display(op, arg):
    return op in ("sort by", "order by") or (op in ("project", "project-away")
                                              and bool(_PLAIN_NAMES.fullmatch(arg)))


def _xql_display(op, arg):
    return op == "sort" or (op == "fields" and bool(_PLAIN_NAMES.fullmatch(arg)))


def _unsupported(reason: str) -> dict:
    return {"query": "", "confidence": 0.0, "method": "rules", "unsupported": True,
            "warnings": [f"not converted: {reason}"], "tokens": 0}


def convert(text: str, lang: str) -> dict | None:
    """KQL/XQL -> Kibana KQL by rules. None = a condition without a rule (LLM may try)."""
    if lang == "kql":
        problems = validate.check(text, "kql") if validate.KqlValidator.available() else []
        bad = [p for p in problems if "syntax" in p or p.startswith("unbalanced")]
        if bad:
            return _unsupported(f"input is not valid KQL: {bad[0]}")          # no LLM
        stages = reverse.split_pipes(text)
        table = stages[0].strip() if stages else ""
        if not reverse._IDENT.fullmatch(table):
            return _unsupported("the query must start with a table name")
        settings, rest = {"case_sensitive": False, "earliest": None}, stages[1:]
        op_of, filter_ops, display = reverse.operator_of, ("where", "filter"), _kql_display
    else:
        problems = validate.check(reverse.strip_comments(text), "xql")
        if problems and problems != ["empty output"]:
            return _unsupported(f"input is not valid XQL: {problems[0]}")
        try:
            settings, table, rest = reverse_xql.read_head(reverse.split_pipes(text))
        except reverse.Unsupported as e:
            return _unsupported(str(e))
        op_of, filter_ops, display = reverse_xql.operator_of, ("filter",), _xql_display

    filters, dropped, transforms = _split(rest, op_of, filter_ops, display)
    index, warnings = index_for(table, lang)
    rename, map_warnings = field_names(table, lang, index)
    warnings += map_warnings
    if settings.get("earliest"):
        warnings.append(W_TIME.format(expr=f"config timeframe ({settings['earliest'][1:]})"))
    cond = _Cond(lang, rename, settings.get("case_sensitive", False))
    parts, gap = [], None
    try:
        for arg in filters:
            conjuncts = [arg] if reverse.has_top_level_or(arg) else reverse.split_and(arg)
            for c in conjuncts:
                if lang == "kql" and _KQL_TIME.match(c):
                    warnings.append(W_TIME.format(expr=c.strip()))
                    continue
                if lang == "kql" and re.search(r"\b(ago|now|datetime)\(", c):
                    raise Gap("time expression other than TimeGenerated > ago()")
                node = (kql_expr.parse(c) if lang == "kql" else xql_expr.parse(c))
                parts.append(cond.kql(node) if lang == "kql" else cond.xql(node))
    except (Gap, kql_expr.Unsupported, elk.Unsupported) as e:
        gap = str(e)
    # every or-group is already parenthesized (_Cond.join), so a plain and-chain is safe
    query = " and ".join(parts)
    from .search import _balanced_outer
    if len(parts) == 1 and query.startswith("(") and _balanced_outer(query):
        query = query[1:-1]

    if transforms:
        ops = ", ".join(f"`{o}`" for o in dict.fromkeys(transforms))
        verb = "has" if len(set(transforms)) == 1 else "have"
        ok = query and not gap
        what = "The file holds only the event filter (the stages before it). " if ok else ""
        out = {"query": query if ok else "", "confidence": 0.9 if ok else 0.0,
               "method": "rules", "unsupported": True, "tokens": 0, "index": index,
               "no_rule": list(dict.fromkeys(transforms)) + ([gap] if gap else []),
               "warnings": [W_TRANSFORM.format(ops=ops, verb=verb, what=what)]
               + (warnings + cond.finish() if ok else [])}
        return out
    if gap:
        return None
    if not query:
        return _unsupported("no filter: in Elastic this is only the index pattern (empty query)")
    if dropped:
        warnings.insert(0, W_DISPLAY.format(ops=", ".join(f"`{o}`" for o in dropped)))
    return {"query": query, "confidence": 0.9, "method": "rules", "tokens": 0, "index": index,
            "warnings": warnings + cond.finish(), "field_map": rename or None}


def missing_rules(text: str, lang: str) -> list[str]:
    res = convert(text, lang)
    return ["condition"] if res is None else res.get("no_rule") or []
