"""Kibana KQL (ELK) -> KQL (Sentinel) and XQL (Cortex), directly, not through SPL.

Input: elk.py's parser, with the optional `# index: <pattern>` header (reverse_elk.py).
The index pattern selects the KQL table / XQL dataset through mappings/sources.json
(the entry that has this "elk" value). Without a mapped index there is no table to
query, so the result is unsupported and never sent to the LLM (it cannot know it either).

Semantics (sources: elk.py for Kibana; KQL datatypes-string-operators; XQL
stages/config.md and stages/filter.md, local copies in rag/raw):
  Kibana `f: "v"` on a keyword field: whole value, case-sensitive
      KQL  f == "v"            (== is case-sensitive)
      XQL  f = "v" with `config case_sensitive = true` ("controls whether field values
           are evaluated in a case-sensitive manner. Default is false")
    On a text field Kibana matches words instead -> flagged for review.
  Kibana wildcard `f: *x*`, `x*`, `*x`, `a*b`
      KQL  contains_cs / startswith_cs / endswith_cs / matches regex "^a.*b$"
      XQL  f = "a*b"  (in "..." a * matches any sequence)
  Kibana `f: *` (any value, also an empty string)
      KQL  isnotempty(f) (excludes "": flagged)   XQL  f != null
  ranges with numbers; not; and/or (always parenthesized: XQL does not document
  and/or precedence).
Not translated (rule gap -> LLM when the table is known): free text, nested queries,
non-numeric ranges, null/true/false literals; for XQL also " or a literal * in a value.
"""
from __future__ import annotations

import re

from . import elk, fieldmap, reverse, rules, schema
from .reverse_elk import read_header

W_TEXT = ("{T}: if these are text fields in Elastic, Kibana KQL matched words, not whole "
          "values: {fields}. {how}")
W_EMPTY = ("KQL: isnotempty() excludes empty strings; Kibana `{field}: *` also matched \"\"; "
           "verify")
W_XQL_NOT = ("XQL: Kibana `not` also matched documents without the field; XQL null handling "
             "for not / != is not documented; verify")
W_FIELDS = ("{T}: field names kept from Elastic ({fields}); map them in "
            "mappings/field_map.json (Splunk name -> \"elk\" and -> \"{t}\" entries)")
W_NO_HEADER = ("the Kibana query names no index pattern: start the file with "
               "`# index: <pattern>` so the {kind} can be found")


class Gap(ValueError):
    """No rule; the LLM may try (the table is known)."""


class Fail(ValueError):
    """Not translatable without more mappings; never sent to the LLM."""


def table_for(index: str, target: str) -> tuple[str, list[str]]:
    """Index pattern -> the KQL table / XQL dataset text of the same sources.json entry."""
    found = []
    for v in rules._load_sources().values():
        if isinstance(v, dict) and v.get("elk") == index and v.get(target) \
                and v[target] not in found:
            found.append(v[target])
    kind = "table" if target == "kql" else "dataset"
    if not found:
        raise Fail(f"no {target.upper()} {kind} in mappings/sources.json for the index pattern "
                   f"{index} (add \"{target}\" to the entry whose \"elk\" is {index})")
    w = [] if len(found) == 1 else [
        f"{target.upper()}: several {kind}s map to {index} ({'; '.join(found)}); used "
        f"{found[0]}; verify"]
    return found[0], w


def field_names(index: str, target: str, table: str) -> tuple[dict, list[str]]:
    """Elastic field -> target column through the Splunk name: the EXACT "elk" entries
    (Splunk -> Elastic, read backwards), then the target's entries for that Splunk field."""
    to_spl = reverse.reverse_field_names(index, "elk")
    tmap = fieldmap.table_map(target, table)
    out, warnings = {}, []
    for elk_name, spl_name in to_spl.items():
        e = tmap.get(spl_name) or {}
        if e.get("level") in ("exact", "conditional") and e.get("to"):
            out[elk_name] = e["to"]
            if e["level"] == "conditional":
                warnings.append(f"{target.upper()}: field '{spl_name}' mapped to {e['to']} "
                                f"(conditional: {e.get('note', '')}); verify")
    return out, warnings


class _Render:
    def __init__(self, target: str, rename: dict, table_name: str):
        self.t, self.rename, self.table = target, rename, table_name
        self.warnings: list[str] = []
        self.text: list[str] = []
        self.unmapped: list[str] = []
        self.strings = False                     # XQL needs config case_sensitive = true

    def warn(self, w):
        if w not in self.warnings:
            self.warnings.append(w)

    def field(self, lit) -> str:
        if lit is None:
            raise Gap("free-text term (Kibana searches the default fields)")
        if lit.kind != "str" or not lit.text or "*" in lit.text:
            raise Gap(f"field name {lit.text.replace(elk.WILD, '*')!r} (wildcard or special)")
        name = self.rename.get(lit.text)
        if name is None:
            name = lit.text
            if name not in self.unmapped:
                self.unmapped.append(name)
        if self.t == "kql":
            return rules.kql_name(name)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise Fail(f"Elastic field {name!r} has no XQL name; map it in "
                       "mappings/field_map.json")
        return name

    def numeric_column(self, col: str) -> bool | None:
        t = schema.field_type(self.table, self.t, col.strip("[]'"))
        return None if t is None else t in ("int", "long", "real", "decimal")

    # -- values
    def kql_str(self, v: str) -> str:
        return '@"' + v.replace('"', '""') + '"' if ('"' in v or "\\" in v) else f'"{v}"'

    def xql_str(self, v: str) -> str:
        if '"' in v:
            raise Gap('" inside a value (XQL "..." strings have no escape)')
        if "*" in v:
            raise Gap('literal * in a value (XQL "..." reads * as a wildcard)')
        return f'"{v}"'

    def is_(self, f_lit, v) -> str:
        f = self.field(f_lit)
        if v.kind in ("null", "true", "false"):
            raise Gap(f"{v.kind} literal")
        if v.kind == "wild" and v.text == elk.WILD:                       # f: *
            if self.t == "kql":
                self.warn(W_EMPTY.format(field=f_lit.text))
                return f"isnotempty({f})"
            return f"{f} != null"
        number = v.kind == "str" and not v.quoted and re.fullmatch(r"-?\d+(\.\d+)?", v.text)
        if number and self.numeric_column(f) is not False:
            return f"{f} == {v.text}" if self.t == "kql" else f"{f} = {v.text}"
        if f_lit.text not in self.text:
            self.text.append(f_lit.text)
        self.strings = True
        if self.t == "xql":
            if v.kind == "wild":
                parts = v.text.split(elk.WILD)
                if any('"' in p for p in parts):
                    raise Gap('" inside a value (XQL "..." strings have no escape)')
                if any("*" in p for p in parts):
                    raise Gap('literal * in a value (XQL "..." reads * as a wildcard)')
                return f'{f} = "{"*".join(parts)}"'
            return f"{f} = {self.xql_str(v.text)}"
        if v.kind != "wild":
            return f"{f} == {self.kql_str(v.text)}"
        parts = v.text.split(elk.WILD)
        if len(parts) == 3 and not parts[0] and not parts[2] and parts[1]:
            return f"{f} contains_cs {self.kql_str(parts[1])}"
        if len(parts) == 2 and parts[0] and not parts[1]:
            return f"{f} startswith_cs {self.kql_str(parts[0])}"
        if len(parts) == 2 and not parts[0] and parts[1]:
            return f"{f} endswith_cs {self.kql_str(parts[1])}"
        rx = "^" + ".*".join(re.escape(p) for p in parts) + "$"
        return f"{f} matches regex {self.kql_str(rx)}"

    def node(self, n) -> str:
        k = n[0]
        if k == "is":
            return self.is_(n[1], n[2])
        if k == "range":
            f, op, v = self.field(n[1]), n[2], n[3]
            if v.kind != "str" or not re.fullmatch(r"-?\d+(\.\d+)?", v.text):
                raise Gap("range on a non-number (dates, strings)")
            return f"{f} {op} {v.text}"
        if k == "not":
            inner = self.node(n[1])
            if self.t == "kql":
                return f"not({inner})"
            self.warn(W_XQL_NOT)
            return f"not ({inner})"
        if k == "nested":
            raise Gap("nested query field: { ... }")
        return "(" + f" {k} ".join(self.node(c) for c in n[1]) + ")"

    def finish(self) -> list[str]:
        w = list(self.warnings)
        T = self.t.upper()
        if self.text:
            how = ("Use has / has_cs for word matching." if self.t == "kql"
                   else "Use contains for word matching.")
            w.append(W_TEXT.format(T=T, fields=", ".join(self.text), how=how))
        if self.unmapped:
            w.append(W_FIELDS.format(T=T, t=self.t, fields=", ".join(self.unmapped)))
        return w


def _unsupported(reason: str, llm_base: str | None = None) -> dict:
    return {"query": "", "confidence": 0.0, "method": "rules", "unsupported": True,
            "warnings": [f"not converted: {reason}"], "tokens": 0, "llm_base": llm_base}


def convert(text: str, target: str) -> dict:
    """-> result dict; unsupported with llm_base set = a rule gap the LLM may try."""
    index, body = read_header(text)
    try:
        ast = elk.parse(body)
    except elk.ParseError as e:
        return _unsupported(f"invalid Kibana KQL: {e}")                 # never to the LLM
    kind = "table" if target == "kql" else "dataset"
    if not index:
        return _unsupported(W_NO_HEADER.format(kind=kind))
    try:
        table_text, warnings = table_for(index, target)
    except Fail as e:
        return _unsupported(str(e))
    table = schema.table_of(table_text, target)
    rename, map_warnings = field_names(index, target, table)
    r = _Render(target, rename, table)
    try:
        cond = r.node(ast)
    except Gap as e:
        return _unsupported(str(e), llm_base=table_text)
    except Fail as e:
        return _unsupported(str(e))
    from .search import _balanced_outer
    if cond.startswith("(") and _balanced_outer(cond):
        cond = cond[1:-1]
    if target == "kql":
        query = f"{table_text}\n| where {cond}"
    else:
        query = f"{table_text}\n| filter {cond}"
        if r.strings:
            query = "config case_sensitive = true\n| " + query
    return {"query": query, "confidence": 0.9, "method": "rules", "tokens": 0,
            "warnings": warnings + map_warnings + r.finish(), "field_map": rename or None}
