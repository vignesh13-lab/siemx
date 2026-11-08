"""Kibana KQL (Elastic) -> SPL base search, by rules. Parser and facts: elk.py.

A Kibana KQL query names no index: the index pattern lives in the Elastic rule or data
view. So a detections/elk/*.elk file may start with one siemx header line

    # index: logs-system.security-*

which is mapped to a Splunk source through mappings/sources.json ("elk" entries), like
a KQL table. Without it the SPL searches the default indexes (flagged).

SPL search semantics (help.splunk.com .../search-commands/search): field=value matches the
whole value, case-insensitively; * is a wildcard (also inside quotes); NOT field=value
also returns events without the field; precedence NOT > OR > AND, so every group is
parenthesized here.
"""
from __future__ import annotations

import re

from . import elk, search, validate
from .reverse import Unsupported, _unsupported, base_search_for, reverse_field_names

HEADER = re.compile(r"\A\s*#\s*index\s*:\s*(\S+)\s*(?:\n|\Z)", re.I)
_SPL_FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*")
_SPL_PLAIN = re.compile(r"[A-Za-z0-9_.\-]+")

W_CASE = ("SPL: search matches whole values case-insensitively; Kibana KQL matched {fields} "
          "exactly and case-sensitively (keyword fields) or by words (text fields). If case "
          "or partial-word matching matters, use where / CASE() or wildcards; verify")
W_NO_INDEX = ("SPL: the Kibana query names no index pattern (add a first line "
              "`# index: <pattern>`); this SPL searches the default indexes")
W_FIELDS = ("SPL: field names kept from Elastic ({fields}); map them to your Splunk field "
            "names")


def read_header(text: str) -> tuple[str | None, str]:
    m = HEADER.match(text)
    return (m.group(1), text[m.end():]) if m else (None, text)


class _Gap(ValueError):
    """No rule for this construct; the LLM may try."""


class _Render:
    def __init__(self, renames: dict[str, str]):
        self.renames = renames
        self.case_fields: list[str] = []
        self.unmapped: list[str] = []

    def field(self, lit: elk.Lit | None) -> str:
        if lit is None:
            raise _Gap("free-text term (Kibana searches the default fields, SPL _raw)")
        if lit.kind != "str" or lit.text == "":
            raise _Gap(f"field name {lit.text.replace(elk.WILD, '*')!r} (wildcard or special)")
        name = self.renames.get(lit.text)
        if name is None:
            name = lit.text
            if name not in self.unmapped:
                self.unmapped.append(name)
        if not _SPL_FIELD.fullmatch(name) or name.upper() in ("AND", "OR", "NOT"):
            raise _Gap(f"field name {name!r} needs quoting in SPL")
        return name

    def value(self, field: str, lit: elk.Lit) -> str:
        if lit.kind == "null":
            raise _Gap("null value")
        if "*" in lit.text:                       # escaped \* (wildcards are elk.WILD)
            raise _Gap("literal * (SPL search reads * as a wildcard)")
        v = lit.text.replace(elk.WILD, "*")
        if v == "*":
            return "*"
        if re.search(r"[A-Za-z]", v) and field not in self.case_fields:
            self.case_fields.append(field)
        if _SPL_PLAIN.fullmatch(v.replace("*", "")) and v.upper() not in ("AND", "OR", "NOT"):
            return v
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'

    def node(self, n) -> str:
        kind = n[0]
        if kind == "is":
            f = self.field(n[1])
            return f"{f}={self.value(f, n[2])}"
        if kind == "range":
            f, op, lit = self.field(n[1]), n[2], n[3]
            if lit.kind != "str" or not re.fullmatch(r"-?\d+(?:\.\d+)?", lit.text):
                raise _Gap("range on a non-number (dates, strings)")
            return f"{f}{op}{lit.text}"
        if kind == "not":
            return f"NOT {_paren(self.node(n[1]))}"
        if kind == "nested":
            raise _Gap("nested query field: { ... }")
        word = " AND " if kind == "and" else " OR "
        return "(" + word.join(self.node(c) for c in n[1]) + ")"


def _paren(text: str) -> str:
    return text if text.startswith("(") and search._balanced_outer(text) else f"({text})"


def convert(text: str) -> dict:
    index, body = read_header(text)
    try:
        ast = elk.parse(body)
    except elk.ParseError as e:
        return _unsupported(f"invalid Kibana KQL: {e}")       # bad input: never to the LLM
    warnings, base = [], None
    if index:
        try:
            base, warnings = base_search_for(index, "elk")
        except Unsupported as e:
            return _unsupported(str(e))                       # unmapped source: never guessed
    else:
        warnings.append(W_NO_INDEX)
    r = _Render(reverse_field_names(index, "elk") if index else {})
    try:
        filt = r.node(ast)
    except _Gap as e:
        return _unsupported(str(e), llm_base=base, llm_table=index)
    if filt.startswith("(") and search._balanced_outer(filt):
        filt = filt[1:-1]
    spl = f"{base} {filt}" if base else filt
    try:                                                      # safety net: our own SPL reads back
        search.parse(spl)
    except search._Unsupported as e:
        return _unsupported(f"generated SPL does not read back ({e})", llm_base=base,
                            llm_table=index)
    if r.case_fields:
        warnings.append(W_CASE.format(fields=", ".join(r.case_fields)))
    if r.unmapped:
        warnings.append(W_FIELDS.format(fields=", ".join(r.unmapped)))
    warnings += [f"validation: {p}" for p in validate.check(spl, "spl")]
    return {"query": spl, "confidence": 0.9, "method": "rules", "warnings": warnings,
            "tokens": 0}
