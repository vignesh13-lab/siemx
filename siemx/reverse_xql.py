"""Roadmap 7 (part 3): XQL -> SPL, rules first (the LLM fallback lives in pipeline.py).

    config timeframe = 1d | dataset = xdr_data | filter ... | comp ... by ...
        ->  index=... earliest=-1d | where ... | stats ... by ...

No official XQL parser is available, so the input is checked with what we have:
balanced quotes/parentheses, and every stage/function name against the official XQL
reference (validate.xql_problems). A failed check -> unsupported, no LLM (fix the input).

Head of the query (stages/config.md, stages/dataset.md):
  config timeframe = N<S|M|H|D|W>   earliest=-N<s|m|h|d|w>   (XQL M = minutes; MO / Y
                                    and `timeframe between` are not translated)
  config case_sensitive = true|false  string comparison mode (default: insensitive)
  dataset [=] name                  base search from mappings/sources.json read backwards;
                                    no dataset stage = xdr_data (documented default)
  dataset in (...), preset, datamodel, cold_dataset -> unsupported, no LLM

Stages (anything else is a rule gap -> unsupported, the LLM may try):
  filter <cond>                where <cond>              (xql_expr.py)
  alter a = e, ...             eval a = e, ...
  fields a, b as c             rename b AS c | table a, c
  fields - a, b                fields - a, b
  comp f(x) as n, ... by g     stats f(x) AS n, ... by g count() count(x) count_distinct
                                                         sum avg min max; `as` required
                                                         (the default name is not documented)
  sort asc a, desc b           sort 0 +a, -b             (direction required: the XQL
                                                         default is not documented)
  limit N                      head N
  dedup a, b [by asc|desc t]   [sort 0 ±t |] dedup a b
"""
from __future__ import annotations

import re

from . import validate, xql_expr
from .kql_expr import Unsupported as ExprUnsupported
from .reverse import (Unsupported, _assignments, _unsupported, base_search_for,
                      has_top_level_or, reverse_field_names, split_and, split_pipes, split_top,
                      strip_comments)

DEFAULT_DATASET = "xdr_data"
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
_UNITS = {"s": "s", "m": "m", "h": "h", "d": "d", "w": "w"}
W_NULL_GROUP = ("SPL: stats drops events whose by-field is missing; XQL comp behaviour for "
                "null groups is not documented; verify")
W_FIELDS = ("SPL: table keeps only the listed fields; XQL fields always keeps system fields "
            "such as _time")
W_DEDUP_NULL = ("SPL: dedup drops events missing a dedup field (keepempty=false); XQL dedup "
                "null handling is not documented; verify")
W_DEDUP_ANY = ("SPL: dedup keeps the first event in search order; XQL dedup without `by` "
               "keeps an arbitrary record; verify")
W_COLUMNS = ("SPL: column names are the XQL dataset's ({table}); map them to your Splunk "
             "field names (no exact reverse mapping for: {cols})")


def operator_of(stage: str) -> tuple[str, str]:
    m = re.match(r"\s*([A-Za-z_]+)\s*(.*)$", stage, re.S)
    if not m:
        raise Unsupported("empty stage")
    return m.group(1).lower(), m.group(2).strip()


# ---- head: config + dataset -------------------------------------------------------------------------

def read_head(stages: list[str]) -> tuple[dict, str, list[str]]:
    """-> (settings, dataset, remaining stages). Raises Unsupported for a head we cannot
    map (that is not a rule gap: the LLM could not know the source either)."""
    settings = {"case_sensitive": False, "earliest": None}
    i = 0
    while i < len(stages) and operator_of(stages[i])[0] == "config":
        arg = operator_of(stages[i])[1]
        m = re.fullmatch(r"timeframe\s*=\s*(\d+)\s*([A-Za-z]+)", arg, re.I)
        c = re.fullmatch(r"case_sensitive\s*=\s*(true|false)", arg, re.I)
        if m and m.group(2).lower() in _UNITS:
            settings["earliest"] = f"-{m.group(1)}{_UNITS[m.group(2).lower()]}"
        elif c:
            settings["case_sensitive"] = c.group(1).lower() == "true"
        else:
            raise Unsupported(f"config {arg}")
        i += 1
    dataset = DEFAULT_DATASET
    if i < len(stages) and operator_of(stages[i])[0] in ("dataset", "cold_dataset", "preset",
                                                          "datamodel"):
        op, arg = operator_of(stages[i])
        m = re.fullmatch(r"=?\s*([A-Za-z0-9_]+)", arg)
        if op != "dataset" or not m:
            raise Unsupported(f"{op} {arg}".strip())
        dataset = m.group(1).lower()
        i += 1
    return settings, dataset, stages[i:]


# ---- stages ----------------------------------------------------------------------------------------

def _names(text: str, ctx: dict) -> list[str]:
    cols = [c.strip() for c in split_top(text)]
    if not cols or not all(_NAME.fullmatch(c) for c in cols):
        raise Unsupported("expressions, wildcards or special names in a field list")
    cols = [ctx["rename"].get(c, c) for c in cols]
    ctx["columns"] += cols
    return cols


def _filter(arg: str, ctx: dict) -> str:
    if not has_top_level_or(arg):
        for c in split_and(arg):
            m = re.fullmatch(r"\s*([\w.]+)\s*!=\s*null\s*", c)
            if m:
                ctx["notnull"].add(m.group(1))
    r = xql_expr.condition(arg, ctx["rename"], ctx["cs"])
    ctx["warnings"] += r.warnings
    ctx["columns"] += r.columns
    return f"where {r.text}"


def _fields(arg: str, ctx: dict) -> str:
    if arg.startswith("-"):
        return "fields - " + ", ".join(_names(arg[1:], ctx))
    renames, out = [], []
    for part in split_top(arg):
        m = re.fullmatch(r"(\S+)\s+as\s+([A-Za-z_][A-Za-z0-9_]*)", part.strip(), re.I)
        if m:
            src = _names(m.group(1), ctx)[0]
            renames.append(f"{src} AS {m.group(2)}")
            ctx["created"].add(m.group(2))
            out.append(m.group(2))
        else:
            out += _names(part, ctx)
    ctx["warnings"].append(W_FIELDS)
    table = "table " + ", ".join(out)
    return f"rename {', '.join(renames)} | {table}" if renames else table


_AGG = re.compile(r"(count|count_distinct|sum|avg|min|max)\(\s*([\w.]+)?\s*\)\s+as\s+"
                  r"([A-Za-z_][A-Za-z0-9_]*)$", re.I)


def _comp(arg: str, ctx: dict) -> str:
    if re.search(r"\baddrawdata\b", arg, re.I):
        raise Unsupported("comp addrawdata")
    m = re.match(r"(.*?)(?:\bby\b(.*))?$", arg, re.S)
    aggs_txt, by_txt = m.group(1).strip(), (m.group(2) or "").strip()
    if not aggs_txt:
        raise Unsupported("comp without aggregation")
    by = _names(by_txt, ctx) if by_txt else []
    terms = []
    for part in split_top(aggs_txt):
        a = _AGG.fullmatch(part.strip())
        if not a:
            raise Unsupported(f"aggregation {part.strip()} (supported: count, count_distinct, "
                              "sum, avg, min, max, each with `as <name>`)")
        fn, col, name = a.group(1).lower(), a.group(2), a.group(3)
        if fn != "count" and not col:
            raise Unsupported(f"{fn}() without a field")
        if col:
            col = ctx["rename"].get(col, col)
            ctx["columns"].append(col)
        spl_fn = "dc" if fn == "count_distinct" else fn
        terms.append(f"{spl_fn}({col}) AS {name}" if col else f"count AS {name}")
        ctx["created"].add(name)
    if any(g not in ctx["notnull"] for g in by):
        ctx["warnings"].append(W_NULL_GROUP)
    ctx["notnull"] = set(by)
    return "stats " + ", ".join(terms) + (" by " + ", ".join(by) if by else "")


def _sort_keys(text: str, ctx: dict) -> str:
    keys = []
    for part in split_top(text):
        m = re.fullmatch(r"(asc|desc)\s+([\w.]+)", part.strip(), re.I)
        if not m:
            raise Unsupported("sort key without asc/desc (the XQL default order is not "
                              "documented)")
        col = ctx["rename"].get(m.group(2), m.group(2))
        ctx["columns"].append(col)
        keys.append(("-" if m.group(1).lower() == "desc" else "+") + col)
    return ", ".join(keys)


def _dedup(arg: str, ctx: dict) -> str:
    m = re.fullmatch(r"(.+?)(?:\s+by\s+(.+))?", arg, re.S | re.I)
    cols = _names(m.group(1), ctx)
    ctx["warnings"].append(W_DEDUP_NULL)
    if m.group(2):
        return f"sort 0 {_sort_keys(m.group(2), ctx)} | dedup {' '.join(cols)}"
    ctx["warnings"].append(W_DEDUP_ANY)
    return "dedup " + " ".join(cols)


def stage_to_spl(stage: str, ctx: dict) -> str:
    op, arg = operator_of(stage)
    if op == "filter":
        return _filter(arg, ctx)
    if op == "alter":
        out = []
        for name, e in _assignments(arg, ctx, "alter"):
            r = xql_expr.value(e, ctx["rename"], ctx["cs"])
            ctx["warnings"] += r.warnings
            ctx["columns"] += r.columns
            out.append(f"{name} = {r.text}")
            ctx["created"].add(name)
            ctx["notnull"].discard(name)
        return "eval " + ", ".join(out)
    if op == "fields":
        return _fields(arg, ctx)
    if op == "comp":
        return _comp(arg, ctx)
    if op == "sort":
        return "sort 0 " + _sort_keys(arg, ctx)
    if op == "limit" and arg.isdigit():
        return f"head {arg}"
    if op == "dedup":
        return _dedup(arg, ctx)
    raise Unsupported(f"XQL stage '{op}'")


# ---- whole query ------------------------------------------------------------------------------------

def convert(xql: str) -> dict:
    problems = validate.check(strip_comments(xql), "xql")     # // comments: dataset.md example
    if problems and problems != ["empty output"]:
        return _unsupported(f"input is not valid XQL: {problems[0]}")         # no LLM
    stages = split_pipes(xql)
    if not stages:
        return _unsupported("empty query")
    try:
        settings, dataset, rest = read_head(stages)
        base, warnings = base_search_for(dataset, "xql")
    except Unsupported as e:
        return _unsupported(str(e))           # no LLM: it cannot know your Splunk source
    ctx = {"cs": settings["case_sensitive"], "warnings": warnings, "columns": [],
           "created": set(), "notnull": set(), "rename": reverse_field_names(dataset, "xql")}
    try:
        out = [stage_to_spl(st, ctx) for st in rest]
    except (Unsupported, ExprUnsupported) as e:
        return _unsupported(str(e), llm_base=_with_time(base, settings), llm_table=dataset)
    base = _with_time(base, settings)
    mapped = set(ctx["rename"].values())
    unmapped = sorted({c for c in ctx["columns"] if c not in mapped and c not in ctx["created"]})
    if unmapped:
        ctx["warnings"].append(W_COLUMNS.format(table=dataset, cols=", ".join(unmapped)))
    return {"query": " | ".join([base] + out), "confidence": 0.9, "method": "rules",
            "warnings": list(dict.fromkeys(ctx["warnings"])), "tokens": 0}


def _with_time(base: str, settings: dict) -> str:
    return f"{base} earliest={settings['earliest']}" if settings["earliest"] else base
