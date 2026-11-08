"""Roadmap 7 (part 1): KQL -> SPL, rules only.

    T | where ... | summarize ... by ...   ->   index=... where ... | stats ... by ...

Input KQL is first checked with Microsoft's parser (validate.py) when available.
Table -> SPL base search: mappings/sources.json read backwards (+ client overrides).
Column names stay as they are, except a client's EXACT field mappings, reversed.

Operators (anything else -> None, the result is unsupported, never guessed):
  where / filter        where <expr>; top-level `TimeGenerated > ago(N<unit>)` -> earliest=-N<unit>
  project a, b          table a, b                  (expressions in project -> None)
  project-away a, b     fields - a, b
  project-rename n = o  rename o AS n
  extend n = expr       eval n = expr
  summarize ... by ...  stats ... by ...            count() count_distinct() dcount() sum avg min max
  count                 stats count AS Count
  take / limit N        head N
  sort / order by       sort 0 ...                  KQL sorts DESCENDING by default; sort 0 = no
                                                    10,000-row limit (SPL sort default)
  top N by x            sort 0 -x | head N
  distinct a, b         stats count by a, b | fields - count
Output column names follow KQL so later stages keep working: count() -> count_,
sum(x) -> sum_x, dcount(x) -> dcount_x, avg(x) -> avg_x (summarize operator docs).
Caveats (warnings): summarize/distinct keep empty group values in KQL while SPL stats
drops events missing a by-field; dcount() is an estimate while SPL dc() is exact.
"""
from __future__ import annotations

import re

from . import config, fieldmap, kql_expr, mappings, search, validate

T_SPL = "SPL"
W_NULL_GROUP = ("SPL: stats drops events whose by-field is missing; KQL summarize/distinct "
                "keeps them as an empty group; verify")
W_DCOUNT = "SPL: dc() is exact; KQL dcount() is an estimate, so counts can differ slightly"
W_COLUMNS = ("SPL: column names are the KQL table's ({table}); map them to your Splunk field "
             "names (no exact reverse mapping for: {cols})")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_UNITS = {"d": "d", "h": "h", "m": "m", "s": "s"}


class Unsupported(ValueError):
    pass


# ---- splitting ------------------------------------------------------------------------------------

def strip_comments(kql: str) -> str:
    out = []
    for line in kql.splitlines():
        code, quote, i = [], None, 0
        while i < len(line):
            ch = line[i]
            if quote:
                if ch == "\\" and quote != "@":
                    code.append(line[i:i + 2])
                    i += 2
                    continue
                if ch == quote:
                    quote = None
            elif ch in "\"'":
                quote = ch
            elif line.startswith("//", i):
                break
            code.append(ch)
            i += 1
        out.append("".join(code))
    return "\n".join(out)


def split_pipes(kql: str) -> list[str]:
    """Split on | outside strings and brackets."""
    parts, buf, depth, quote, i = [], [], 0, None, 0
    s = strip_comments(kql)
    while i < len(s):
        ch = s[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and not verbatim:
                buf.append(s[i + 1:i + 2])
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "\"'":
            verbatim = i > 0 and s[i - 1] == "@"
            quote = ch
            buf.append(ch)
        elif ch in "([{":
            depth += 1
            buf.append(ch)
        elif ch in ")]}":
            depth -= 1
            buf.append(ch)
        elif ch == "|" and depth == 0:
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf).strip())
    return [p for p in parts if p]


def split_top(text: str, sep: str = ",") -> list[str]:
    parts, buf, depth, quote = [], [], 0, None
    for ch in text:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append("".join(buf).strip())
            buf = []
            continue
        buf.append(ch)
    parts.append("".join(buf).strip())
    return [p for p in parts if p]


def operator_of(stage: str) -> tuple[str, str]:
    m = re.match(r"\s*(project-away|project-rename|project-keep|project-reorder|mv-expand|"
                 r"order\s+by|sort\s+by|[A-Za-z_][A-Za-z0-9_-]*)\s*(.*)$", stage, re.S)
    if not m:
        raise Unsupported("empty stage")
    return re.sub(r"\s+", " ", m.group(1).lower()), m.group(2).strip()


# ---- table -> base search ------------------------------------------------------------------------

def base_search_for(table: str) -> tuple[str, list[str]]:
    from .rules import _load_sources
    keys = [k for k, v in _load_sources().items()
            if isinstance(v, dict) and str(v.get("kql", "")).strip() == table]
    if not keys:
        raise Unsupported(f"no SPL source in mappings/sources.json maps to {table}")
    keys.sort(key=lambda k: (-len(search.parse_meta(k) or {}), k))   # most specific first
    warnings = []
    if len(keys) > 1:
        warnings.append(f"SPL: several Splunk sources map to {table} ({'; '.join(keys)}); "
                        f"used '{keys[0]}'; verify")
    return keys[0], warnings


def reverse_field_names(table: str) -> dict[str, str]:
    """Column -> Splunk field from EXACT entries only (e.g. a client's props.conf)."""
    out = {}
    for spl_name, e in fieldmap.table_map("kql", table).items():
        if e.get("level") == "exact" and e.get("to"):
            out.setdefault(e["to"], spl_name)
    return out


# ---- operators -----------------------------------------------------------------------------------

_AGO = re.compile(r"^\s*TimeGenerated\s*(>=|>)\s*ago\(\s*(\d+)([dhms])\s*\)\s*$")


def _where(arg, ctx):
    """Top-level `TimeGenerated > ago(Nu)` conjuncts become earliest=; the rest -> where.
    Splitting on `and` is only safe without a top-level `or`: `x or y and z` means
    `x or (y and z)`, so it is translated as one expression."""
    conjuncts = [arg] if has_top_level_or(arg) else split_and(arg)
    rest = []
    for c in conjuncts:
        m = _AGO.match(c)
        if m and ctx["first"]:
            ctx["earliest"] = f"-{m.group(2)}{_UNITS[m.group(3)]}"
        elif "ago(" in c or "now(" in c or "datetime(" in c:
            raise Unsupported("time expressions other than a leading TimeGenerated > ago()")
        else:
            rest.append(c)
    if not rest:
        return None
    text = rest[0] if len(rest) == 1 else " and ".join(f"({c})" for c in rest)
    r = kql_expr.condition(text, ctx["rename"])
    ctx["warnings"] += r.warnings
    ctx["columns"] += r.columns
    return f"where {r.text}"


def has_top_level_or(expr: str) -> bool:
    depth, quote = 0, None
    for i, ch in enumerate(expr):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif depth == 0 and re.match(r"or\b", expr[i:], re.I) and (i == 0 or not expr[i - 1].isalnum()):
            return True
    return False


def split_and(expr: str) -> list[str]:
    """Top-level `and` conjuncts (outside brackets/strings)."""
    parts, buf, depth, quote, i = [], [], 0, None, 0
    while i < len(expr):
        ch = expr[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            buf.append(ch)
        elif ch in "([":
            depth += 1
            buf.append(ch)
        elif ch in ")]":
            depth -= 1
            buf.append(ch)
        elif depth == 0 and re.match(r"\band\b", expr[i:], re.I) and (i == 0 or not expr[i - 1].isalnum()):
            parts.append("".join(buf).strip())
            buf, i = [], i + 3
            continue
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf).strip())
    return [p for p in parts if p]


def _names(arg, ctx) -> list[str]:
    cols = [c.strip() for c in split_top(arg)]
    if not all(_IDENT.fullmatch(c) for c in cols):
        raise Unsupported("expressions or special names in a column list")
    cols = [ctx["rename"].get(c, c) for c in cols]
    ctx["columns"] += cols
    return cols


def _assignments(arg, ctx, what):
    out = []
    for part in split_top(arg):
        m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)", part, re.S)
        if not m:
            raise Unsupported(f"{what} without a name")
        out.append((m.group(1), m.group(2).strip()))
    return out


_AGG = re.compile(r"(count|count_distinct|dcount|sum|avg|min|max)\(\s*([A-Za-z_][A-Za-z0-9_]*)?\s*\)$")


def _summarize(arg, ctx):
    m = re.match(r"(.*?)(?:\bby\b(.*))?$", arg, re.S)
    aggs_txt, by_txt = m.group(1).strip(), (m.group(2) or "").strip()
    if not aggs_txt:
        raise Unsupported("summarize without aggregation")
    by = _names(by_txt, ctx) if by_txt else []
    terms = []
    for part in split_top(aggs_txt):
        nm = re.fullmatch(r"(?:([A-Za-z_][A-Za-z0-9_]*)\s*=\s*)?(.+)", part, re.S)
        name, call = nm.group(1), nm.group(2).strip()
        a = _AGG.fullmatch(call)
        if not a:
            raise Unsupported(f"aggregation {call}")
        fn, col = a.group(1), a.group(2)
        if (fn == "count") != (col is None):
            raise Unsupported("count(x) / other aggregations without a column")
        if col:
            col = ctx["rename"].get(col, col)
            ctx["columns"].append(col)
        default = "count_" if fn == "count" else f"{fn}_{col}"
        spl_fn = {"count": "count", "count_distinct": "dc", "dcount": "dc"}.get(fn, fn)
        if fn == "dcount":
            ctx["warnings"].append(W_DCOUNT)
        terms.append(f"{spl_fn}({col})" if col else spl_fn)
        terms[-1] += f" AS {name or default}"
        ctx["created"].add(name or default)
    if by:
        ctx["warnings"].append(W_NULL_GROUP)
    return "stats " + ", ".join(terms) + (" by " + ", ".join(by) if by else "")


def _sort(arg, ctx):
    keys = []
    for part in split_top(arg):
        m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)(?:\s+(asc|desc))?", part.strip(), re.I)
        if not m:
            raise Unsupported("sort key (nulls first/last, expressions)")
        col = ctx["rename"].get(m.group(1), m.group(1))
        ctx["columns"].append(col)
        desc = (m.group(2) or "desc").lower() == "desc"         # KQL default: descending
        keys.append(("-" if desc else "+") + col)
    return "sort 0 " + ", ".join(keys)


def stage_to_spl(stage: str, ctx: dict) -> str | None:
    op, arg = operator_of(stage)
    if op in ("where", "filter"):
        return _where(arg, ctx)
    if op == "project":
        return "table " + ", ".join(_names(arg, ctx))
    if op == "project-away":
        return "fields - " + ", ".join(_names(arg, ctx))
    if op == "project-rename":
        pairs = _assignments(arg, ctx, "project-rename")
        if not all(_IDENT.fullmatch(o) for _, o in pairs):
            raise Unsupported("project-rename source")
        ctx["created"].update(n for n, _ in pairs)
        return "rename " + ", ".join(f"{ctx['rename'].get(o, o)} AS {n}" for n, o in pairs)
    if op == "extend":
        out = []
        for name, e in _assignments(arg, ctx, "extend"):
            r = kql_expr.value(e, ctx["rename"])
            ctx["warnings"] += r.warnings
            ctx["columns"] += r.columns
            out.append(f"{name} = {r.text}")
            ctx["created"].add(name)
        return "eval " + ", ".join(out)
    if op == "summarize":
        return _summarize(arg, ctx)
    if op == "count" and not arg:
        ctx["created"].add("Count")
        return "stats count AS Count"
    if op in ("take", "limit") and arg.isdigit():
        return f"head {arg}"
    if op in ("sort by", "order by"):
        return _sort(arg, ctx)
    if op == "top":
        m = re.fullmatch(r"(\d+)\s+by\s+(.+)", arg, re.S)
        if not m:
            raise Unsupported("top")
        return f"{_sort(m.group(2), ctx)} | head {m.group(1)}"
    if op == "distinct":
        cols = _names(arg, ctx)
        ctx["warnings"].append(W_NULL_GROUP)
        return f"stats count by {', '.join(cols)} | fields - count"
    raise Unsupported(f"KQL operator '{op}'")


# ---- whole query ----------------------------------------------------------------------------------

def convert(kql: str) -> dict:
    """KQL -> {"query", "confidence", "method", "warnings", ...}; unsupported when a
    stage has no rule (no LLM fallback for this direction yet)."""
    problems = validate.check(kql, "kql") if validate.KqlValidator.available() else []
    syntax = [p for p in problems if "syntax" in p or p.startswith("unbalanced")]
    if syntax:
        return _unsupported(f"input is not valid KQL: {syntax[0]}")       # no LLM: fix input
    stages = split_pipes(kql)
    table = stages[0].strip() if stages else ""
    if not _IDENT.fullmatch(table):
        return _unsupported("the query must start with a table name")    # no LLM
    try:
        base, warnings = base_search_for(table)
    except Unsupported as e:
        return _unsupported(str(e))      # no LLM: it cannot know your Splunk index either
    try:
        ctx = {"first": True, "earliest": None, "warnings": warnings, "columns": [],
               "created": set(), "rename": reverse_field_names(table)}
        out = []
        for st in stages[1:]:
            spl = stage_to_spl(st, ctx)
            ctx["first"] = False
            if spl:
                out.append(spl)
    except (Unsupported, kql_expr.Unsupported) as e:
        # a rule gap (operator / expression): the LLM may translate it with this base search
        return _unsupported(str(e), llm_base=base)
    if ctx["earliest"]:
        base = f"{base} earliest={ctx['earliest']}"
    mapped = set(ctx["rename"].values())
    unmapped = sorted({c for c in ctx["columns"] if c not in mapped and c not in ctx["created"]})
    if unmapped:
        ctx["warnings"].append(W_COLUMNS.format(table=table, cols=", ".join(unmapped)))
    query = " | ".join([base] + out)
    return {"query": query, "confidence": 0.9, "method": "rules",
            "warnings": list(dict.fromkeys(ctx["warnings"])), "tokens": 0}


def _unsupported(reason: str, llm_base: str | None = None) -> dict:
    """llm_base set = a rule gap the LLM fallback may handle, using this SPL base search."""
    return {"query": "", "confidence": 0.0, "method": "rules", "unsupported": True,
            "warnings": [f"not converted: {reason}"], "tokens": 0, "llm_base": llm_base}
