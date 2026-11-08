"""Deterministic 1:1 stage rules. Return None when unsure -> falls to LLM.
STARTER RULES: verify each against the official docs before trusting.

Doc references:
  KQL summarize:    https://learn.microsoft.com/en-us/kusto/query/summarize-operator
  KQL count():      https://learn.microsoft.com/en-us/kusto/query/count-aggregation-function
  KQL names/quotes: https://learn.microsoft.com/en-us/kusto/query/schema-entities/entity-names
  KQL project:      https://learn.microsoft.com/en-us/kusto/query/project-operator
  KQL take:         https://learn.microsoft.com/en-us/kusto/query/take-operator
  KQL sort:         https://learn.microsoft.com/en-us/kusto/query/sort-operator
  XQL comp:         https://cortex-docs.paloaltonetworks.com/xql-command-reference-guide/readme/stages/comp.md
  XQL count():      https://cortex-docs.paloaltonetworks.com/xql-command-reference-guide/readme/functions/count_with_comp_stage.md
  XQL sort:         https://cortex-docs.paloaltonetworks.com/xql-command-reference-guide/readme/stages/sort.md
  SPL/KQL/XQL where/filter: see expr.py
  SPL rename:       https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/9.4/search-commands/rename
  KQL project-rename: https://learn.microsoft.com/en-us/kusto/query/project-rename-operator
  XQL alter:        https://cortex-docs.paloaltonetworks.com/xql-command-reference-guide/readme/stages/alter.md
  XQL fields:       https://cortex-docs.paloaltonetworks.com/xql-command-reference-guide/readme/stages/fields.md
  SPL dedup:        https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/9.4/search-commands/dedup
  KQL arg_max():    https://learn.microsoft.com/en-us/kusto/query/arg-max-aggregation-function
  KQL isnotempty(): https://learn.microsoft.com/en-us/kusto/query/isnotempty-function
  XQL dedup:        https://cortex-docs.paloaltonetworks.com/xql-command-reference-guide/readme/stages/dedup.md
  KQL take order:   https://learn.microsoft.com/en-us/kusto/query/take-operator
  SPL/KQL/XQL eval: see expr.py and _eval() below
  SPL top:          https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/9.4/search-commands/top
  KQL top:          https://learn.microsoft.com/en-us/kusto/query/top-operator
  XQL top:          https://cortex-docs.paloaltonetworks.com/xql-command-reference-guide/readme/stages/top.md
  SPL rex:          https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/9.4/search-commands/rex
  KQL extract():    https://learn.microsoft.com/en-us/kusto/query/extract-function
  KQL regex:        https://learn.microsoft.com/en-us/kusto/query/regex
  KQL strings:      https://learn.microsoft.com/en-us/kusto/query/scalar-data-types/string
  XQL regextract(): https://cortex-docs.paloaltonetworks.com/xql-command-reference-guide/readme/functions/regextract.md
  SPL timechart:    https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/9.4/search-commands/timechart
  KQL bin():        https://learn.microsoft.com/en-us/kusto/query/bin-function
  XQL bin:          https://cortex-docs.paloaltonetworks.com/xql-command-reference-guide/readme/stages/bin.md
  SPL lookup:       https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/9.4/search-commands/lookup
  KQL lookup:       https://learn.microsoft.com/en-us/kusto/query/lookup-operator
  Sentinel watchlists: https://learn.microsoft.com/en-us/azure/sentinel/watchlists-queries
  XQL join:         https://cortex-docs.paloaltonetworks.com/xql-command-reference-guide/readme/stages/join.md
  SPL join:         https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/9.4/search-commands/join
  KQL join:         https://learn.microsoft.com/en-us/kusto/query/join-operator
  XQL limit order:  https://cortex-docs.paloaltonetworks.com/xql-command-reference-guide/readme/stages/limit.md
"""
import json
import re

from . import expr
from .config import MAP_FILE
from .triage import command_of


class Out(str):
    """Rule output. Behaves as the query text (a str) and also records, for the
    pipeline's field check (schema.py), which input fields the stage reads and
    how it changes the set of available fields:
      reads   - field names the stage references
      only    - the stage outputs only these fields (table, stats)
      add / drop - fields created / removed (rename)
    and, for the order check, how it affects row order:
      order   - "sorts" (sort), "loses" (stats, dedup: target output order is
                not guaranteed), "takes_first" (head: picks the first N rows),
                "keeps_first" (dedup: SPL keeps the first row in current order)
    and, for join (max=1 needs at most one subsearch row per key):
      unique  - after this stage there is at most one row per combination of
                these fields (stats by, dedup, top, timechart); [] = one row
      multiplies - the stage can produce several rows per input row (lookup, join)
    """
    warnings: list[str] = []

    def __new__(cls, text: str, *, reads=(), only=None, add=(), drop=(), order=(),
                unique=None, multiplies=False):
        obj = super().__new__(cls, text)
        obj.reads = list(reads)
        obj.only = None if only is None else list(only)
        obj.add, obj.drop = list(add), list(drop)
        obj.order = set([order] if isinstance(order, str) else order)
        obj.unique = None if unique is None else list(unique)
        obj.multiplies = multiplies
        return obj


class Flagged(Out):
    """Rule output that is usable but must be reviewed by a human.
    The pipeline reads .warnings and marks needs-review."""

    def __new__(cls, text: str, warnings: list[str], **effects):
        obj = super().__new__(cls, text, **effects)
        obj.warnings = list(warnings)
        return obj

# KQL identifiers that are language keywords "must be enclosed using [' and ']"
# (entity-names page). The docs give no complete list, so this set is
# conservative: operator names and common keywords. Over-quoting is valid KQL.
KQL_KEYWORDS = {
    "and", "as", "asc", "between", "by", "contains", "count", "desc", "distinct",
    "evaluate", "extend", "false", "find", "from", "has", "in", "invoke", "join", "kind",
    "let", "limit", "lookup", "not", "null", "of", "on", "or", "order", "parse",
    "print", "project", "range", "render", "sample", "search", "serialize", "sort",
    "step", "summarize", "take", "to", "top", "true", "typeof", "union", "where", "with",
}
_PLAIN_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def kql_name(name: str) -> str:
    """Quote a KQL column name when it is a keyword or has special characters."""
    if _PLAIN_IDENT.fullmatch(name) and name.lower() not in KQL_KEYWORDS:
        return name
    return "['" + name.replace("'", "\\'") + "']"


def _fields(arg: str) -> list[str]:
    return [f for f in re.split(r"[,\s]+", arg.strip()) if f]


def _names(fields: list[str], target: str) -> str:
    return ", ".join(kql_name(f) if target == "kql" else f for f in fields)


def _load_sources() -> dict:
    return json.loads(MAP_FILE.read_text()) if MAP_FILE.exists() else {}


def first_stage(stage: str, target: str):
    """Base search -> table/dataset (mappings/sources.json) + filter (search.py).

    The index/sourcetype/source terms must match a sources.json key exactly
    (an unmatched sourcetype could not be dropped safely); other terms become
    a where / filter. Free text, time modifiers etc. -> None."""
    from . import schema, search
    try:
        meta, ast = search.parse(stage)
    except search._Unsupported:
        return None
    if not meta:
        return None
    table_text = None
    for key, tgt in _load_sources().items():
        if search.parse_meta(key) == meta and target in tgt:
            table_text = tgt[target]
            break
    if table_text is None:
        return None
    table = schema.table_of(table_text, target)
    if ast is None:
        out = Out(table_text)
    else:
        r = search.render(ast, target, lambda f: schema.field_type(table, target, f))
        if r is None:
            return None
        op = "where" if target == "kql" else "filter"
        text = f"{table_text}\n| {op} {r.text}"
        out = Flagged(text, r.warnings, reads=r.reads) if r.warnings else Out(text, reads=r.reads)
    out.table = table
    return out


def stage(stage_text: str, target: str):
    cmd = command_of(stage_text)
    arg = stage_text.strip()[len(cmd):].strip()

    if cmd == "fields" and arg.startswith("+"):
        arg = arg[1:].strip()              # `fields + a` == `fields a`
    if cmd in ("table", "fields") and "-" not in arg:
        fl = _fields(arg)
        if not fl or not all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", f) for f in fl):
            return None                    # wildcards, quoted names
        f = _names(fl, target)
        return Out(f"project {f}" if target == "kql" else f"fields {f}", reads=fl, only=fl)

    # SPL where -> KQL where / XQL filter (simple comparisons only; see expr.py)
    if cmd == "where" and arg:
        r = expr.translate(arg, target)
        if r is None:
            return None
        text = f"where {r.text}" if target == "kql" else f"filter {r.text}"
        reads = expr.fields_in(expr.parse(arg))
        return Flagged(text, r.warnings, reads=reads) if r.warnings else Out(text, reads=reads)

    if cmd == "eval" and arg:
        return _eval(arg, target)

    if cmd == "top":
        return _top(arg, target)

    if cmd == "rex":
        return _rex(arg, target)

    if cmd == "timechart":
        return _timechart(arg, target)

    if cmd == "lookup":
        return _lookup(arg, target)

    if cmd == "join":
        return _join(arg, target)

    if cmd == "dedup":
        return _dedup(arg, target)

    if cmd == "rename":
        return _rename(arg, target)

    if cmd == "head" and arg.isdigit():
        out = Out(f"take {arg}" if target == "kql" else f"limit {arg}", order="takes_first")
        out.take_n = int(arg)
        return out

    if cmd == "stats":
        return _stats(arg, target)

    if cmd == "sort":
        return _sort(arg, target)

    if cmd == "fields" and arg.startswith("-"):
        return _fields_minus(arg[1:], target)

    return None


# ---- stats ----------------------------------------------------------------------
# SPL `stats <agg> [as name], ... [by f1, f2]`. Default output names are the call
# text (dc(user), sum(bytes)); bare `count` -> `count`. dc is exact (estdc is the
# estimate). count(X) counts events that have the field.
#   KQL: summarize name = <agg>, ... by ...  Unnamed count() becomes count_, so
#        every column is named. KQL counts empty strings as values, so field
#        aggregations filter with isnotempty(): countif / count_distinctif /
#        minif / maxif / sumif / avgif. dcount() is an estimate, so dc uses the
#        exact count_distinctif(), which is in preview -> flagged.
#   XQL: comp <agg>(f) as name, ... by ...; count(f) / count_distinct(f) skip
#        nulls; sum ignores NULL. Names with special characters -> None.
# Docs: SPL aggregate-functions; KQL summarize, countif, count-distinctif,
# minif; XQL count_with_comp_stage, count_distinct, sum_with_comp_stage.

KQL_DC_WARNING = ("KQL: dc() -> count_distinctif() (exact) is a preview function; dcount() "
                  "would only be an estimate. Verify it is available in your workspace")
_STATS_FUNCS = {   # spl name -> (kql aggregate, xql aggregate)
    "count": ("countif", "count"), "c": ("countif", "count"),
    "dc": ("count_distinctif", "count_distinct"),
    "distinct_count": ("count_distinctif", "count_distinct"),
    "sum": ("sumif", "sum"), "avg": ("avgif", "avg"),
    "min": ("minif", "min"), "max": ("maxif", "max"),
}
_STATS_AGG = re.compile(
    r"\s*(?:(?P<bare>count|c)\b(?!\()|(?P<fn>[a-z_]+)\((?P<field>[A-Za-z_][A-Za-z0-9_.]*)\))"
    r"(?:\s+[Aa][Ss]\s+(?P<alias>[A-Za-z_][A-Za-z0-9_]*))?\s*,?")


def _stats(arg: str, target: str):
    m = re.fullmatch(r"(.*?)(?:\s+[Bb][Yy]\s+(.+))?", arg.strip(), re.S)
    aggs_txt, by_txt = m.group(1), m.group(2)
    by_fields = _fields(by_txt) if by_txt else []
    if not all(_PLAIN_IDENT.fullmatch(f) for f in by_fields) or len(set(by_fields)) != len(by_fields):
        return None
    aggs, pos = [], 0                      # (name, kind, field)
    while pos < len(aggs_txt):
        a = _STATS_AGG.match(aggs_txt, pos)
        if not a or a.end() == pos:
            return None
        pos = a.end()
        if a.group("bare"):
            aggs.append((a.group("alias") or "count", "count", None))
            continue
        fn, f = a.group("fn"), a.group("field")
        if fn not in _STATS_FUNCS:
            return None                    # values, list, estdc, perc, ...
        if fn in ("count", "c") and not a.group("alias"):
            return None                    # default name of count(X) not documented
        aggs.append((a.group("alias") or f"{fn}({f})", fn, f))
    names = [n for n, _, _ in aggs]
    if not aggs or len(set(names + by_fields)) != len(names) + len(by_fields):
        return None
    agg_fields = [f for _, _, f in aggs if f]
    fx = dict(reads=list(dict.fromkeys(by_fields + agg_fields)), only=[*names, *by_fields],
              order="loses", unique=by_fields)
    warnings = []
    parts = []
    for name, fn, f in aggs:
        kql_fn, xql_fn = _STATS_FUNCS[fn]
        if target == "kql":
            if f is None:
                expr_ = "count()"
            else:
                expr_ = f"{kql_fn}({kql_name(f)}, isnotempty({kql_name(f)}))"
                if fn in ("count", "c"):
                    expr_ = f"countif(isnotempty({kql_name(f)}))"
                if kql_fn == "count_distinctif" and KQL_DC_WARNING not in warnings:
                    warnings.append(KQL_DC_WARNING)
            parts.append(f"{kql_name(name)} = {expr_}")
        else:
            if not _XQL_IDENT.fullmatch(name) or (f and not _XQL_IDENT.fullmatch(f)):
                return None
            parts.append(f"{xql_fn}({f or ''}) as {name}")
    by = f" by {_names(by_fields, target)}" if by_fields else ""
    op = "summarize" if target == "kql" else "comp"
    text = f"{op} {', '.join(parts)}{by}"
    return Flagged(text, warnings, **fx) if warnings else Out(text, **fx)


# ---- sort -------------------------------------------------------------------------
# SPL `sort [N] [-|+]f1, [-|+]f2 ...`: each field has its own sign (none = asc);
# default limit 10,000 results, N=0 = all (search-commands/sort). The limit is
# emitted explicitly; pipeline.py drops it when a smaller head follows.

SORT_DEFAULT_LIMIT = 10000


def _sort(arg: str, target: str):
    toks = [t for t in re.split(r"[\s,]+", arg.strip()) if t]
    limit = SORT_DEFAULT_LIMIT
    if toks and toks[0].isdigit():
        limit = int(toks.pop(0))
    if any(t.lower() == "desc" for t in toks):
        return None                        # trailing `desc` reverses the whole sort
    keys, sign = [], None
    for tok in toks:
        if tok in ("-", "+"):
            if sign is not None:
                return None
            sign = tok
            continue
        m = re.fullmatch(r"([-+]?)([A-Za-z_][A-Za-z0-9_]*)", tok)
        if not m or (sign and m.group(1)):
            return None                    # desc keyword, num()/str()/ip(), wildcards
        keys.append((m.group(2), (sign or m.group(1)) == "-"))
        sign = None
    if not keys or sign is not None or len({k for k, _ in keys}) != len(keys):
        return None
    if target == "kql":
        text = "sort by " + ", ".join(f"{kql_name(k)} {'desc' if d else 'asc'}" for k, d in keys)
        cap = f"take {limit}"
    else:
        text = "sort " + ", ".join(f"{'desc' if d else 'asc'} {k}" for k, d in keys)
        cap = f"limit {limit}"
    full = f"{text}\n| {cap}" if limit else text
    out = Out(full, reads=[k for k, _ in keys], order="sorts")
    out.without_limit, out.limit = (text, limit) if limit else (None, None)
    return out


# ---- fields - -------------------------------------------------------------------------
# SPL `fields - a, b` removes fields.
#   KQL: project-away a, b.
#   XQL: fields - a, b (docs only show it after a fields selection -> flagged).

XQL_FIELDS_MINUS_WARNING = ("XQL: `fields -` is only shown after a `fields` selection in the "
                            "docs; verify it keeps all other fields")


def _fields_minus(arg: str, target: str):
    fl = _fields(arg)
    if not fl or not all(_PLAIN_IDENT.fullmatch(f) for f in fl) or len(set(fl)) != len(fl):
        return None                        # wildcards, quoted names
    fx = dict(reads=fl, drop=fl)
    if target == "kql":
        return Out("project-away " + _names(fl, target), **fx)
    return Flagged("fields - " + ", ".join(fl), [XQL_FIELDS_MINUS_WARNING], **fx)


# ---- rename -------------------------------------------------------------------

_RENAME_NAME = r'(?:"[^"]*"|[^\s,"]+)'
_RENAME_PAIR = re.compile(rf"\s*({_RENAME_NAME})\s+[Aa][Ss]\s+({_RENAME_NAME})\s*(?:,|(?=\s)|$)")
_XQL_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

XQL_RENAME_WARNING = ("XQL has no rename stage; emitted `alter new = old | fields - old`. "
                      "Docs only show `fields -` after a `fields` selection; verify it keeps "
                      "all other fields")


def parse_rename(arg: str) -> list[tuple[str, str]] | None:
    """`a AS b, "c d" AS e` -> [("a", "b"), ("c d", "e")], or None if unsupported."""
    pairs, pos = [], 0
    while pos < len(arg):
        m = _RENAME_PAIR.match(arg, pos)
        if not m or m.end() == pos:
            return None
        pairs.append(tuple(n[1:-1] if n.startswith('"') else n for n in m.groups()))
        pos = m.end()
    if not pairs:
        return None
    olds = [o for o, _ in pairs]
    news = [n for _, n in pairs]
    if any("*" in n or not n for pair in pairs for n in pair):
        return None                      # wildcard renames: not handled
    if len(set(olds)) != len(olds) or len(set(news)) != len(news):
        return None                      # one field -> two names is invalid SPL
    if set(olds) & set(news):
        return None                      # chained/swapped renames: order semantics unclear
    return pairs


def _rename(arg: str, target: str):
    pairs = parse_rename(arg)
    if pairs is None:
        return None
    olds, news = [o for o, _ in pairs], [n for _, n in pairs]
    fx = dict(reads=olds, drop=olds, add=news)
    if target == "kql":
        return Out("project-rename " + ", ".join(f"{kql_name(n)} = {kql_name(o)}"
                                                 for o, n in pairs), **fx)
    if not all(_XQL_IDENT.fullmatch(x) for pair in pairs for x in pair):
        return None                      # XQL quoting of special names not verified
    alter = "alter " + ", ".join(f"{n} = {o}" for o, n in pairs)
    drop = "fields - " + ", ".join(o for o, _ in pairs)
    return Flagged(f"{alter}\n| {drop}", [XQL_RENAME_WARNING], **fx)


# ---- dedup --------------------------------------------------------------------
# SPL `dedup f1 f2` keeps the first event per combination in search order (most
# recent first by default) and drops events where any of the fields is null.
#   KQL: no dedup operator. Filter empty values, then keep the latest row per
#        group with all columns: summarize arg_max(TimeGenerated, *) by f1, f2.
#   XQL: `dedup` keeps an ARBITRARY record unless `by asc|desc <field>` is given,
#        so `by desc _time` is required. Null handling and whether all fields are
#        kept are not documented -> flagged.

XQL_DEDUP_WARNING = ("XQL dedup: null handling and whether all fields are kept are not "
                     "documented; verify")
_DEDUP_FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*")


def _dedup(arg: str, target: str):
    fields = _fields(arg)
    if not fields or not all(_DEDUP_FIELD.fullmatch(f) for f in fields):
        return None          # count form, options (x=y), sortby, quoted names
    if "sortby" in fields or len(set(fields)) != len(fields):
        return None
    if target == "kql":
        notempty = " and ".join(f"isnotempty({kql_name(f)})" for f in fields)
        text = (f"where {notempty}\n"
                f"| summarize arg_max(TimeGenerated, *) by {_names(fields, target)}")
        return Out(text, reads=[*fields, "TimeGenerated"], order={"keeps_first", "loses"},
                   unique=fields)
    if not all(_XQL_IDENT.fullmatch(f) for f in fields):
        return None
    notnull = " and ".join(f"{f} != null" for f in fields)
    text = f"filter {notnull}\n| dedup {', '.join(fields)} by desc _time"
    return Flagged(text, [XQL_DEDUP_WARNING], reads=[*fields, "_time"],
                   order={"keeps_first", "loses"}, unique=fields)


# ---- eval ---------------------------------------------------------------------
# SPL `eval a = <expr>, b = <expr>`: later assignments may use earlier ones and
# existing fields are overwritten (search-commands/eval).
#   KQL: extend (replaces existing columns). The docs do not say a later
#        expression in the same extend can use an earlier one, so a dependent
#        assignment starts a new extend stage.
#   XQL: alter (comma-separated assignments, overwrites existing fields).
# Expressions: see expr.py.

_ASSIGN = re.compile(r"\s*('(?:[^'\\]|\\.)+'|[A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)\s*(.+?)\s*$", re.S)


def split_top_level(arg: str, sep: str = ",") -> list[str] | None:
    """Split on `sep` outside quotes and parentheses; None if unbalanced."""
    parts, buf, depth, quote = [], [], 0, None
    i = 0
    while i < len(arg):
        ch = arg[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and i + 1 < len(arg):
                buf.append(arg[i + 1])
                i += 1
            elif ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            buf.append(ch)
        elif ch == "(":
            depth += 1
            buf.append(ch)
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return None
            buf.append(ch)
        elif ch == sep and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    if quote or depth:
        return None
    parts.append("".join(buf))
    return parts


def parse_eval(arg: str) -> list[tuple[str, str]] | None:
    """`a = x + 1, 'b c' = "y"` -> [("a", "x + 1"), ("b c", '"y"')]."""
    pieces = split_top_level(arg)
    if not pieces:
        return None
    out = []
    for piece in pieces:
        m = _ASSIGN.fullmatch(piece)
        if not m:
            return None
        name = m.group(1)
        if name.startswith("'"):
            name = re.sub(r"\\(.)", r"\1", name[1:-1])
        out.append((name, m.group(2)))
    return out


def _eval(arg: str, target: str):
    assigns = parse_eval(arg)
    if not assigns:
        return None
    stages: list[list[str]] = [[]]
    stage_names: set[str] = set()
    created: set[str] = set()
    reads: list[str] = []
    warnings: list[str] = []
    for name, src in assigns:
        node = expr.parse_value(src)
        r = expr.render_value(node, target) if node is not None else None
        if r is None:
            return None
        if target == "xql" and not _XQL_IDENT.fullmatch(name):
            return None                      # XQL quoting of special names not verified
        used = expr.fields_in(node)
        reads += [f for f in used if f not in created and f not in reads]
        if stage_names & set(used):          # depends on this stage -> new stage
            stages.append([])
            stage_names = set()
        lhs = kql_name(name) if target == "kql" else name
        stages[-1].append(f"{lhs} = {r.text}")
        stage_names.add(name)
        created.add(name)
        warnings += [w for w in r.warnings if w not in warnings]
    op = "extend" if target == "kql" else "alter"
    text = "\n| ".join(f"{op} {', '.join(s)}" for s in stages)
    fx = dict(reads=reads, add=[n for n, _ in assigns])
    return Flagged(text, warnings, **fx) if warnings else Out(text, **fx)


# ---- top ------------------------------------------------------------------------
# SPL `top [N] [limit=N] field [countfield=x] [showperc=f]`: the N most common
# values of field with a count column (default `count`) and a percent column
# (default `percent`); default limit 10, limit=0 returns all values.
#   KQL: summarize count by field | top N by count desc (top output is sorted).
#   XQL: comp / sort / limit (exact). XQL's own `top` stage reports an
#        "approximate count", so it is not used.
# The SPL docs do not define the percent denominator, so percent is not
# produced: if SPL would output it (showperc defaults to true), the result is
# flagged. `by`, several fields, useother and showcount=f -> None.

TOP_PERCENT_WARNING = ("{T}: SPL top also outputs a percent column; its denominator is not "
                       "documented, so it is not produced. Add it if the detection uses it")
_TOP_OPTION = re.compile(r"(limit|countfield|showperc)=(\S+)")
_FALSE = {"f", "false", "0"}
_TRUE = {"t", "true", "1"}


def _top(arg: str, target: str):
    tokens = arg.split()
    limit, countfield, showperc, fields = 10, "count", True, []
    for i, tok in enumerate(tokens):
        if "=" in tok:
            m = _TOP_OPTION.fullmatch(tok)
            if not m:
                return None                  # useother, showcount, percentfield, ...
            key, val = m.groups()
            if key == "limit":
                if not val.isdigit():
                    return None
                limit = int(val)
            elif key == "countfield":
                countfield = val
            elif val.lower() in _FALSE:
                showperc = False
            elif val.lower() not in _TRUE:
                return None
        elif tok.isdigit() and i == 0:
            limit = int(tok)
        elif tok.lower() == "by":
            return None                      # per-group top: not handled yet
        else:
            fields.append(tok)
    if len(fields) != 1 or not _PLAIN_IDENT.fullmatch(countfield):
        return None                          # multi-field top has odd semantics
    f = fields[0]
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", f) or f == countfield:
        return None
    if target == "kql":
        c = kql_name(countfield)
        tail = f"top {limit} by {c} desc" if limit else f"sort by {c} desc"
        text = f"summarize {c} = count() by {kql_name(f)}\n| {tail}"
    else:
        if not _XQL_IDENT.fullmatch(f):
            return None
        text = f"comp count() as {countfield} by {f}\n| sort desc {countfield}"
        if limit:
            text += f"\n| limit {limit}"
    fx = dict(reads=[f], only=[f, countfield], order="sorts", unique=[f])
    if showperc:
        return Flagged(text, [TOP_PERCENT_WARNING.format(T=target.upper())], **fx)
    return Out(text, **fx)


# ---- rex ------------------------------------------------------------------------
# SPL `rex field=<f> "<PCRE with (?<name>...)>"` extracts named groups into fields
# (default field _raw, max_match 1). No-match behaviour is not documented.
#   KQL: extend name = extract(@"<regex>", <group index>, f); null on no match.
#        KQL regex has (?<name>) groups but no lookaround / backreferences.
#        Verbatim @"..." keeps backslashes; a " is written "".
#        Note: KQL \d \w are Unicode-aware (PCRE default is ASCII); only matters
#        for non-ASCII text, not flagged.
#   XQL: alter name = regextract(f, "<regex>"): returns the FIRST capture group,
#        NULL on no match. Each named group gets its own regextract with the
#        other groups made non-capturing. Regex dialect is not stated on that
#        page (RE2 per the regexcapture page) -> flagged. regexcapture() itself
#        only works in parsing rules, so it is not used.
# _raw (no equivalent in Sentinel tables), sed mode, max_match != 1,
# offset_field and PCRE-only syntax -> None.

XQL_REX_WARNING = ("XQL: regextract regex dialect is not stated in its docs (RE2 assumed); "
                   "verify the pattern")
_REX_UNSUPPORTED = re.compile(
    r"\(\?[=!>|R(]|\(\?<[=!]|\(\?\d|\\[1-9gkKGZhHRXC]|[*+?}][+]|\\Q|\\E")
_REX_OPTION = re.compile(r'\s*(field|max_match)=("[^"]*"|\S+)')


def _rex_groups(pattern: str) -> list[tuple[int, int, str | None]] | None:
    """Capturing groups as (start, end_of_opening, name) in order; None if unparsable."""
    groups, i, in_class = [], 0, False
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":
            i += 2
            continue
        if in_class:
            if ch == "]":
                in_class = False
        elif ch == "[":
            in_class = True
            if pattern[i + 1:i + 2] == "]":       # literal ] first in a class
                i += 1
        elif ch == "(":
            m = re.match(r"\(\?P?<([A-Za-z_][A-Za-z0-9_]*)>", pattern[i:])
            if m:
                groups.append((i, i + m.end(), m.group(1)))
            elif pattern[i + 1:i + 2] == "?":
                pass                              # non-capturing / flags
            else:
                groups.append((i, i + 1, None))
        i += 1
    return None if in_class else groups


def _rex_rewrite(pattern: str, groups, keep: int | None = None) -> str:
    """Strip group names; if keep is set, only group #keep (0-based) stays capturing."""
    out, last = [], 0
    for idx, (start, end, _) in enumerate(groups):
        out.append(pattern[last:start])
        out.append("(" if keep is None or idx == keep else "(?:")
        last = end
    out.append(pattern[last:])
    return "".join(out)


def _rex(arg: str, target: str):
    opts, rest = {}, arg
    while True:
        m = _REX_OPTION.match(rest)
        if not m:
            break
        opts[m.group(1)] = m.group(2).strip('"')
        rest = rest[m.end():]
    m = re.fullmatch(r'\s*"((?:[^"\\]|\\.)*)"\s*', rest)
    if not m or opts.get("max_match", "1") != "1":
        return None                    # sed mode, offset_field, unquoted, multi-match
    src = opts.get("field", "_raw")
    if src == "_raw" or not _PLAIN_IDENT.fullmatch(src):
        return None                    # no _raw equivalent in Sentinel / XQL datasets
    raw = m.group(1)
    if "\\\\" in raw:
        return None                    # SPL backslash-escaping of the regex is ambiguous
    pattern = raw.replace('\\"', '"')
    if _REX_UNSUPPORTED.search(pattern):
        return None                    # PCRE-only: lookaround, backrefs, atomic, ...
    groups = _rex_groups(pattern)
    if not groups:
        return None
    named = [(i, g[2]) for i, g in enumerate(groups) if g[2]]
    names = [n for _, n in named]
    if not named or len(set(names)) != len(names):
        return None
    if src in names and len(names) > 1:
        return None                    # source overwritten while still being read
    fx = dict(reads=[src], add=names)
    if target == "kql":
        regex = '@"' + _rex_rewrite(pattern, groups).replace('"', '""') + '"'
        parts = [f"{kql_name(n)} = extract({regex}, {i + 1}, {kql_name(src)})" for i, n in named]
        return Out("extend " + ", ".join(parts), **fx)
    if '"' in pattern or not all(_XQL_IDENT.fullmatch(n) for n in names):
        return None
    parts = [f'{n} = regextract({src}, "{_rex_rewrite(pattern, groups, keep=i)}")'
             for i, n in named]
    return Flagged("alter " + ", ".join(parts), [XQL_REX_WARNING], **fx)


# ---- timechart --------------------------------------------------------------------
# SPL `timechart span=<n><unit> count`: event count per time bucket, columns
# _time and count. cont=true (default) fills empty buckets; bins start at
# epoch-aligned boundaries, but day bins "may not match your local timezone".
#   KQL: summarize count by _time = bin(TimeGenerated, <span>) | sort by _time
#        asc. Empty bins are not produced (bin() docs pad them with union/range).
#   XQL: bin _time span = <span> | comp count() as count by _time | sort asc
#        _time. Empty bins and default alignment are not documented.
# Only spans that divide a day (s/m/h) or exactly 1d, so bucket boundaries do
# not depend on the engine's epoch. No span (depends on the time range), by
# (one column per value + OTHER/NULL), other aggregations -> None.

TC_FILL_WARNING = ("{T}: SPL timechart fills empty time buckets (cont=true); this output "
                   "omits them. Verify, or add cont=false to the SPL if gaps do not matter")
TC_DAY_WARNING = ("{T}: span=1d buckets are UTC here; SPL day buckets may follow the "
                  "user's timezone; verify")
XQL_TC_ALIGN_WARNING = ("XQL: default bin alignment is not documented (no timeshift/timezone "
                        "given); verify bucket boundaries")
_SPAN_UNITS = {"s": 1, "sec": 1, "secs": 1, "second": 1, "seconds": 1,
               "m": 60, "min": 60, "mins": 60, "minute": 60, "minutes": 60,
               "h": 3600, "hr": 3600, "hrs": 3600, "hour": 3600, "hours": 3600,
               "d": 86400, "day": 86400, "days": 86400}
_SPAN_SUFFIX = {1: "s", 60: "m", 3600: "h", 86400: "d"}


def _timechart(arg: str, target: str):
    opts, rest = {}, []
    for tok in arg.split():
        m = re.fullmatch(r"(span|cont)=(\S+)", tok)
        if m:
            opts[m.group(1)] = m.group(2).lower()
        else:
            rest.append(tok)
    if rest != ["count"] or "span" not in opts:
        return None                    # by-clause, other aggregations, options, no span
    m = re.fullmatch(r"(\d+)([a-z]+)", opts["span"])
    if not m or m.group(2) not in _SPAN_UNITS or int(m.group(1)) == 0:
        return None
    n, unit = int(m.group(1)), _SPAN_UNITS[m.group(2)]
    seconds = n * unit
    if unit == 86400 and n != 1:
        return None                    # multi-day bins: epoch alignment differs
    if unit < 86400 and 86400 % seconds:
        return None                    # bins that do not divide a day
    cont = opts.get("cont", "true")
    if cont not in _TRUE | _FALSE:
        return None
    span = f"{n}{_SPAN_SUFFIX[unit]}"
    T = target.upper()
    warnings = [TC_FILL_WARNING.format(T=T)] if cont in _TRUE else []
    if unit == 86400:
        warnings.append(TC_DAY_WARNING.format(T=T))
    if target == "kql":
        text = (f"summarize {kql_name('count')} = count() by _time = bin(TimeGenerated, {span})\n"
                "| sort by _time asc")
        reads = ["TimeGenerated"]
    else:
        warnings.append(XQL_TC_ALIGN_WARNING)
        text = f"bin _time span = {span}\n| comp count() as count by _time\n| sort asc _time"
        reads = ["_time"]
    fx = dict(reads=reads, only=["_time", "count"], order="sorts", unique=["_time"])
    return Flagged(text, warnings, **fx) if warnings else Out(text, **fx)


# ---- lookup -----------------------------------------------------------------------
# SPL `lookup <table> <lfield> [AS <efield>] ... OUTPUT <dest> [AS <edest>] ...`.
# OUTPUT overwrites existing fields; OUTPUTNEW only fills missing ones. No-match
# and multiple-match behaviour are not documented. ALWAYS flagged: the lookup
# table must exist on the target side and lookup options are not carried over.
#   KQL: lookup kind=leftouter (_GetWatchlist('<alias>') | project ...)
#        on $left.<efield> == $right.<lfield>   (Sentinel watchlists docs).
#        Columns already present on the left are renamed, not overwritten.
#   XQL: join type = left (dataset = <name> | fields ...) as lk <condition>.
#        conflict_strategy defaults to right (lookup value wins, like OUTPUT).
#        Keys are aliased inside the subquery so a same-named event field is
#        not overwritten with NULL on no match, then removed with `fields -`.
# OUTPUTNEW, no OUTPUT list (unknown columns), options -> None.

LOOKUP_WARNING = (
    "{T}: lookup '{table}' must exist as {where} '{alias}' with columns {cols}. Splunk "
    "lookup settings (case sensitivity, match type such as CIDR, max matches) are not "
    "carried over; several matching rows give several result rows; {conflict}. Verify")
_LOOKUP_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def parse_lookup(arg: str):
    """-> (table, [(lookup_field, event_field)], [(dest, event_dest)]) or None."""
    toks = [t for t in re.split(r"[\s,]+", arg.strip()) if t]
    if len(toks) < 2 or "=" in arg:
        return None                        # options like local=, update=
    table, toks = toks[0], toks[1:]
    upper = [t.upper() for t in toks]
    if "OUTPUTNEW" in upper or "OUTPUT" not in upper:
        return None
    cut = upper.index("OUTPUT")

    def pairs(items):
        out, i = [], 0
        while i < len(items):
            name = items[i]
            if i + 1 < len(items) and items[i + 1].upper() == "AS":
                if i + 2 >= len(items):
                    return None
                out.append((name, items[i + 2]))
                i += 3
            else:
                out.append((name, name))
                i += 1
        return out

    keys, outs = pairs(toks[:cut]), pairs(toks[cut + 1:])
    if not keys or not outs:
        return None
    names = [n for p in keys + outs for n in p]
    if not all(_LOOKUP_NAME.fullmatch(n) and n.upper() not in ("AS", "OUTPUT") for n in names):
        return None
    lnames = [k for k, _ in keys] + [d for d, _ in outs]
    enames = [e for _, e in keys] + [e for _, e in outs]
    if len(set(lnames)) != len(lnames) or len(set(enames)) != len(enames):
        return None
    return table, keys, outs


def _lookup(arg: str, target: str):
    parsed = parse_lookup(arg)
    if parsed is None:
        return None
    table, keys, outs = parsed
    alias = table[:-4] if table.lower().endswith(".csv") else table
    if not re.fullmatch(r"[A-Za-z0-9_-]+", alias):
        return None
    cols = ", ".join([k for k, _ in keys] + [d for d, _ in outs])
    fx = dict(reads=[e for _, e in keys], add=[e for _, e in outs], multiplies=True)
    T = target.upper()
    if target == "kql":
        proj = [kql_name(k) for k, _ in keys] + [
            kql_name(d) if d == e else f"{kql_name(e)} = {kql_name(d)}" for d, e in outs]
        on = [kql_name(k) if k == e else f"$left.{kql_name(e)} == $right.{kql_name(k)}"
              for k, e in keys]
        text = (f"lookup kind=leftouter (_GetWatchlist('{alias}') | project {', '.join(proj)}) "
                f"on {', '.join(on)}")
        warn = LOOKUP_WARNING.format(T=T, table=table, where="a Sentinel watchlist",
                                     alias=alias, cols=cols,
                                     conflict="existing columns with an output name are "
                                              "renamed by KQL, not overwritten as in SPL")
        return Flagged(text, [warn], **fx)
    if not re.fullmatch(r"[A-Za-z0-9_]+", alias):
        return None
    key_alias = [f"lookup_key_{i + 1}" for i in range(len(keys))]
    fields = [f"{k} as {a}" for (k, _), a in zip(keys, key_alias)] + [
        d if d == e else f"{d} as {e}" for d, e in outs]
    cond = " and ".join(f"lk.{a} = {e}" for (_, e), a in zip(keys, key_alias))
    text = (f"join type = left (dataset = {alias} | fields {', '.join(fields)}) as lk {cond}\n"
            f"| fields - {', '.join(key_alias)}")
    warn = LOOKUP_WARNING.format(T=T, table=table, where="an XQL lookup dataset",
                                 alias=alias, cols=cols,
                                 conflict="output fields overwrite existing fields "
                                          "(conflict_strategy right); `dataset = <lookup>` "
                                          "and `fields -` are not shown in the docs")
    return Flagged(text, [warn], **fx)


# ---- join ---------------------------------------------------------------------------
# SPL `join [type=inner|left|outer] [max=N] <fields> [<subsearch>]`: defaults
# type=inner, max=1 (each event joins to only the FIRST subsearch row),
# overwrite=true (subsearch values replace event values). left == outer.
# Subsearches are limited to 50,000 rows / 60 s and silently truncated.
#   KQL: join kind=inner|leftouter (<sub>) on <fields>. The default kind
#        innerunique de-duplicates the LEFT side, so the kind is always given.
#        inner/leftouter return every matching row; same-named right columns are
#        renamed, not overwritten.
#   XQL: join type = inner|left (<sub>) as sub <cond>; conflict_strategy right
#        (default) = subsearch wins, like SPL. Keys are aliased in the subquery.
# The subsearch is translated by the same rules; any gap -> None.
# max=1 is only converted when the subsearch provably has at most one row per
# key (ends in stats/dedup/top by the keys), otherwise None. max=0 -> all rows.
# Always flagged (subsearch limits, column conflicts).
# None: no field list (joins on all common fields), usetime/earlier/overwrite,
# left=/right=/where forms, other max values.

JOIN_WARNING = ("{T}: SPL join subsearches are limited to 50,000 rows / 60 s and silently "
                "truncated; the target has no such limit. {conflict}. Verify")
JOIN_KQL_CONFLICT = ("Right-side columns with the same name as left-side columns are renamed "
                     "(SPL overwrite=true replaces them) and the join key appears twice")
JOIN_XQL_CONFLICT = ("Subsearch fields overwrite event fields (conflict_strategy right), like "
                     "SPL; `fields -` on the subquery is not shown in the docs")


def split_subsearch(arg: str):
    """'type=left host [search x | y]' -> ('type=left host', 'search x | y') or None."""
    start = arg.find("[")
    if start < 0 or not arg.rstrip().endswith("]"):
        return None
    depth, quote = 0, None
    for i in range(start, len(arg)):
        ch = arg[i]
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return (arg[:start], arg[start + 1:i].strip()) if not arg[i + 1:].strip() else None
    return None


def convert_rules_only(spl: str, target: str) -> list | None:
    """Translate a (sub)search with rules only; None if any stage has no rule."""
    from .triage import split_stages
    stages = split_stages(spl)
    if not stages:
        return None
    head = re.sub(r"(?i)^search\s+", "", stages[0])
    first = first_stage(head, target)
    rest = [stage(s, target) for s in stages[1:]]
    if first is None or any(r is None for r in rest):
        return None
    return [first, *rest]


def _join(arg: str, target: str):
    from . import schema
    split = split_subsearch(arg)
    if split is None:
        return None
    head, sub = split
    opts, keys = {"type": "inner", "max": "1"}, []
    for tok in [t for t in re.split(r"[\s,]+", head.strip()) if t]:
        m = re.fullmatch(r"(type|max)=(\w+)", tok)
        if m:
            opts[m.group(1)] = m.group(2).lower()
        elif "=" in tok or not _PLAIN_IDENT.fullmatch(tok):
            return None                    # usetime, earlier, overwrite, left=/right=
        else:
            keys.append(tok)
    kind = {"inner": "inner", "left": "leftouter", "outer": "leftouter"}.get(opts["type"])
    if not keys or kind is None or opts["max"] not in ("0", "1") or len(set(keys)) != len(keys):
        return None
    parts = convert_rules_only(sub, target)
    if parts is None:
        return None
    if opts["max"] == "1":
        uniq = schema.unique_after(parts)
        if uniq is None or not uniq <= set(keys):
            return None                    # first-row-per-key semantics not reproducible
    T = target.upper()
    warnings = []
    for part in parts:
        warnings += [f"subsearch: {w}" for w in getattr(part, "warnings", [])]
    warnings += [f"subsearch: {w}" for w in schema.check(parts, target)]
    warnings += [f"subsearch: {w}" for w in schema.order_check(parts, target)]
    sub_fields = schema.output_fields(parts, target)
    if sub_fields is not None and not set(keys) <= set(sub_fields):
        warnings.append(f"{T}: join key(s) not produced by the subsearch: "
                        + ", ".join(k for k in keys if k not in sub_fields))
    fx = dict(reads=keys, add=[f for f in (sub_fields or []) if f not in keys],
              order="loses", multiplies=opts["max"] == "0")
    if target == "kql":
        body = "\n".join("    " + line for line in "\n| ".join(parts).split("\n"))
        text = f"join kind={kind} (\n{body}\n) on {', '.join(kql_name(k) for k in keys)}"
        warnings.insert(0, JOIN_WARNING.format(T=T, conflict=JOIN_KQL_CONFLICT))
        return Flagged(text, list(dict.fromkeys(warnings)), **fx)
    if not all(_XQL_IDENT.fullmatch(k) for k in keys):
        return None
    aliases = [f"join_key_{i + 1}" for i in range(len(keys))]
    sub_parts = [*parts,
                 "alter " + ", ".join(f"{a} = {k}" for a, k in zip(aliases, keys)),
                 "fields - " + ", ".join(keys)]
    body = "\n    ".join("\n| ".join(sub_parts).split("\n"))
    cond = " and ".join(f"sub.{a} = {k}" for a, k in zip(aliases, keys))
    xtype = "inner" if kind == "inner" else "left"
    text = (f"join type = {xtype} ({body}) as sub {cond}\n"
            f"| fields - {', '.join(aliases)}")
    warnings.insert(0, JOIN_WARNING.format(T=T, conflict=JOIN_XQL_CONFLICT))
    return Flagged(text, list(dict.fromkeys(warnings)), **fx)
