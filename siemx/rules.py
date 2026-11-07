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
    """
    warnings: list[str] = []

    def __new__(cls, text: str, *, reads=(), only=None, add=(), drop=(), order=()):
        obj = super().__new__(cls, text)
        obj.reads = list(reads)
        obj.only = None if only is None else list(only)
        obj.add, obj.drop = list(add), list(drop)
        obj.order = set([order] if isinstance(order, str) else order)
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
    """Map `index=... sourcetype=...` to a table/dataset via mappings/sources.json."""
    for prefix, tgt in _load_sources().items():
        if stage.lower().startswith(prefix.lower()) and target in tgt:
            rest = stage[len(prefix):].strip()
            if rest:   # leftover search terms need real translation
                return None
            return tgt[target]
    return None


def stage(stage_text: str, target: str):
    cmd = command_of(stage_text)
    arg = stage_text.strip()[len(cmd):].strip()

    if cmd in ("table", "fields") and "-" not in arg:
        fl = _fields(arg)
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

    if cmd == "dedup":
        return _dedup(arg, target)

    if cmd == "rename":
        return _rename(arg, target)

    if cmd == "head" and arg.isdigit():
        return Out(f"take {arg}" if target == "kql" else f"limit {arg}", order="takes_first")

    # SPL `stats count` outputs a column named `count`. Name it explicitly so
    # later stages (e.g. `sort - count`) can reference it:
    #   KQL: unnamed count() becomes `count_`, and `count` is a keyword -> ['count'].
    #   XQL: `comp count() as <alias> by f1, f2` (alias optional, documented).
    m = re.fullmatch(r"count(?: by (.+))?", arg) if cmd == "stats" else None
    if m:
        by_fields = _fields(m.group(1)) if m.group(1) else []
        by = f" by {_names(by_fields, target)}" if by_fields else ""
        fx = dict(reads=by_fields, only=["count", *by_fields], order="loses")
        if target == "kql":
            return Out(f"summarize {kql_name('count')} = count(){by}", **fx)
        return Out(f"comp count() as count{by}", **fx)

    m = re.fullmatch(r"([-+])?\s*(\w+)", arg) if cmd == "sort" else None
    if m:
        desc, f = m.group(1) == "-", m.group(2)
        if target == "kql":
            return Out(f"sort by {kql_name(f)} {'desc' if desc else 'asc'}", reads=[f], order="sorts")
        return Out(f"sort {'desc' if desc else 'asc'} {f}", reads=[f], order="sorts")

    return None


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
        return Out(text, reads=[*fields, "TimeGenerated"], order={"keeps_first", "loses"})
    if not all(_XQL_IDENT.fullmatch(f) for f in fields):
        return None
    notnull = " and ".join(f"{f} != null" for f in fields)
    text = f"filter {notnull}\n| dedup {', '.join(fields)} by desc _time"
    return Flagged(text, [XQL_DEDUP_WARNING], reads=[*fields, "_time"],
                   order={"keeps_first", "loses"})


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
    fx = dict(reads=[f], only=[f, countfield], order="sorts")
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
