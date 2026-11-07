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
    """
    warnings: list[str] = []

    def __new__(cls, text: str, *, reads=(), only=None, add=(), drop=()):
        obj = super().__new__(cls, text)
        obj.reads = list(reads)
        obj.only = None if only is None else list(only)
        obj.add, obj.drop = list(add), list(drop)
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
    "evaluate", "extend", "false", "find", "has", "in", "invoke", "join", "kind",
    "let", "limit", "lookup", "not", "null", "of", "on", "or", "order", "parse",
    "print", "project", "range", "render", "sample", "search", "serialize", "sort",
    "summarize", "take", "top", "true", "typeof", "union", "where", "with",
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

    if cmd == "rename":
        return _rename(arg, target)

    if cmd == "head" and arg.isdigit():
        return f"take {arg}" if target == "kql" else f"limit {arg}"

    # SPL `stats count` outputs a column named `count`. Name it explicitly so
    # later stages (e.g. `sort - count`) can reference it:
    #   KQL: unnamed count() becomes `count_`, and `count` is a keyword -> ['count'].
    #   XQL: `comp count() as <alias> by f1, f2` (alias optional, documented).
    m = re.fullmatch(r"count(?: by (.+))?", arg) if cmd == "stats" else None
    if m:
        by_fields = _fields(m.group(1)) if m.group(1) else []
        by = f" by {_names(by_fields, target)}" if by_fields else ""
        fx = dict(reads=by_fields, only=["count", *by_fields])
        if target == "kql":
            return Out(f"summarize {kql_name('count')} = count(){by}", **fx)
        return Out(f"comp count() as count{by}", **fx)

    m = re.fullmatch(r"([-+])?\s*(\w+)", arg) if cmd == "sort" else None
    if m:
        desc, f = m.group(1) == "-", m.group(2)
        if target == "kql":
            return Out(f"sort by {kql_name(f)} {'desc' if desc else 'asc'}", reads=[f])
        return Out(f"sort {'desc' if desc else 'asc'} {f}", reads=[f])

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
