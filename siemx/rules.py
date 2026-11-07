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
"""
import json
import re

from . import expr
from .config import MAP_FILE
from .triage import command_of


class Flagged(str):
    """Rule output that is usable but must be reviewed by a human.
    Behaves as a str; the pipeline reads .warnings and marks needs-review."""

    def __new__(cls, text: str, warnings: list[str]):
        obj = super().__new__(cls, text)
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
        f = _names(_fields(arg), target)
        return f"project {f}" if target == "kql" else f"fields {f}"

    # SPL where -> KQL where / XQL filter (simple comparisons only; see expr.py)
    if cmd == "where" and arg:
        r = expr.translate(arg, target)
        if r is None:
            return None
        text = f"where {r.text}" if target == "kql" else f"filter {r.text}"
        return Flagged(text, r.warnings) if r.warnings else text

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
        if target == "kql":
            return f"summarize {kql_name('count')} = count(){by}"
        return f"comp count() as count{by}"

    m = re.fullmatch(r"([-+])?\s*(\w+)", arg) if cmd == "sort" else None
    if m:
        desc = m.group(1) == "-"
        if target == "kql":
            return f"sort by {kql_name(m.group(2))} {'desc' if desc else 'asc'}"
        return f"sort {'desc' if desc else 'asc'} {m.group(2)}"

    return None
