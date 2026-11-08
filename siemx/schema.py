"""Field-name safety check for rule-based output.

Field names are copied from SPL unchanged (field mapping is roadmap item 6).
To stop wrong names from being auto-approved, walk the rule outputs and flag
any field a stage reads that the target table does not have, according to
mappings/fields.json. Fields created inside the query (stats, rename) count
as known from that stage on.
"""
from __future__ import annotations

import json
import re

from . import config


_CACHE: dict = {}


def _load() -> dict:
    f = config.FIELDS_FILE
    if not f.exists():
        return {}
    key = (str(f), f.stat().st_mtime_ns)
    if key not in _CACHE:
        _CACHE.clear()
        _CACHE[key] = json.loads(f.read_text(encoding="utf-8"))
    return _CACHE[key]


def table_of(first_stage, target: str) -> str:
    """Table/dataset name of the first stage ('dataset = xdr_data' -> 'xdr_data').
    A first stage with a filter carries the name in its .table attribute."""
    table = getattr(first_stage, "table", None)
    if table:
        return table
    if target == "xql":
        m = re.fullmatch(r"\s*dataset\s*=\s*(\w+)\s*", first_stage)
        return m.group(1) if m else first_stage.strip()
    return first_stage.strip()


def known_fields(table: str, target: str) -> list[str] | None:
    entry = _load().get(target, {}).get(table)
    return None if entry is None else list(entry.get("fields", []))


def field_type(table: str, target: str, field: str) -> str | None:
    """Column type from mappings/fields.json ('int', 'string', ...), or None."""
    entry = _load().get(target, {}).get(table) or {}
    return entry.get("types", {}).get(field)


def check(parts: list, target: str) -> list[str]:
    """Return warnings for unknown field reads; [] when all fields are known."""
    table = table_of(parts[0], target)
    known = known_fields(table, target)
    schema = set(known or [])
    seen = set(schema)                 # every field that existed at some point
    unknown: list[str] = []
    removed: list[str] = []
    for part in parts:                 # parts[0] may filter fields too (base search)
        for f in getattr(part, "reads", []):
            if f in schema or f in unknown or f in removed:
                continue
            (removed if f in seen else unknown).append(f)
        only = getattr(part, "only", None)
        if only is not None:
            schema = set(only)
        schema -= set(getattr(part, "drop", []))
        schema |= set(getattr(part, "add", []))
        seen |= schema
    T = target.upper()
    warnings = []
    if removed:
        warnings.append(f"{T}: field(s) used after an earlier stage removed them "
                        f"(e.g. stats, table, rename): {', '.join(removed)}; verify")
    if unknown and not known:
        warnings.append(f"{T}: no field list for {table} in mappings/fields.json; "
                        f"field names not verified: {', '.join(unknown)}")
    elif unknown:
        warnings.append(f"{T}: field(s) not in {table} (mappings/fields.json): "
                        f"{', '.join(unknown)}. Field names are copied from SPL unmapped; verify")
    return warnings


ORDER_HEAD_WARNING = ("{T}: head -> {op} on rows with no defined order; SPL takes the first rows "
                      "in its order (newest first, or as sorted by stats). Add a sort or verify")
ORDER_DEDUP_WARNING = ("{T}: dedup keeps the newest row per group, but SPL keeps the first row "
                       "in the current (re-sorted) order; verify")


def order_check(parts: list, target: str) -> list[str]:
    """Flag stages whose result depends on row order that the target does not keep.

    SPL search results start newest-first; KQL/XQL results have no defined order
    until a sort (take/limit docs: no guarantee which records are returned
    unless sorted). where / table / rename are assumed to keep the order.
    """
    T = target.upper()
    op = "take" if target == "kql" else "limit"
    target_sorted = False      # target rows are in a defined order
    spl_newest_first = True    # SPL rows still in default newest-first order
    warnings: list[str] = []
    for part in parts[1:]:
        order = getattr(part, "order", set())
        if "keeps_first" in order and not spl_newest_first:
            warnings.append(ORDER_DEDUP_WARNING.format(T=T))
        if "takes_first" in order and not target_sorted:
            warnings.append(ORDER_HEAD_WARNING.format(T=T, op=op))
        if "sorts" in order:
            target_sorted, spl_newest_first = True, False
        if "loses" in order:
            target_sorted, spl_newest_first = False, False
    return list(dict.fromkeys(warnings))


def output_fields(parts: list, target: str) -> list[str] | None:
    """Fields available after all stages, or None if unknown (no field list for
    the table and no stage that fixes the output columns)."""
    known = known_fields(table_of(parts[0], target), target)
    fields = set(known) if known else None
    for part in parts[1:]:
        only = getattr(part, "only", None)
        if only is not None:
            fields = set(only)
        if fields is not None:
            fields -= set(getattr(part, "drop", []))
            fields |= set(getattr(part, "add", []))
    return sorted(fields) if fields is not None else None


def unique_after(parts: list) -> set[str] | None:
    """Fields F such that the result has at most one row per value of F, or None.
    Set by stats/dedup/top/timechart; kept by where/sort/head/eval and by stages
    that keep F; lost by row-multiplying stages or stages that change F."""
    uniq = None
    for part in parts[1:]:
        u = getattr(part, "unique", None)
        if u is not None:
            uniq = set(u)
            continue
        if uniq is None:
            continue
        only = getattr(part, "only", None)
        changed = set(getattr(part, "drop", [])) | set(getattr(part, "add", []))
        if (getattr(part, "multiplies", False) or (only is not None and not uniq <= set(only))
                or uniq & changed):
            uniq = None
    return uniq
