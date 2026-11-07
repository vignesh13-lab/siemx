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


def _load() -> dict:
    f = config.FIELDS_FILE
    return json.loads(f.read_text()) if f.exists() else {}


def table_of(first_stage_text: str, target: str) -> str:
    """'SecurityEvent' -> 'SecurityEvent'; 'dataset = xdr_data' -> 'xdr_data'."""
    if target == "xql":
        m = re.fullmatch(r"\s*dataset\s*=\s*(\w+)\s*", first_stage_text)
        return m.group(1) if m else first_stage_text.strip()
    return first_stage_text.strip()


def known_fields(table: str, target: str) -> list[str] | None:
    entry = _load().get(target, {}).get(table)
    return None if entry is None else list(entry.get("fields", []))


def check(parts: list, target: str) -> list[str]:
    """Return warnings for unknown field reads; [] when all fields are known."""
    table = table_of(parts[0], target)
    known = known_fields(table, target)
    schema = set(known or [])
    unknown: list[str] = []
    for part in parts[1:]:
        for f in getattr(part, "reads", []):
            if f not in schema and f not in unknown:
                unknown.append(f)
        only = getattr(part, "only", None)
        if only is not None:
            schema = set(only)
        schema -= set(getattr(part, "drop", []))
        schema |= set(getattr(part, "add", []))
    if not unknown:
        return []
    names = ", ".join(unknown)
    if not known:
        return [f"{target.upper()}: no field list for {table} in mappings/fields.json; "
                f"field names not verified: {names}"]
    return [f"{target.upper()}: field(s) not in {table} (mappings/fields.json): {names}. "
            "Field names are copied from SPL unmapped; verify"]
