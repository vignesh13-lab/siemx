"""Deterministic 1:1 stage rules. Return None when unsure -> falls to LLM.
STARTER RULES: verify each against the official docs before trusting."""
import json
import re
from .config import MAP_FILE
from .triage import command_of


def _fields(arg: str) -> list[str]:
    return [f for f in re.split(r"[,\s]+", arg.strip()) if f]


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
        f = ", ".join(_fields(arg))
        return f"project {f}" if target == "kql" else f"fields {f}"

    if cmd == "head" and arg.isdigit():
        return f"take {arg}" if target == "kql" else f"limit {arg}"

    m = re.fullmatch(r"count(?: by (.+))?", arg) if cmd == "stats" else None
    if m:
        by = f" by {', '.join(_fields(m.group(1)))}" if m.group(1) else ""
        return f"summarize count(){by}" if target == "kql" else f"comp count() as count{by}"

    m = re.fullmatch(r"([-+])?\s*(\w+)", arg) if cmd == "sort" else None
    if m:
        desc = m.group(1) == "-"
        if target == "kql":
            return f"sort by {m.group(2)} {'desc' if desc else 'asc'}"
        return f"sort {'desc' if desc else 'asc'} {m.group(2)}"

    return None
