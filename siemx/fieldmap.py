"""Roadmap 6: field mapping (Splunk field names -> target table columns).

There is no official complete crosswalk: Microsoft's Splunk migration guide asks you to
build your own mapping, and the Splunk Windows add-on maps fields per event ID in its
props.conf. So mappings are kept per target table, per client, with an evidence level:

  exact        documented equivalence (e.g. a FIELDALIAS in the client's own add-on
               config, imported with `siemx fields import-props`) -> applied silently
  conditional  right under a stated condition -> applied AND flagged with the condition
  ambiguous    several candidates (e.g. Account_Name = SubjectUserName or TargetUserName
               in event 4624) -> NOT applied; flagged with the candidates

Files (keys starting with "_" are comments):
  mappings/field_map.json                  shared defaults
  mappings/clients/<client>/field_map.json client overrides (e.g. from import-props)
  {"kql": {"SecurityEvent": {"sources": [urls], "fields": {
       "host": {"to": "Computer", "level": "conditional", "note": "..."},
       "user": {"level": "ambiguous", "candidates": ["TargetUserName", "SubjectUserName"]}}}}}

Applying: only to fields the query READS from the source table and never CREATES
(schema.field_reads), so every occurrence of the name means the source field and a
rename of the SPL identifier is safe. Created fields (eval x=..., rex groups, AS
aliases) are never renamed.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from . import config

LEVELS = ("exact", "conditional", "ambiguous")


def shared_file() -> Path:
    return config.MAPPINGS_DIR / "field_map.json"


def _read(path: Path | None) -> dict:
    if path is None or not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def table_map(target: str, table: str) -> dict[str, dict]:
    """Field entries for a target table: shared, then the client's entries on top."""
    cdir = config.client_dir()
    out = {}
    for data in (_read(shared_file()), _read(cdir / "field_map.json" if cdir else None)):
        section = data.get(target, {}).get(table, {})
        out.update({k: v for k, v in section.get("fields", {}).items() if not k.startswith("_")})
    return out


def load_all() -> dict:
    """Everything (for the mappings fingerprint)."""
    cdir = config.client_dir()
    return {"shared": _read(shared_file()),
            "client": _read(cdir / "field_map.json" if cdir else None)}


# ---- planning which names to rename -----------------------------------------------------------

def plan(unknown: list[str], created: set[str], target: str, table: str) -> dict:
    """-> {"renames": {spl: col}, "warnings": [...], "applied": {spl: {to, level}}}"""
    fmap = table_map(target, table)
    T = target.upper()
    renames, warnings, applied = {}, [], {}
    for name in unknown:
        e = fmap.get(name)
        if not e or name in created:
            continue
        level = e.get("level", "conditional")
        if level == "ambiguous":
            cands = ", ".join(e.get("candidates", []))
            warnings.append(f"{T}: field '{name}' is ambiguous for {table}: one of {cands}. "
                            f"{e.get('note', '')} Not mapped; choose the right column".strip())
            continue
        renames[name] = e["to"]
        applied[name] = {"to": e["to"], "level": level}
        if level == "conditional":
            warnings.append(f"{T}: field '{name}' mapped to {e['to']} (conditional: "
                            f"{e.get('note', 'see mappings/field_map.json')}); verify")
    return {"renames": renames, "warnings": warnings, "applied": applied}


# ---- renaming identifiers in SPL ----------------------------------------------------------------

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*")
_VALUE_OPS = ("=", "!=", "<", ">", "<=", ">=")


def rename_in_spl(spl: str, renames: dict[str, str]) -> str:
    """Rename field identifiers outside double-quoted strings.
    'single quoted' SPL field names are renamed too. Not renamed: function names
    (followed by '('), the command word of a stage, and in the base search (first
    stage) the VALUE side of field=value (a literal there, not a field)."""
    if not renames:
        return spl
    from .triage import split_stages
    out_stages = []
    for idx, stage in enumerate(split_stages(spl)):
        out_stages.append(_rename_stage(stage, renames, base=(idx == 0)))
    return " | ".join(out_stages)


def _rename_stage(stage: str, renames: dict[str, str], base: bool) -> str:
    out, i, first_word = [], 0, not base
    while i < len(stage):
        ch = stage[i]
        if ch == '"':                                     # string literal: copy as is
            j = i + 1
            while j < len(stage) and stage[j] != '"':
                j += 2 if stage[j] == "\\" else 1
            out.append(stage[i:j + 1])
            i = j + 1
            continue
        if ch == "'":                                     # 'quoted field name'
            j = stage.find("'", i + 1)
            j = len(stage) - 1 if j < 0 else j
            name = stage[i + 1:j]
            out.append(f"'{renames.get(name, name)}'")
            i = j + 1
            continue
        m = _IDENT.match(stage, i) if (ch.isalpha() or ch == "_") and (
            i == 0 or not (stage[i - 1].isalnum() or stage[i - 1] in "_.")) else None
        if m:
            word, end = m.group(), m.end()
            rest = stage[end:].lstrip()
            prev = "".join(out).rstrip()
            is_call = rest.startswith("(")
            is_value = base and prev.endswith(_VALUE_OPS)
            if first_word:
                first_word = False                        # the command name
                out.append(word)
            elif word in renames and not is_call and not is_value:
                out.append(renames[word])
            else:
                out.append(word)
            i = end
            continue
        out.append(ch)
        i += 1
    return "".join(out).strip()


# ---- importing a client's Splunk add-on config (props.conf) ------------------------------

_STANZA = re.compile(r"^\s*\[(.+?)\]\s*$")
_ALIAS = re.compile(r"^\s*FIELDALIAS-[^=]+=\s*(.+)$")
_EVAL = re.compile(r"^\s*EVAL-([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$")


def parse_props(text: str, stanza: str) -> dict[str, dict]:
    """CIM field -> source field(s) from one props.conf stanza.
      FIELDALIAS-x = SrcField AS cim_field [OTHER AS other ...]  -> exact
      EVAL-cim_field = coalesce(A, B)                             -> ambiguous [A, B]
      EVAL-cim_field = SrcField                                   -> exact
      any other EVAL (case(...), if(...), ...)                     -> skipped (logic)"""
    out, current = {}, None
    for line in text.splitlines():
        m = _STANZA.match(line)
        if m:
            current = m.group(1).strip()
            continue
        if current != stanza or line.lstrip().startswith("#"):
            continue
        m = _ALIAS.match(line)
        if m:
            for src, dst in re.findall(r"(\S+)\s+(?:AS|as)\s+(\S+)", m.group(1)):
                out[dst] = {"from": [src], "how": "FIELDALIAS"}
            continue
        m = _EVAL.match(line)
        if m:
            dst, expr = m.group(1), m.group(2).strip()
            c = re.fullmatch(r"coalesce\((.+)\)", expr)
            if c:
                args = [a.strip() for a in c.group(1).split(",")]
                if all(_IDENT.fullmatch(a) for a in args):
                    out[dst] = {"from": args, "how": "EVAL coalesce"}
            elif _IDENT.fullmatch(expr):
                out[dst] = {"from": [expr], "how": "EVAL"}
    return out


def entries_from_props(parsed: dict, target_columns: set[str], source: str) -> dict:
    """Keep only mappings whose source fields are real target columns (fields.json)."""
    entries = {}
    for cim, info in parsed.items():
        cols = [f for f in info["from"] if f in target_columns]
        if not cols:
            continue
        if len(info["from"]) == 1:
            entries[cim] = {"to": cols[0], "level": "exact",
                            "note": f"{info['how']} in {source}"}
        else:
            entries[cim] = {"level": "ambiguous", "candidates": cols,
                            "note": f"{info['how']}({', '.join(info['from'])}) in {source}: "
                                    f"the first non-empty one is used per event."}
    return entries
