"""Shared + per-client mappings: data sources and Splunk macros.

Files (keys starting with "_" are comments and ignored):
  mappings/sources.json                  shared, e.g. {"sourcetype=XmlWinEventLog:Security":
                                         {"kql": "SecurityEvent", "xql": "dataset = ..."}}
  mappings/macros.json                   shared macro definitions {"name": "definition"}
  mappings/clients/<client>/sources.json client index names, e.g. {"index=acme_win": {...}}
  mappings/clients/<client>/macros.json  client macro definitions
Client entries override shared ones with the same key.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from . import config

_MACRO = re.compile(r"`([A-Za-z0-9_]+)`")     # macros with (args) are not expanded
MAX_MACRO_DEPTH = 10


def _read(path: Path | None) -> dict:
    if path is None or not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}


def load_sources(shared: Path) -> dict:
    cdir = config.client_dir()
    return {**_read(shared), **_read(cdir / "sources.json" if cdir else None)}


def load_macros() -> dict:
    cdir = config.client_dir()
    return {**_read(config.MACROS_FILE), **_read(cdir / "macros.json" if cdir else None)}


def expand_macros(spl: str) -> str:
    """Replace `name` with its definition (nested macros too). Unknown macros and
    macros with arguments are left as they are, so no rule matches them."""
    macros = load_macros()
    if not macros:
        return spl
    for _ in range(MAX_MACRO_DEPTH):
        new = _MACRO.sub(lambda m: macros.get(m.group(1), m.group(0)), spl)
        if new == spl:
            return new
        spl = new
    return spl                                  # recursive definition: stop expanding


# ---- unmapped sources: editable placeholder entries ------------------------------------------------

def missing_sources(files: list[Path]) -> dict[str, list[Path]]:
    """Splunk sources (sourcetype / source, else index) that detections use and
    sources.json does not map -> the detections that use them."""
    from . import rules, triage
    out: dict[str, list[Path]] = {}
    for f in files:
        spl = triage.normalize_spl(expand_macros(triage.normalize_spl(f.read_text(encoding="utf-8"))))
        hit = rules.unmapped_source(spl, "kql")
        if hit is None:
            continue
        stage = triage.split_stages(spl)[0]
        label = rules.source_label(hit[1])
        for m in rules._META_TERM.finditer(stage):          # the detection's own spelling
            written = m.group(3) if m.group(3) is not None else m.group(2)
            label = label.replace(f"{m.group(1).lower()}={written.lower()}",
                                  f"{m.group(1).lower()}={written}")
        same = next((k for k in out if k.lower() == label.lower()), label)   # Splunk: any case
        out.setdefault(same, []).append(f)
    return out


def placeholder_entry(label: str) -> dict:
    from . import rules, search
    meta = search.parse_meta(label) or {}
    name = rules.placeholder_name(meta, label)
    return {"kql": name, "xql": f"dataset = {name}", "elk": name}


def write_placeholders(labels: list[str], path: Path) -> list[str]:
    """Add placeholder entries for `labels` to a sources.json (one entry per line, like
    the shared file). Existing keys are never changed. -> the keys added."""
    data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    known = {k.lower() for k in data}
    added = [lb for lb in labels if lb.lower() not in known]
    for lb in added:
        data[lb] = placeholder_entry(lb)
    lines = [f"  {json.dumps(k)}: {json.dumps(v, ensure_ascii=False)}" for k, v in data.items()]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{\n" + ",\n".join(lines) + "\n}\n", encoding="utf-8", newline="\n")
    return added
