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
