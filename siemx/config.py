import re
from pathlib import Path

ROOT = Path.cwd()
SRC_REL = Path("detections") / "spl"   # stored in meta as a repo-relative path
SRC_DIR = ROOT / SRC_REL
OUT_DIR = ROOT / "converted"
META_DIR = OUT_DIR / "_meta"
MAPPINGS_DIR = ROOT / "mappings"
MAP_FILE = MAPPINGS_DIR / "sources.json"       # shared: sourcetype/index -> table
MACROS_FILE = MAPPINGS_DIR / "macros.json"     # shared Splunk macro definitions
FIELDS_FILE = MAPPINGS_DIR / "fields.json"     # known target fields per table
GOLD_DIR = ROOT / "gold"

# Per-client settings (index names and macros differ per client).
# set_client("acme") reads mappings/clients/acme/{sources,macros}.json on top of
# the shared files and writes output to converted/acme/.
CLIENT: str | None = None

EXT = {"kql": ".kql", "xql": ".xql", "spl": ".spl"}
CONF_AUTO_APPROVE = 0.85   # at or above this -> auto-approved
# LLM results are never auto-approved until the pilot shows the model's own confidence
# can be trusted (`siemx report`: accuracy of auto-approved). A local 7B model reported
# 0.9 for answers that dropped a `by` clause. Turn on per model, after measuring.
LLM_AUTO_APPROVE = False

# Bump whenever rules/prompts change output, so unchanged SPL is re-converted.
CONVERTER_VERSION = "21"   # 21: LLM results never auto-approved (LLM_AUTO_APPROVE)


def set_client(name: str | None) -> None:
    """Select a client: its mapping overrides and its own output folder."""
    global CLIENT, OUT_DIR, META_DIR
    name = name or None                    # "" (e.g. an empty CI input) = no client
    if name is None and CLIENT is None:
        return                             # nothing selected: keep the default folders
    if name is not None and not re.fullmatch(r"[A-Za-z0-9_-]+", name):
        raise ValueError(f"invalid client name: {name!r} (use letters, digits, _ and -)")
    CLIENT = name
    OUT_DIR = ROOT / "converted" / name if name else ROOT / "converted"
    META_DIR = OUT_DIR / "_meta"


def client_dir() -> Path | None:
    return MAPPINGS_DIR / "clients" / CLIENT if CLIENT else None
