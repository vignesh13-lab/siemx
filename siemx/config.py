from pathlib import Path

ROOT = Path.cwd()
SRC_REL = Path("detections") / "spl"   # stored in meta as a repo-relative path
SRC_DIR = ROOT / SRC_REL
OUT_DIR = ROOT / "converted"
META_DIR = OUT_DIR / "_meta"
MAP_FILE = ROOT / "mappings" / "sources.json"
FIELDS_FILE = ROOT / "mappings" / "fields.json"   # known target fields per table
GOLD_DIR = ROOT / "gold"

EXT = {"kql": ".kql", "xql": ".xql"}
CONF_AUTO_APPROVE = 0.85   # at or above this -> auto-approved

# Bump whenever rules/prompts change output, so unchanged SPL is re-converted.
CONVERTER_VERSION = "12"
