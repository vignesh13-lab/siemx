from pathlib import Path

ROOT = Path.cwd()
SRC_DIR = ROOT / "detections" / "spl"
OUT_DIR = ROOT / "converted"
META_DIR = OUT_DIR / "_meta"
MAP_FILE = ROOT / "mappings" / "sources.json"
GOLD_DIR = ROOT / "gold"

EXT = {"kql": ".kql", "xql": ".xql"}
CONF_AUTO_APPROVE = 0.85   # at or above this -> auto-approved
