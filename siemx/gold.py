"""Roadmap 4: gold examples - verified SPL -> KQL / XQL pairs used as few-shot examples.

gold/pairs.jsonl, one JSON object per line:
  id           "seed-001" (generated) or "rev-<n>" (added after human review)
  spl          the SPL query
  kql, xql     the verified translation, or null when that target is not verified
  notes        short remark (e.g. why a target is missing)
  verified_by  "docs+tests"  = produced by siemx rules whose mappings were checked against
                               the official docs and are covered by tests (not a human)
               "<name>"      = a person reviewed it (siemx gold add ... --by <name>)
  source       where it came from (rules version, or the converted file)
  added        date

Seeding is strict: a target is included only if NO rule raised a caveat (rules.Flagged)
for it. Field-name / row-order checks (schema.py) are ignored because examples show
SYNTAX; their field names are illustrative and the prompt says so.

Example retrieval: rank pairs by overlap of SPL commands/functions with the query
(Jaccard), then by shared words. `exclude_spl` drops an exact match so an evaluation
never retrieves the answer to the question it asks (leakage).
"""
from __future__ import annotations

import json
import re
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from . import config, validate

SEED_SOURCES = {"index=wineventlog": {"kql": "SecurityEvent", "xql": "dataset = xdr_data"}}
SEED_QUERIES = [
    "index=wineventlog | stats count by host | sort - count | head 10",
    "index=wineventlog | stats count as failures by user | where failures > 5",
    "index=wineventlog | stats sum(bytes) as total by src | sort - total",
    "index=wineventlog | stats max(bytes) as biggest, min(bytes) as smallest by dest",
    "index=wineventlog | stats avg(duration) as avg_dur by host",
    "index=wineventlog | stats dc(user) as users by host | where users > 10",
    "index=wineventlog | eval n = len(cmd) | where n > 100 | table host, cmd, n",
    "index=wineventlog | eval u = lower(user) | stats count by u",
    "index=wineventlog | eval h = upper(host) | table h",
    'index=wineventlog | eval result = if(status == 200, "ok", "error") | stats count by result',
    "index=wineventlog | eval ip = coalesce(src, dest) | stats count by ip",
    "index=wineventlog | eval kb = bytes / 1024 | where kb > 500",
    "index=wineventlog | where status >= 400 AND bytes > 1000",
    "index=wineventlog | table host, user, cmd",
    "index=wineventlog | fields - raw",
    "index=wineventlog | rename src AS source_ip | table source_ip",
    "index=wineventlog | dedup host | table host, user",
    'index=wineventlog | rex field=cmd "user=(?<account>\\w+)" | stats count by account',
    "index=wineventlog | top 5 user showperc=f",
    "index=wineventlog | timechart span=1h cont=f count",
    "index=wineventlog | sort - bytes, host | head 20",
    "index=wineventlog EventID=4625 | stats count by user",
    "index=wineventlog EventID=4625 user=adm* | stats count by host",
    "index=wineventlog NOT user=SYSTEM | stats count by user",
    "index=wineventlog EventID IN (4624, 4625) | stats count by EventID",
]


def pairs_file() -> Path:
    return config.GOLD_DIR / "pairs.jsonl"


def load(path: Path | None = None) -> list[dict]:
    path = path or pairs_file()
    if not path.exists():
        return []
    return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def save(pairs: list[dict], path: Path | None = None) -> None:
    path = path or pairs_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(p, ensure_ascii=False) + "\n" for p in pairs),
                    encoding="utf-8", newline="\n")


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


# ---- seeding from the rules -------------------------------------------------------------

@contextmanager
def _seed_mapping():
    """Use a fixed sample mapping (and no client) while generating seeds."""
    from . import rules
    old_map, old_client = rules.MAP_FILE, config.CLIENT
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "sources.json"
        f.write_text(json.dumps(SEED_SOURCES))
        rules.MAP_FILE, config.CLIENT = f, None
        try:
            yield
        finally:
            rules.MAP_FILE, config.CLIENT = old_map, old_client


def rule_translation(spl: str, target: str) -> tuple[str | None, list[str]]:
    """Rules-only translation. -> (query, caveats); query is None if a stage has no rule.
    Caveats are rule-level warnings (rules.Flagged); schema checks are not included."""
    from . import mappings, pipeline, rules, triage
    stages = triage.split_stages(mappings.expand_macros(spl))
    parts = [rules.first_stage(stages[0], target)] + [rules.stage(s, target) for s in stages[1:]]
    if any(p is None for p in parts):
        return None, []
    caveats = [w for p in parts for w in getattr(p, "warnings", [])]
    return "\n| ".join(pipeline.render_parts(parts)), caveats


def seed(queries: list[str] = SEED_QUERIES) -> list[dict]:
    out = []
    with _seed_mapping():
        for i, spl in enumerate(queries, 1):
            row = {"id": f"seed-{i:03d}", "spl": spl, "kql": None, "xql": None, "notes": "",
                   "verified_by": "docs+tests",
                   "source": f"siemx rules (converter {config.CONVERTER_VERSION})",
                   "added": _today()}
            skipped = []
            for t in ("kql", "xql"):
                query, caveats = rule_translation(spl, t)
                invalid = validate.check(query, t, scope="rules") if query else []
                if query is not None and not caveats and not invalid:
                    row[t] = query
                else:
                    why = "no rule" if query is None else "rule caveat" if caveats else "invalid"
                    skipped.append(f"{t}: {why}")
            if skipped:
                row["notes"] = "not verified -> " + "; ".join(skipped)
            if row["kql"] or row["xql"]:
                out.append(row)
    return out


def merge_seeds(existing: list[dict], seeds: list[dict]) -> list[dict]:
    """Replace generated rows, keep human-reviewed rows."""
    return seeds + [p for p in existing if not p["id"].startswith("seed-")]


# ---- adding a reviewed conversion ------------------------------------------------------------

def add_reviewed(pairs: list[dict], spl: str, target: str, query: str, by: str,
                 source: str, notes: str = "") -> dict:
    if not by.strip():
        raise ValueError("--by is required: who reviewed this translation")
    norm = normalize(spl)
    for p in pairs:                                   # same SPL already present: update target
        if normalize(p["spl"]) == norm and not p["id"].startswith("seed-"):
            p[target], p["verified_by"], p["source"], p["added"] = query, by, source, _today()
            if notes:
                p["notes"] = notes
            return p
    n = 1 + sum(1 for p in pairs if p["id"].startswith("rev-"))
    row = {"id": f"rev-{n:03d}", "spl": spl, "kql": None, "xql": None, "notes": notes,
           "verified_by": by, "source": source, "added": _today()}
    row[target] = query
    pairs.append(row)
    return row


# ---- example retrieval -----------------------------------------------------------------------

def normalize(spl: str) -> str:
    return re.sub(r"\s+", " ", spl.strip())


def spl_features(spl: str) -> set[str]:
    """Commands + functions used after the base search, e.g. {'eval', 'len', 'where'}."""
    from .retrieve import spl_names
    from .triage import split_stages
    return {n for st in split_stages(spl)[1:] for n in spl_names(st)}


def _words(spl: str) -> set[str]:
    from .retrieve import tokens
    return set(tokens(spl))


def similar(pairs: list[dict], spl: str, target: str, k: int = 3,
            exclude_spl: str | None = None) -> list[tuple[float, dict]]:
    """Top-k pairs that have a `target` translation, most similar first."""
    feats, words = spl_features(spl), _words(spl)
    skip = normalize(exclude_spl) if exclude_spl else None
    scored = []
    for p in pairs:
        if not p.get(target) or (skip and normalize(p["spl"]) == skip):
            continue
        pf = spl_features(p["spl"])
        union = feats | pf
        jaccard = len(feats & pf) / len(union) if union else 0.0
        overlap = len(words & _words(p["spl"])) / (len(words) or 1)
        score = jaccard + 0.1 * overlap                 # commands/functions first, words break ties
        if feats & pf:
            scored.append((score, p))
    scored.sort(key=lambda x: (-x[0], x[1]["id"]))
    return scored[:k]


def examples_for_prompt(spl: str, target: str, k: int = 3,
                        exclude_spl: str | None = None, source: str = "spl") -> list[dict]:
    if source != "spl":
        return [{source: p[source], "spl": p["spl"], "verified_by": p["verified_by"],
                 "notes": p.get("notes", "")}
                for _, p in similar_reverse(load(), spl, source, k, exclude_spl)]
    return [{"spl": p["spl"], target: p[target], "verified_by": p["verified_by"],
             "notes": p.get("notes", "")}
            for _, p in similar(load(), spl, target, k, exclude_spl)]


def kql_features(kql: str) -> set[str]:
    """Operators + functions after the table, e.g. {'summarize', 'count', 'top'}."""
    from .retrieve import kql_names
    from .reverse import split_pipes
    return {n for st in split_pipes(kql)[1:] for n in kql_names(st)}


def similar_reverse(pairs: list[dict], query: str, source: str, k: int = 3,
                    exclude: str | None = None) -> list[tuple[float, dict]]:
    """Gold pairs read backwards: rank by shared KQL operators/functions."""
    feats = kql_features(query)
    skip = normalize(exclude) if exclude else None
    scored = []
    for p in pairs:
        if not p.get(source) or (skip and normalize(p[source]) == skip):
            continue
        pf = kql_features(p[source])
        union = feats | pf
        if feats & pf:
            scored.append((len(feats & pf) / len(union), p))
    scored.sort(key=lambda x: (-x[0], x[1]["id"]))
    return scored[:k]


def check(pairs: list[dict]) -> list[dict]:
    """Regression: for rule-generated pairs, do the rules still give the same answer,
    and does it still pass validation (official KQL parser / XQL names)?"""
    problems = []
    with _seed_mapping():
        for p in pairs:
            if p["verified_by"] != "docs+tests":
                continue
            for t in ("kql", "xql"):
                if not p.get(t):
                    continue
                now, caveats = rule_translation(p["spl"], t)
                invalid = validate.check(p[t], t, scope="rules")
                if now != p[t] or caveats or invalid:
                    problems.append({"id": p["id"], "target": t, "gold": p[t], "now": now,
                                     "caveats": caveats + invalid})
    return problems
