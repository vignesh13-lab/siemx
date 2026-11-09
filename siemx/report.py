"""Roadmap 8 + 9: conversion report and pilot review results.

    siemx verdict <spl_file> --to kql --result correct|fixed|wrong --by <name>
        appends a human review to converted/<client>/_reviews.jsonl
    siemx report [--client c] [--mkdocs <dir>]
        writes converted/<client>/_report/report.md and summary.csv

Review results are ground truth for the pilot:
  correct  the generated query was right as it was
  fixed    usable after an edit (the edit can become a gold pair: siemx gold add)
  wrong    not usable
A review stores the hash of the query it judged. If the query changes later (a rule
or mapping changed), the review is shown as stale instead of being counted.

The threshold analysis only RECOMMENDS: CLAUDE.md says thresholds in config.py are
not changed silently.
"""
from __future__ import annotations

import csv
import io
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from . import config

RESULTS = ("correct", "fixed", "wrong")
THRESHOLDS = (0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.95)

# warning text -> category (first match wins); keeps the report readable
CATEGORIES = [
    ("LLM not available / failed", r"^LLM step failed"),
    ("no rule could convert it (rules-only mode)", r"rules-only mode, AI is off"),
    ("no translation produced", r"^validation: empty output"),
    ("preview function (dc)", r"count_distinctif\(\) \(exact\) is a preview"),
    ("field mapping: conditional", r"mapped to .* \(conditional"),
    ("field mapping: ambiguous", r"is ambiguous for"),
    ("field name not in table", r"not in \S+ \(mappings/fields\.json\)|no field list for"),
    ("field removed earlier", r"removed them"),
    ("row order", r"no defined order|dedup keeps the newest"),
    ("validation error", r"^validation:"),
    ("lookup table must exist", r"lookup '.*' must exist"),
    ("join subsearch limits", r"join subsearches are limited"),
    ("!= null handling", r"!= null handling"),
    ("XQL undocumented behaviour", r"^XQL.*(not documented|not stated|verify it keeps)"),
    ("dropped index", r"index=.* was dropped"),
    ("ELK: only a filter (stats etc. have no equivalent)", r"^ELK: Kibana KQL only selects"),
    ("ELK: no index pattern mapped", r"^ELK: (no index pattern|the SPL names no index)"),
    ("ELK: columns dropped (table/fields/sort)", r"^ELK: .* dropped: they choose or order"),
    ("ELK/SPL: case and whole-value matching", r"case-sensitively"),
    ("field names not mapped (ELK)", r"field names kept from (Splunk|Elastic|KQL|XQL)"),
    ("ELK: text vs keyword fields", r"^ELK: on text fields"),
    ("ELK: time range moved to the rule", r"^ELK: time range .* dropped"),
    ("ELK: empty string / missing field", r"also matches (an empty string|events without)"),
    ("SPL: no index pattern header", r"names no index pattern"),
    ("other rule caveat", r"."),
]


def reviews_file() -> Path:
    return config.OUT_DIR / "_reviews.jsonl"


def report_dir() -> Path:
    return config.OUT_DIR / "_report"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---- data ----------------------------------------------------------------------------------

def load_metas() -> list[dict]:
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(config.META_DIR.rglob("*.json"))]


def load_reviews() -> list[dict]:
    f = reviews_file()
    if not f.exists():
        return []
    return [json.loads(ln) for ln in f.read_text(encoding="utf-8").splitlines() if ln.strip()]


def add_review(meta: dict, result: str, by: str, notes: str = "") -> dict:
    if result not in RESULTS:
        raise ValueError(f"result must be one of {RESULTS}")
    if not by.strip():
        raise ValueError("--by is required: who reviewed it")
    row = {"src": meta["src"], "target": meta["target"], "result": result, "by": by,
           "notes": notes, "query_sha": meta.get("query_sha"), "ts": _now()}
    reviews_file().parent.mkdir(parents=True, exist_ok=True)
    with reviews_file().open("a", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(row) + "\n")
    return row


def latest_reviews(metas: list[dict], reviews: list[dict]) -> dict:
    """(src, target) -> {"review": latest review, "stale": bool}"""
    by_key = {}
    for r in reviews:                                   # later lines win
        by_key[(r["src"], r["target"])] = r
    sha = {(m["src"], m["target"]): m.get("query_sha") for m in metas}
    return {k: {"review": r, "stale": sha.get(k) != r.get("query_sha")} for k, r in by_key.items()}


def source_type(src: str) -> str:
    """detections/spl/<source>/... -> <source>"""
    parts = Path(src).parts
    return parts[2] if len(parts) > 3 else "(root)"


def category(warning: str) -> str:
    text = re.sub(r"^(KQL|XQL): ", "", warning)
    for name, pattern in CATEGORIES:
        if re.search(pattern, warning) or re.search(pattern, text):
            return name
    return "other"


# ---- sections ---------------------------------------------------------------------------------

def _table(header: list[str], rows: list[list]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    lines += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(lines)


def _pct(n: int, d: int) -> str:
    return f"{100 * n / d:.0f}%" if d else "-"


def summary_section(metas: list[dict]) -> str:
    rows = []
    for (src, target), group in sorted(_group(metas, lambda m: (source_type(m["src"]), m["target"])).items()):
        st = Counter(m["status"] for m in group)
        method = Counter("rules" if m.get("method") == "rules" else "llm" for m in group)
        rows.append([src, target, len(group), st["auto-approved"], st["needs-review"],
                     st["unsupported"], method["rules"], method["llm"]])
    return _table(["source", "target", "queries", "auto-approved", "needs-review", "unsupported",
                   "by rules", "by LLM"], rows)


def warnings_section(metas: list[dict]) -> str:
    c = Counter()
    for m in metas:
        for cat in {category(w) for w in m.get("warnings") or []}:
            c[(cat, m["target"])] += 1
    rows = [[cat, t, n] for (cat, t), n in c.most_common()]
    return _table(["reason", "target", "queries"], rows) if rows else "_No warnings._"


def missing_rules_section(metas: list[dict]) -> str:
    c = Counter()
    for m in metas:
        for cmd in set(m.get("no_rule") or []):
            c[cmd] += 1
    rows = [[f"`{cmd}`", n] for cmd, n in c.most_common()]
    return (_table(["SPL command without a rule", "queries it sent to the LLM"], rows)
            if rows else "_Every query was handled by rules._")


def reviews_section(metas: list[dict], reviewed: dict) -> str:
    meta_by_key = {(m["src"], m["target"]): m for m in metas}
    fresh = {k: v["review"] for k, v in reviewed.items() if not v["stale"] and k in meta_by_key}
    stale = sum(1 for v in reviewed.values() if v["stale"])
    if not fresh:
        return "_No reviews yet: record them with `siemx verdict`._" + (
            f" ({stale} stale review(s) of older outputs.)" if stale else "")

    def acc(keyfn):
        groups = defaultdict(Counter)
        for k, r in fresh.items():
            groups[keyfn(meta_by_key[k])][r["result"]] += 1
        rows = []
        for g, c in sorted(groups.items(), key=lambda x: str(x[0])):
            n = sum(c.values())
            rows.append([g, n, c["correct"], c["fixed"], c["wrong"], _pct(c["correct"], n)])
        return _table(["", "reviewed", "correct", "fixed", "wrong", "correct %"], rows)

    out = [f"{len(fresh)} reviewed outputs" + (f" ({stale} stale, not counted)" if stale else "") + ".",
           "", "**By status.** The key number: how often *auto-approved* was actually correct.", "",
           acc(lambda m: m["status"]), "", "**By method**", "", acc(lambda m: m.get("method") or "?"),
           "", "**By target**", "", acc(lambda m: m["target"])]
    by_cmd = defaultdict(Counter)
    for k, r in fresh.items():
        for cmd in set(meta_by_key[k].get("no_rule") or []) or {"(rules only)"}:
            by_cmd[cmd][r["result"]] += 1
    rows = [[f"`{cmd}`", sum(c.values()), c["correct"], c["fixed"], c["wrong"],
             _pct(c["correct"], sum(c.values()))] for cmd, c in sorted(by_cmd.items())]
    out += ["", "**By SPL command handled by the LLM**", "",
            _table(["command", "reviewed", "correct", "fixed", "wrong", "correct %"], rows)]
    return "\n".join(out)


def threshold_section(metas: list[dict], reviewed: dict) -> str:
    """What auto-approval of LLM output would look like at other thresholds."""
    pts = []
    for m in metas:
        r = reviewed.get((m["src"], m["target"]))
        if (m.get("method") or "").startswith("llm") and r and not r["stale"] \
                and m.get("confidence") is not None:
            pts.append((m["confidence"], bool(m.get("warnings")), r["review"]["result"]))
    if not pts:
        return "_Needs reviewed LLM outputs._"
    rows = []
    for t in THRESHOLDS:
        approved = [res for conf, warn, res in pts if conf >= t and not warn]
        wrong = sum(1 for res in approved if res != "correct")
        rows.append([f"{t:.2f}" + (" (current)" if t == config.CONF_AUTO_APPROVE else ""),
                     len(approved), wrong, _pct(len(approved) - wrong, len(approved))])
    return "\n".join([
        f"{len(pts)} reviewed LLM outputs. Auto-approval also needs *no warnings*.", "",
        _table(["threshold", "would be auto-approved", "of those not correct",
                "precision"], rows), "",
        "Pick the lowest threshold whose precision you accept; change `CONF_AUTO_APPROVE` in "
        "`siemx/config.py` in a reviewed PR (never silently)."])


def detail_rows(metas: list[dict], reviewed: dict) -> list[dict]:
    rows = []
    for m in metas:
        r = reviewed.get((m["src"], m["target"]))
        rows.append({"source": source_type(m["src"]), "src": m["src"], "target": m["target"],
                     "status": m["status"], "method": m.get("method"),
                     "confidence": m.get("confidence"), "warnings": len(m.get("warnings") or []),
                     "categories": "; ".join(sorted({category(w) for w in m.get("warnings") or []})),
                     "no_rule": " ".join(m.get("no_rule") or []),
                     "review": (r["review"]["result"] + (" (stale)" if r["stale"] else "")) if r else "",
                     "reviewed_by": r["review"]["by"] if r else ""})
    return rows


def _group(items, keyfn):
    g = defaultdict(list)
    for it in items:
        g[keyfn(it)].append(it)
    return g


# ---- build ---------------------------------------------------------------------------------------

def build(mkdocs: bool = False) -> tuple[str, str]:
    """-> (markdown, csv). mkdocs=True adds SIEM Hub front matter (type: doc)."""
    metas = load_metas()
    reviewed = latest_reviews(metas, load_reviews())
    client = config.CLIENT or "shared mappings"
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    md = []
    if mkdocs:
        sources = sorted({source_type(m["src"]) for m in metas}) or ["all"]
        md += ["---", f"title: siemx conversion report ({client})", "type: doc", "fmo: [all]",
               f"source_type: [{', '.join(sources)}]", "status: testing", "owner: SOC Detection Team",
               "summary: Conversion status, review results and next rules to build.",
               f"last_reviewed: {today}", "---", ""]
    md += [f"# siemx conversion report: {client}", "",
           f"Generated {today} by `siemx report`, converter version {config.CONVERTER_VERSION}.",
           f"{len(metas)} converted outputs.", "",
           "## Summary per source", "", summary_section(metas) if metas else "_Nothing converted yet._", "",
           "## Why outputs need review", "", warnings_section(metas), "",
           "## SPL commands without a rule", "",
           "Each row is a rule that, once written, moves these queries from the LLM to rules.", "",
           missing_rules_section(metas), "",
           "## Review results (pilot)", "", reviews_section(metas, reviewed), "",
           "## Auto-approval threshold for LLM output", "", threshold_section(metas, reviewed), ""]
    rows = detail_rows(metas, reviewed)
    buf = io.StringIO()
    fields = ["source", "src", "target", "status", "method", "confidence", "warnings",
              "categories", "no_rule", "review", "reviewed_by"]
    w = csv.DictWriter(buf, fieldnames=fields, lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    return "\n".join(md), buf.getvalue()


def pilot_sample(root: Path, n: int, seed: int = 7) -> list[Path]:
    """Stratified sample: proportional to each (source type, complexity) group, at least
    one per group, deterministic (same seed -> same list). A random sample of a large
    library would over-represent the most common, usually simplest, detections."""
    import random
    from .triage import complexity
    files = sorted(root.rglob("*.spl"))
    if n >= len(files):
        return files
    groups = defaultdict(list)
    for f in files:
        rel = f.relative_to(root)
        src = rel.parts[0] if len(rel.parts) > 1 else "(root)"
        groups[(src, complexity(f.read_text(encoding="utf-8", errors="replace")))].append(f)
    rng = random.Random(seed)
    quota = {k: max(1, round(n * len(v) / len(files))) for k, v in groups.items()}
    while sum(quota.values()) > n:                       # trim the largest groups first
        k = max(quota, key=lambda k: (quota[k], str(k)))
        quota[k] -= 1
    picked = []
    for k in sorted(groups):
        picked += rng.sample(groups[k], min(quota[k], len(groups[k])))
    return sorted(picked)


def write(mkdocs_dir: Path | None = None) -> dict:
    md, csv_text = build()
    d = report_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / "report.md").write_text(md, encoding="utf-8", newline="\n")
    (d / "summary.csv").write_text(csv_text, encoding="utf-8", newline="\n")
    out = {"report": str(d / "report.md"), "csv": str(d / "summary.csv")}
    if mkdocs_dir:
        mkdocs_dir.mkdir(parents=True, exist_ok=True)
        name = f"siemx-report-{config.CLIENT or 'shared'}.md"
        (mkdocs_dir / name).write_text(build(mkdocs=True)[0], encoding="utf-8", newline="\n")
        out["mkdocs"] = str(mkdocs_dir / name)
    return out
