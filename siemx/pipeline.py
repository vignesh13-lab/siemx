import hashlib
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import config, llm, rules, schema, triage, validate


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def convert_query(spl: str, target: str) -> dict:
    stages = triage.split_stages(spl)
    # 1) rules first
    head = rules.first_stage(stages[0], target)
    rest = [rules.stage(s, target) for s in stages[1:]]
    if head and all(r is not None for r in rest):
        parts = [head] + rest
        q = "\n| ".join(parts)
        # rules.Flagged parts carry warnings -> status_for() marks needs-review
        warnings = [w for part in parts for w in getattr(part, "warnings", [])]
        warnings += schema.check(parts, target)        # unknown field names -> review
        warnings += schema.order_check(parts, target)  # order-dependent stages -> review
        return {"query": q, "confidence": 0.9, "method": "rules", "warnings": warnings, "tokens": 0}
    # 2) LLM + RAG fallback with validation retry
    out = llm.translate(spl, target)
    out["method"] = "llm"
    for _ in range(2):
        problems = validate.check(out.get("query", ""), target)
        if not problems or out.get("unsupported"):
            break
        out = llm.translate(spl + f"\n\nPrevious attempt failed: {problems}", target)
        out["method"] = "llm-retry"
    out.setdefault("warnings", []).extend(validate.check(out.get("query", ""), target))
    return out


def status_for(res: dict) -> str:
    if res.get("unsupported") or not res.get("query"):
        return "unsupported"
    if res["warnings"] or res["confidence"] < config.CONF_AUTO_APPROVE:
        return "needs-review"
    return "auto-approved"


def is_current(meta_path, src_hash: str) -> bool:
    """True if this output was made from the same SPL by the same converter version."""
    if not meta_path.exists():
        return False
    m = json.loads(meta_path.read_text())
    return m.get("src_hash") == src_hash and m.get("converter") == config.CONVERTER_VERSION


def process_file(path, targets, force):
    spl = path.read_text()
    h = sha(spl)
    name = path.stem
    rel = path.relative_to(config.SRC_DIR).parent
    results = []
    for t in targets:
        meta_path = config.META_DIR / f"{name}.{t}.json"
        if not force and is_current(meta_path, h):
            results.append({"file": name, "target": t, "status": "skipped"})
            continue
        res = convert_query(spl, t)
        st = status_for(res)
        out_file = config.OUT_DIR / t / rel / f"{name}{config.EXT[t]}"
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(res.get("query", "") + "\n")
        config.META_DIR.mkdir(parents=True, exist_ok=True)
        meta = {"src": (config.SRC_REL / path.relative_to(config.SRC_DIR)).as_posix(),
                "src_hash": h, "converter": config.CONVERTER_VERSION, "target": t, "status": st,
                "complexity": triage.complexity(spl), "model": llm.MODEL,
                "ts": int(time.time()),
                **{k: res.get(k) for k in ("confidence", "method", "warnings", "tokens")}}
        meta_path.write_text(json.dumps(meta, indent=2))
        results.append({"file": name, "target": t, "status": st})
    return results


def run(targets, workers=4, force=False):
    files = sorted(config.SRC_DIR.rglob("*.spl"))
    print(f"found {len(files)} SPL files -> {','.join(targets)}", file=sys.stderr)
    counts = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(process_file, f, targets, force): f for f in files}
        for i, fut in enumerate(as_completed(futs), 1):
            for r in fut.result():
                counts[r["status"]] = counts.get(r["status"], 0) + 1
                print(json.dumps(r))          # one JSON line per result = the stream
            print(f"[{i}/{len(files)}] {futs[fut].name}", file=sys.stderr)
    return counts


def status():
    counts = {}
    for m in config.META_DIR.glob("*.json"):
        s = json.loads(m.read_text())["status"]
        counts[s] = counts.get(s, 0) + 1
    return counts


def review_list():
    metas = [json.loads(m.read_text()) for m in config.META_DIR.glob("*.json")]
    return [m for m in metas if m["status"] in ("needs-review", "unsupported")]
