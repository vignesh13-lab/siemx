import hashlib
from pathlib import Path
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import config, fieldmap, llm, mappings, rules, schema, triage, validate


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def render_parts(parts: list) -> list[str]:
    """Query text per stage. A sort's implicit SPL limit (10,000) is dropped when
    the next stage is a head that takes no more rows than that limit."""
    out = []
    for i, part in enumerate(parts):
        nxt = parts[i + 1] if i + 1 < len(parts) else None
        limit, take_n = getattr(part, "limit", None), getattr(nxt, "take_n", None)
        if limit and take_n is not None and take_n <= limit:
            out.append(part.without_limit)
        else:
            out.append(str(part))
    return out


def rule_parts(spl: str, target: str) -> list | None:
    """Rules for every stage, or None if some stage has no rule."""
    stages = triage.split_stages(spl)
    head = rules.first_stage(stages[0], target)
    rest = [rules.stage(s, target) for s in stages[1:]]
    if head is None or any(r is None for r in rest):
        return None
    return [head] + rest


def missing_rules(spl: str, target: str) -> list[str]:
    """SPL commands whose stage has no rule ('search' = the base search). For reports:
    which rules would convert the most detections."""
    stages = triage.split_stages(spl)
    out = [] if rules.first_stage(stages[0], target) is not None else ["search"]
    for s in stages[1:]:
        if rules.stage(s, target) is None:
            out.append(triage.command_of(s) or "?")
    return out


def apply_field_map(spl: str, parts: list, target: str) -> tuple[str, list, list[str], dict]:
    """Rename source fields the table does not have, using mappings/field_map.json.
    -> (spl, parts, warnings, applied). Unchanged when nothing applies."""
    reads = schema.field_reads(parts, target)
    p = fieldmap.plan(reads["unknown"], reads["created"], target, reads["table"])
    if not p["renames"]:
        return spl, parts, p["warnings"], {}
    new_spl = fieldmap.rename_in_spl(spl, p["renames"])
    new_parts = rule_parts(new_spl, target)
    if new_parts is None:                       # should not happen; keep the original
        return spl, parts, p["warnings"], {}
    return new_spl, new_parts, p["warnings"], p["applied"]


def convert_query(spl: str, target: str) -> dict:
    spl = mappings.expand_macros(spl)        # client/shared Splunk macros
    # 1) rules first
    parts = rule_parts(spl, target)
    if parts is not None:
        spl, parts, map_warnings, applied = apply_field_map(spl, parts, target)
        q = "\n| ".join(render_parts(parts))
        # rules.Flagged parts carry warnings -> status_for() marks needs-review
        warnings = [w for part in parts for w in getattr(part, "warnings", [])]
        warnings += map_warnings                       # conditional / ambiguous field names
        warnings += schema.check(parts, target)        # unknown field names -> review
        warnings += schema.order_check(parts, target)  # order-dependent stages -> review
        # safety net for bugs in our own rules (column errors are left to schema.check)
        warnings += [f"validation: {p}" for p in validate.check(q, target, scope="rules")]
        return {"query": q, "confidence": 0.9, "method": "rules", "warnings": warnings,
                "tokens": 0, "validator": validate.status()[target], "field_map": applied}
    # 2) LLM + RAG fallback; the validator's exact errors go back to the model
    out = llm_with_retry(spl, target)
    out["no_rule"] = missing_rules(spl, target)
    return out


def llm_with_retry(text: str, target: str, source: str = "spl", base: str | None = None) -> dict:
    """LLM translation, validated; the exact problems go back to the model (MAX_RETRIES)."""
    out = llm.translate(text, target, source=source, base=base)
    out["method"] = "llm"
    for _ in range(MAX_RETRIES):
        problems = validate.check(out.get("query", ""), target)
        if not problems or out.get("unsupported"):
            break
        out = llm.translate(retry_request(text, target, out.get("query", ""), problems), target,
                            source=source, base=base)
        out["method"] = "llm-retry"
    out.setdefault("warnings", []).extend(
        f"validation: {p}" for p in validate.check(out.get("query", ""), target))
    out["validator"] = validate.status()[target]
    return out


MAX_RETRIES = 2


def retry_request(spl: str, target: str, previous: str, problems: list[str]) -> str:
    """Retry text for the model: its previous query and the validator's exact errors."""
    listed = "\n".join(f"- {p}" for p in problems)
    return (f"{spl}\n\nYour previous {target.upper()} translation was:\n{previous}\n\n"
            f"The validator reported:\n{listed}\n\nReturn a corrected translation.")


def status_for(res: dict) -> str:
    if res.get("unsupported") or not res.get("query"):
        return "unsupported"
    if res["warnings"] or res["confidence"] < config.CONF_AUTO_APPROVE:
        return "needs-review"
    return "auto-approved"


def mappings_hash() -> str:
    """Fingerprint of everything outside the SPL file that changes the output:
    sources (shared + client), macros (shared + client) and the field lists."""
    fields = config.FIELDS_FILE.read_bytes() if config.FIELDS_FILE.exists() else b""
    blob = json.dumps({"sources": rules._load_sources(), "macros": mappings.load_macros(),
                       "field_map": fieldmap.load_all(),
                       "fields": hashlib.sha256(fields).hexdigest()}, sort_keys=True)
    return sha(blob)


def is_current(meta_path, src_hash: str, map_hash: str) -> bool:
    """True if this output was made from the same SPL, converter version and mappings."""
    if not meta_path.exists():
        return False
    m = json.loads(meta_path.read_text())
    return (m.get("src_hash") == src_hash and m.get("converter") == config.CONVERTER_VERSION
            and m.get("mappings_hash") == map_hash)


SOURCES = {"spl": ".spl", "kql": ".kql", "xql": ".xql"}     # input language -> file extension


def source_dir(source: str = "spl") -> tuple[Path, Path]:
    """(absolute folder, repo-relative folder) of the input files: detections/<source>."""
    if source == "spl":
        return config.SRC_DIR, config.SRC_REL
    return config.SRC_DIR.parent / source, config.SRC_REL.parent / source


def meta_path_for(path, target: str, source: str = "spl"):
    """converted/_meta/<same folders as detections/<source>>/<name>.<target>.json, so files
    with the same name in different folders do not overwrite each other."""
    rel = path.relative_to(source_dir(source)[0])
    return config.META_DIR / rel.parent / f"{rel.stem}.{target}.json"


def convert_any(text: str, target: str, source: str = "spl") -> dict:
    if source == "spl":
        return convert_query(text, target)
    if source in ("kql", "xql") and target == "spl":
        from . import reverse, reverse_xql
        res = (reverse if source == "kql" else reverse_xql).convert(text)
        if res.get("unsupported") and res.get("llm_base"):
            rule_gap, table = res["warnings"], res.get("llm_table")
            res = llm_with_retry(text, "spl", source=source, base=res["llm_base"])
            res["no_rule"] = [w.removeprefix("not converted: ") for w in rule_gap]
            if not res.get("unsupported"):
                # the model keeps the source column names (as told); a person must map them
                kind = "KQL table" if source == "kql" else "XQL dataset"
                res.setdefault("warnings", []).append(
                    f"SPL: LLM translation keeps the {kind}'s column names ({table}); "
                    "map them to your Splunk field names")
        return res
    raise ValueError(f"no conversion from {source} to {target}")


def process_file(path, targets, force, map_hash=None, source="spl"):
    spl = path.read_text()
    h = sha(spl)
    map_hash = map_hash or mappings_hash()
    name = path.stem
    src_dir, src_rel = source_dir(source)
    rel = path.relative_to(src_dir).parent
    shown = (rel / name).as_posix()
    results = []
    for t in targets:
        meta_path = meta_path_for(path, t, source)
        if not force and is_current(meta_path, h, map_hash):
            results.append({"file": shown, "target": t, "status": "skipped"})
            continue
        res = convert_any(spl, t, source)
        st = status_for(res)
        out_file = config.OUT_DIR / t / rel / f"{name}{config.EXT[t]}"
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(res.get("query", "") + "\n")
        meta_path.parent.mkdir(parents=True, exist_ok=True)
        meta = {"src": (src_rel / path.relative_to(src_dir)).as_posix(), "source": source,
                "client": config.CLIENT, "mappings_hash": map_hash,
                "src_hash": h, "converter": config.CONVERTER_VERSION, "target": t, "status": st,
                "complexity": triage.complexity(spl),
                "model": llm.MODEL if res.get("method", "").startswith("llm") else None,
                "cached": bool(res.get("cached")),
                "ts": int(time.time()), "query_sha": sha(res.get("query", "")),
                **{k: res.get(k) for k in ("confidence", "method", "warnings", "tokens",
                                           "validator", "field_map", "no_rule")}}
        meta_path.write_text(json.dumps(meta, indent=2))
        results.append({"file": shown, "target": t, "status": st})
    return results


def run(targets, workers=4, force=False, path=None, source="spl"):
    """Convert detections/<source>/** (or only detections/<source>/<path>/**)."""
    base = source_dir(source)[0]
    root = base / path if path else base
    files = sorted(root.rglob("*" + SOURCES[source]))
    print(f"found {len(files)} {source.upper()} files -> {','.join(targets)}", file=sys.stderr)
    counts = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        map_hash = mappings_hash()            # once per run, not per file
        futs = {pool.submit(process_file, f, targets, force, map_hash, source): f for f in files}
        for i, fut in enumerate(as_completed(futs), 1):
            for r in fut.result():
                counts[r["status"]] = counts.get(r["status"], 0) + 1
                print(json.dumps(r))          # one JSON line per result = the stream
            print(f"[{i}/{len(files)}] {futs[fut].name}", file=sys.stderr)
    return counts


def status():
    counts = {}
    for m in config.META_DIR.rglob("*.json"):
        s = json.loads(m.read_text())["status"]
        counts[s] = counts.get(s, 0) + 1
    return counts


def review_list():
    metas = [json.loads(m.read_text()) for m in config.META_DIR.rglob("*.json")]
    return [m for m in metas if m["status"] in ("needs-review", "unsupported")]
