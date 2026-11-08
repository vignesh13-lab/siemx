"""RAG + Claude fallback for stages the rules cannot handle."""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

from . import config

MODEL = os.environ.get("SIEMX_MODEL", "claude-sonnet-5-5")
NAMES = {"kql": "KQL (Microsoft Sentinel / Defender)", "xql": "XQL (Palo Alto Cortex XDR/XSIAM)",
         "spl": "SPL (Splunk)"}

SYSTEM = (
    "You translate SIEM queries between languages. Use ONLY the reference "
    "material and examples provided for syntax. If there is no faithful "
    "equivalent, say so instead of guessing. Reply with JSON only."
)


EXAMPLES_K = 3


def retrieve(spl: str, target: str, source: str = "spl") -> dict:
    """RAG context for the prompt:
    docs     official doc chunks (retrieve.py: name lookup, bridge, BM25 + vectors),
             empty when the index is not built (`siemx docs fetch` + `docs build`)
    examples the most similar verified pairs from gold/pairs.jsonl (gold.py); for
             KQL -> SPL the same pairs read backwards"""
    from . import docs, gold
    from . import retrieve as rag
    examples = gold.examples_for_prompt(spl, target, k=EXAMPLES_K, source=source)
    fields = field_hints(spl, target) if source == "spl" else {}
    index = rag.get_index(docs.index_dir() / "chunks.jsonl")
    if index is None:
        return {"docs": [], "examples": examples, "field_map": fields}
    return {"docs": rag.retrieve(index, spl, target, source=source).docs,
            "examples": examples, "field_map": fields}


def field_hints(spl: str, target: str) -> dict:
    """Field-map entries (mappings/field_map.json) for field names used in this SPL,
    when the base search maps to a known table."""
    from . import fieldmap, rules, triage
    first = rules.first_stage(triage.split_stages(spl)[0], target)
    table = getattr(first, "table", None)
    if not table:
        return {}
    used = set(re.findall(r"[A-Za-z_][A-Za-z0-9_.]*", spl))
    entries = {k: v for k, v in fieldmap.table_map(target, table).items() if k in used}
    return {"table": table, "fields": entries} if entries else {}


def build_prompt(spl: str, target: str, source: str = "spl", base: str | None = None) -> str:
    if source != "spl":
        return build_reverse_prompt(spl, target, source, base)
    ctx = retrieve(spl, target)
    return (
        f"Translate this SPL to {NAMES[target]}.\n\nSPL:\n{spl}\n\n"
        f"Reference docs (official documentation excerpts; each has its source URL):\n"
        f"{json.dumps(ctx['docs'], ensure_ascii=False)}\n\n"
        "Verified examples (similar SPL already translated and checked; they show SYNTAX - "
        "their table and field names are illustrative, do not copy them):\n"
        f"{json.dumps(ctx['examples'], ensure_ascii=False)}\n\n"
        "Field mapping for this table (SPL field -> target column; level exact = apply, "
        "conditional = apply and add a warning with the note, ambiguous = do NOT choose, "
        "add a warning naming the candidates):\n"
        f"{json.dumps(ctx.get('field_map', {}), ensure_ascii=False)}\n\n"
        "Use only syntax shown in the reference docs or the verified examples. If something "
        "you need is not covered by them, add a warning instead of guessing.\n"
        f"{FORWARD_PITFALLS.get(target, '')}"
        'Return JSON: {"query": str, "confidence": 0-1, "warnings": [str], '
        '"unsupported": bool, "sources": [the URLs of the docs you relied on]}'
    )


# Target-specific facts for the forward prompt. KQL has none, so its prompt text (and its
# cached answers) stay unchanged.
FORWARD_PITFALLS = {
    "xql": ("XQL string comparison is case-insensitive by default; SPL where/eval comparison "
            "is case-sensitive (search terms are not). If the SPL compares strings in where or "
            "eval, start the XQL with `config case_sensitive = true`.\n"),
}


REVERSE_PITFALLS = {
    "kql": "KQL sort is descending by default;",
    "xql": ("XQL string comparison is case-insensitive unless `config case_sensitive = true` "
            "while SPL where/eval comparison is case-sensitive; in XQL \"...\" strings * is a "
            "wildcard; XQL `config timeframe` is the time range (M = minutes);"),
}


def build_reverse_prompt(text: str, target: str, source: str, base: str | None) -> str:
    """KQL -> SPL. The SPL base search comes from mappings/sources.json, so the model
    never has to invent an index or sourcetype."""
    ctx = retrieve(text, target, source=source)
    return (
        f"Translate this {NAMES[source]} query to {NAMES[target]}.\n\n"
        f"{source.upper()}:\n{text}\n\n"
        f"Start the SPL with exactly this base search for the table's data: {base}\n"
        "Keep the column names as they are (they are mapped separately).\n\n"
        f"Reference docs (official documentation excerpts; each has its source URL):\n"
        f"{json.dumps(ctx['docs'], ensure_ascii=False)}\n\n"
        "Verified examples (pairs already translated and checked; they show SYNTAX - "
        "their table and field names are illustrative, do not copy them):\n"
        f"{json.dumps(ctx['examples'], ensure_ascii=False)}\n\n"
        "Use only syntax shown in the reference docs or the verified examples. Mind the "
        f"differences: {REVERSE_PITFALLS[source]} SPL sort keeps 10,000 rows unless "
        "`sort 0`; SPL stats drops events whose by-field is missing. If something has no "
        "faithful SPL equivalent, add a warning instead of guessing.\n"
        'Return JSON: {"query": str, "confidence": 0-1, "warnings": [str], '
        '"unsupported": bool, "sources": [the URLs of the docs you relied on]}'
    )


# ---- cache -----------------------------------------------------------------------
# CLAUDE.md: "Cache LLM results by query hash". The key covers everything that
# changes the answer (model, system prompt, full prompt incl. retrieved docs and
# examples), so better context later produces a new key. Only well-formed
# answers are cached; failures (no key, API error, bad JSON) are retried.
# Stored under converted/ so the CI bot PR carries the cache between runs.

def cache_dir() -> Path:
    return config.OUT_DIR / "_cache" / "llm"


def cache_key(prompt: str) -> str:
    blob = json.dumps({"model": MODEL, "system": SYSTEM, "prompt": prompt}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


def _cache_get(key: str) -> dict | None:
    f = cache_dir() / f"{key}.json"
    if not f.exists():
        return None
    out = json.loads(f.read_text(encoding="utf-8"))
    out.update(cached=True, tokens=0)
    return out


def _cache_put(key: str, out: dict) -> None:
    d = cache_dir()
    d.mkdir(parents=True, exist_ok=True)
    tmp = d / f"{key}.json.tmp"
    tmp.write_text(json.dumps(out, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, d / f"{key}.json")      # atomic: workers run in parallel


def _well_formed(out) -> bool:
    return (isinstance(out, dict) and isinstance(out.get("query"), str)
            and isinstance(out.get("confidence"), (int, float))
            and isinstance(out.get("warnings", []), list))


def call_model(prompt: str) -> dict:
    """One Anthropic call -> parsed JSON dict (raises on any failure)."""
    import anthropic
    client = anthropic.Anthropic()
    resp = client.messages.create(
        model=MODEL, max_tokens=2000, system=SYSTEM,
        messages=[{"role": "user", "content": prompt}],
    )
    text = resp.content[0].text.strip().removeprefix("```json").removesuffix("```").strip()
    out = json.loads(text)
    out["tokens"] = resp.usage.input_tokens + resp.usage.output_tokens
    return out


def translate(spl: str, target: str, source: str = "spl", base: str | None = None) -> dict:
    prompt = build_prompt(spl, target, source=source, base=base)
    key = cache_key(prompt)
    cached = _cache_get(key)
    if cached is not None:
        return cached
    try:
        out = call_model(prompt)
        if not _well_formed(out):
            raise ValueError("response is missing query/confidence/warnings")
    except Exception as e:  # no key, bad JSON, API error -> send to review (not cached)
        return {"query": "", "confidence": 0.0, "unsupported": True,
                "warnings": [f"LLM step failed: {e}"], "tokens": 0}
    out.setdefault("warnings", [])
    _cache_put(key, out)
    return out
