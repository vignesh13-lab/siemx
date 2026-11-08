"""RAG + Claude fallback for stages the rules cannot handle."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from . import config

MODEL = os.environ.get("SIEMX_MODEL", "claude-sonnet-5-5")
NAMES = {"kql": "KQL (Microsoft Sentinel / Defender)", "xql": "XQL (Palo Alto Cortex XDR/XSIAM)"}

SYSTEM = (
    "You translate SIEM queries between languages. Use ONLY the reference "
    "material and examples provided for syntax. If there is no faithful "
    "equivalent, say so instead of guessing. Reply with JSON only."
)


def retrieve(spl: str, target: str) -> dict:
    """RAG context for the prompt: official doc chunks (retrieve.py, BM25 + name
    lookup, filtered to SPL + the target language). Empty when the index has not
    been built (`siemx docs fetch` + `siemx docs build`). 'examples' (gold/) comes
    with roadmap item 4."""
    from . import docs
    from . import retrieve as rag
    index = rag.get_index(docs.index_dir() / "chunks.jsonl")
    if index is None:
        return {"docs": [], "examples": []}
    return {"docs": rag.retrieve(index, spl, target).docs, "examples": []}


def build_prompt(spl: str, target: str) -> str:
    ctx = retrieve(spl, target)
    return (
        f"Translate this SPL to {NAMES[target]}.\n\nSPL:\n{spl}\n\n"
        f"Reference docs (official documentation excerpts; each has its source URL):\n"
        f"{json.dumps(ctx['docs'], ensure_ascii=False)}\n\n"
        f"Verified examples:\n{json.dumps(ctx['examples'])}\n\n"
        "Use only syntax shown in the reference docs. If something you need is not "
        "covered by them, add a warning instead of guessing.\n"
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


def translate(spl: str, target: str) -> dict:
    prompt = build_prompt(spl, target)
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
