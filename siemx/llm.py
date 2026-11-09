"""RAG + LLM fallback for stages the rules cannot handle.

The model is a setting (environment variables, read at call time), not code:

  SIEMX_PROVIDER  anthropic (default) | ollama | openai | none
                  none = rules-only mode: no AI; queries without a rule are unsupported
                  (also `siemx convert --no-ai`)
  SIEMX_MODEL     model name; required for ollama / openai
                    anthropic: default claude-sonnet-5-5, key in ANTHROPIC_API_KEY
                    ollama:    e.g. qwen2.5-coder:7b (local, no key, nothing leaves the PC)
                    openai:    any OpenAI-compatible chat API (OpenAI, Azure OpenAI v1
                               endpoint, company gateways, vLLM, LM Studio)
  SIEMX_BASE_URL  ollama: default http://localhost:11434 ; openai: default
                  https://api.openai.com/v1
  SIEMX_API_KEY   key for openai (falls back to OPENAI_API_KEY)
  SIEMX_NUM_CTX   ollama context window in tokens (default 16384). Ollama's own default
                  is small and it silently cuts long prompts; a cut prompt is reported.
  SIEMX_TIMEOUT   seconds per request (default 600: local models are slow)

Every result records which model produced it, and the cache key includes it, so
switching models never reuses another model's answers.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

from . import config

MODEL = os.environ.get("SIEMX_MODEL") or "claude-sonnet-5-5"     # anthropic default
PROVIDERS = ("anthropic", "ollama", "openai", "none")
DEFAULT_URLS = {"ollama": "http://localhost:11434", "openai": "https://api.openai.com/v1"}


def settings() -> dict:
    """The current model setting, from the environment (empty values = unset)."""
    env = {k: (os.environ.get(k) or "").strip() for k in
           ("SIEMX_PROVIDER", "SIEMX_MODEL", "SIEMX_BASE_URL", "SIEMX_NUM_CTX", "SIEMX_TIMEOUT")}
    provider = (env["SIEMX_PROVIDER"] or "anthropic").lower()
    if provider not in PROVIDERS:
        raise ValueError(f"SIEMX_PROVIDER={provider!r}: use one of {', '.join(PROVIDERS)}")
    model = env["SIEMX_MODEL"] or (MODEL if provider == "anthropic" else "")
    return {"provider": provider, "model": model,
            "base_url": (env["SIEMX_BASE_URL"] or DEFAULT_URLS.get(provider, "")).rstrip("/"),
            "num_ctx": int(env["SIEMX_NUM_CTX"] or 16384),
            "timeout": float(env["SIEMX_TIMEOUT"] or 600)}


def model_id() -> str:
    """Recorded in each result's metadata: 'claude-sonnet-5-5', 'ollama:qwen2.5-coder:7b'."""
    try:
        s = settings()
    except ValueError:
        return "invalid SIEMX_PROVIDER"
    return s["model"] if s["provider"] == "anthropic" else f"{s['provider']}:{s['model']}"
NAMES = {"kql": "KQL (Microsoft Sentinel / Defender)", "xql": "XQL (Palo Alto Cortex XDR/XSIAM)",
         "spl": "SPL (Splunk)",
         "elk": "Kibana Query Language (Elastic; not Microsoft KQL)"}

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
    if "elk" in (target, source):
        # no Elastic docs in the RAG index: one page covers the language (elk.REFERENCE)
        from .elk import REFERENCE
        examples = gold.examples_for_prompt(spl, target, k=EXAMPLES_K) if source == "spl" else []
        return {"docs": [REFERENCE], "examples": examples, "field_map": {}}
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
    if target == "elk":
        return {}
    first = rules.first_stage(triage.split_stages(spl)[0], target)
    table = getattr(first, "table", None)
    if not table:
        return {}
    used = set(re.findall(r"[A-Za-z_][A-Za-z0-9_.]*", spl))
    entries = {k: v for k, v in fieldmap.table_map(target, table).items() if k in used}
    return {"table": table, "fields": entries} if entries else {}


def build_prompt(spl: str, target: str, source: str = "spl", base: str | None = None) -> str:
    if source != "spl" and target == "elk":
        return build_to_elk_prompt(spl, source)
    if source == "elk" and target in ("kql", "xql"):
        return build_from_elk_prompt(spl, target, base)
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
        f"{FORWARD_PITFALLS.get(target, '')}{_placeholder_line(spl, target)}"
        'Return JSON: {"query": str, "confidence": 0-1, "warnings": [str], '
        '"unsupported": bool, "sources": [the URLs of the docs you relied on]}'
    )


def _placeholder_line(spl: str, target: str) -> str:
    """Unmapped Splunk source: the model must use the editable placeholder, not invent a
    table. Empty for mapped sources, so their prompts (and cached answers) do not change."""
    from . import rules
    if target not in ("kql", "xql"):
        return ""
    unmapped = rules.unmapped_source(spl, target)
    if not unmapped:
        return ""
    return (f"The Splunk source is not mapped: start the query with exactly `{unmapped[0]}` "
            "(a placeholder the analyst replaces); do not choose a table yourself.\n")


# Target-specific facts for the forward prompt. KQL has none, so its prompt text (and its
# cached answers) stay unchanged.
FORWARD_PITFALLS = {
    "xql": ("XQL string comparison is case-insensitive by default; SPL where/eval comparison "
            "is case-sensitive (search terms are not). If the SPL compares strings in where or "
            "eval, start the XQL with `config case_sensitive = true`.\n"),
    "elk": ("Kibana KQL only filters events. If the SPL needs stats, eval, dedup, transaction "
            "or any other transforming command, answer unsupported. Return one Kibana KQL "
            "filter with no pipes and no index; keep the SPL field names; quote values without "
            "wildcards; parenthesize mixed and/or.\n"),
}


REVERSE_PITFALLS = {
    "kql": "KQL sort is descending by default;",
    "elk": ("Kibana KQL `field: value` matches keyword fields exactly and case-sensitively "
            "and text fields by words, while SPL field=value is whole-value and "
            "case-insensitive; in Kibana KQL * inside quotes is a literal asterisk;"),
    "xql": ("XQL string comparison is case-insensitive unless `config case_sensitive = true` "
            "while SPL where/eval comparison is case-sensitive; in XQL \"...\" strings * is a "
            "wildcard; XQL `config timeframe` is the time range (M = minutes);"),
}


TO_ELK_PITFALLS = {
    "kql": ("KQL == != in are case-sensitive; =~ !~ in~ contains startswith endswith has are "
            "case-insensitive; Kibana KQL keyword fields are case-sensitive, so add a warning "
            "for every case-insensitive comparison."),
    "xql": ("XQL string comparison is case-insensitive unless `config case_sensitive = true` and "
            "* inside XQL \"...\" is a wildcard; Kibana KQL keyword fields are case-sensitive, "
            "so add a warning for every case-insensitive comparison."),
}


def build_to_elk_prompt(text: str, source: str) -> str:
    """KQL / XQL -> Kibana KQL: only the event filter; transforming stages never reach the
    model (to_elk.py marks them unsupported first)."""
    ctx = retrieve(text, "elk", source=source)
    return (
        f"Translate the event filter of this {NAMES[source]} query to {NAMES['elk']}.\n\n"
        f"{source.upper()}:\n{text}\n\n"
        "Return one Kibana KQL filter: no table or index, no pipes. Keep the column names as "
        "they are (they are mapped separately). Drop time ranges (they belong to the Elastic "
        "rule) and add a warning saying so.\n\n"
        f"Reference docs (each has its source URL):\n{json.dumps(ctx['docs'], ensure_ascii=False)}"
        "\n\nUse only syntax shown in the reference. "
        f"{TO_ELK_PITFALLS[source]} If something has no faithful Kibana KQL equivalent, answer "
        "unsupported instead of guessing.\n"
        'Return JSON: {"query": str, "confidence": 0-1, "warnings": [str], '
        '"unsupported": bool, "sources": [the URLs of the docs you relied on]}'
    )


FROM_ELK_PITFALLS = {
    "kql": ("Kibana KQL keyword matching is exact and case-sensitive: use ==, in, contains_cs, "
            "startswith_cs, endswith_cs (not =~ or contains)."),
    "xql": ("Kibana KQL keyword matching is case-sensitive and XQL is not by default: start "
            "with `config case_sensitive = true`. In XQL \"...\" a * is a wildcard. Always "
            "parenthesize mixed and/or (XQL does not document their precedence)."),
}


def build_from_elk_prompt(text: str, target: str, base: str | None) -> str:
    """Kibana KQL -> KQL / XQL. The table / dataset comes from mappings/sources.json."""
    ctx = retrieve(text, target, source="elk")
    return (
        f"Translate this {NAMES['elk']} filter to {NAMES[target]}.\n\n"
        f"Kibana KQL:\n{text}\n\n"
        f"Query exactly this {'table' if target == 'kql' else 'dataset'}: {base}\n"
        "Keep the field names as they are (they are mapped separately). A line starting "
        "with `# index:` is a siemx header, not part of the query.\n\n"
        f"Reference docs (each has its source URL):\n{json.dumps(ctx['docs'], ensure_ascii=False)}"
        f"\n\n{FROM_ELK_PITFALLS[target]} Use only syntax you are sure of; if something has "
        "no faithful equivalent, answer unsupported instead of guessing.\n"
        'Return JSON: {"query": str, "confidence": 0-1, "warnings": [str], '
        '"unsupported": bool, "sources": [the URLs of the docs you relied on]}'
    )


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
    s = settings()
    blob = {"model": s["model"], "system": SYSTEM, "prompt": prompt}
    if s["provider"] != "anthropic":          # anthropic keys unchanged: old cache stays valid
        blob.update(provider=s["provider"], base_url=s["base_url"])
    blob = json.dumps(blob, sort_keys=True)
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
    """One model call -> parsed JSON dict (raises on any failure; translate() turns a
    failure into an unsupported result for review)."""
    s = settings()
    if not s["model"]:
        raise ValueError(f"set SIEMX_MODEL for provider {s['provider']}")
    return {"anthropic": _call_anthropic, "ollama": _call_ollama,
            "openai": _call_openai}[s["provider"]](prompt, s)


def parse_json(text: str) -> dict:
    """The model's JSON answer; tolerates ``` fences and text around the object."""
    text = text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start < 0 or end <= start:
            raise
        return json.loads(text[start:end + 1])


NO_MODEL = ("no AI model configured: set SIEMX_PROVIDER and SIEMX_MODEL (for example "
            "ollama and qwen2.5-coder:7b) or ANTHROPIC_API_KEY; see GUIDE.md section 9")


def rules_only() -> bool:
    """SIEMX_PROVIDER=none (or `siemx convert --no-ai`): never call a model."""
    try:
        return settings()["provider"] == "none"
    except ValueError:
        return False


def default_workers() -> int:
    """A local Ollama answers one request at a time: parallel requests only queue up
    behind each other until they hit SIEMX_TIMEOUT. Hosted APIs handle 4 at once."""
    try:
        return 1 if settings()["provider"] == "ollama" else 4
    except ValueError:
        return 4


def configured() -> bool:
    """False when the default provider has no key: every LLM step would fail."""
    try:
        s = settings()
    except ValueError:
        return False
    return s["provider"] != "anthropic" or bool(os.environ.get("ANTHROPIC_API_KEY"))


def _call_anthropic(prompt: str, s: dict) -> dict:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise ValueError(NO_MODEL)
    import anthropic
    client = anthropic.Anthropic()
    resp = client.messages.create(
        model=s["model"], max_tokens=2000, system=SYSTEM,
        messages=[{"role": "user", "content": prompt}],
    )
    out = parse_json(resp.content[0].text)
    out["tokens"] = resp.usage.input_tokens + resp.usage.output_tokens
    return out


def _post(url: str, body: dict, headers: dict, timeout: float) -> dict:
    import urllib.error
    import urllib.request
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code} from {url}: {e.read().decode('utf-8', 'replace')[:300]}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"cannot reach {url}: {e.reason}")


def _messages(prompt: str) -> list[dict]:
    return [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}]


def _call_ollama(prompt: str, s: dict) -> dict:
    """Ollama's native chat API: it accepts the context size (num_ctx) and reports how
    many prompt tokens it read, so a silently cut prompt is detected."""
    resp = _post(f"{s['base_url']}/api/chat",
                 {"model": s["model"], "messages": _messages(prompt), "stream": False,
                  "format": "json", "options": {"temperature": 0, "num_ctx": s["num_ctx"]}},
                 {}, s["timeout"])
    out = parse_json(resp["message"]["content"])
    read = resp.get("prompt_eval_count") or 0
    if read >= s["num_ctx"]:
        raise ValueError(f"prompt cut at the context limit ({read} tokens); raise SIEMX_NUM_CTX")
    out["tokens"] = read + (resp.get("eval_count") or 0)
    return out


def _call_openai(prompt: str, s: dict) -> dict:
    key = os.environ.get("SIEMX_API_KEY") or os.environ.get("OPENAI_API_KEY") or ""
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    resp = _post(f"{s['base_url']}/chat/completions",
                 {"model": s["model"], "messages": _messages(prompt), "temperature": 0,
                  "max_tokens": 2000, "response_format": {"type": "json_object"}},
                 headers, s["timeout"])
    out = parse_json(resp["choices"][0]["message"]["content"])
    usage = resp.get("usage") or {}
    out["tokens"] = (usage.get("prompt_tokens") or 0) + (usage.get("completion_tokens") or 0)
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
    if out.get("unsupported"):
        out["query"] = ""        # the model said "no equivalent": nothing to save or validate
    _cache_put(key, out)
    return out
