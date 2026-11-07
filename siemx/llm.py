"""RAG + Claude fallback for stages the rules cannot handle."""
import json
import os

MODEL = os.environ.get("SIEMX_MODEL", "claude-sonnet-5-5")
NAMES = {"kql": "KQL (Microsoft Sentinel / Defender)", "xql": "XQL (Palo Alto Cortex XDR/XSIAM)"}

SYSTEM = (
    "You translate SIEM queries between languages. Use ONLY the reference "
    "material and examples provided for syntax. If there is no faithful "
    "equivalent, say so instead of guessing. Reply with JSON only."
)


def retrieve(spl: str, target: str) -> dict:
    """TODO: embed each stage, query the vector store (filter by language),
    and return {'docs': [...], 'examples': [...]} from gold/ and the official docs."""
    return {"docs": [], "examples": []}


def translate(spl: str, target: str) -> dict:
    ctx = retrieve(spl, target)
    prompt = (
        f"Translate this SPL to {NAMES[target]}.\n\nSPL:\n{spl}\n\n"
        f"Reference docs:\n{json.dumps(ctx['docs'])}\n\n"
        f"Verified examples:\n{json.dumps(ctx['examples'])}\n\n"
        'Return JSON: {"query": str, "confidence": 0-1, "warnings": [str], '
        '"unsupported": bool}'
    )
    try:
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
    except Exception as e:  # no key, bad JSON, API error -> send to review
        return {"query": "", "confidence": 0.0, "unsupported": True,
                "warnings": [f"LLM step failed: {e}"], "tokens": 0}
