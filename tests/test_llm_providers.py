"""Switchable LLM provider (SIEMX_PROVIDER / SIEMX_MODEL / ...). No network: _post is stubbed."""
import hashlib
import json

import pytest

from siemx import config, llm, pipeline

ENV = ("SIEMX_PROVIDER", "SIEMX_MODEL", "SIEMX_BASE_URL", "SIEMX_NUM_CTX", "SIEMX_TIMEOUT",
       "SIEMX_API_KEY", "OPENAI_API_KEY")
ANSWER = {"query": "T | take 1", "confidence": 0.7, "warnings": [], "unsupported": False}


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for k in ENV:
        monkeypatch.delenv(k, raising=False)


@pytest.fixture
def post(monkeypatch):
    """Records each HTTP request; returns the queued response."""
    sent, replies = [], []

    def fake(url, body, headers, timeout):
        sent.append({"url": url, "body": body, "headers": headers, "timeout": timeout})
        return replies.pop(0)

    monkeypatch.setattr(llm, "_post", fake)
    return sent, replies


# ---- settings -----------------------------------------------------------------------------------------

def test_default_is_anthropic():
    s = llm.settings()
    assert (s["provider"], s["model"]) == ("anthropic", llm.MODEL)
    assert llm.model_id() == llm.MODEL


def test_ollama_settings(monkeypatch):
    monkeypatch.setenv("SIEMX_PROVIDER", "Ollama")
    monkeypatch.setenv("SIEMX_MODEL", "qwen2.5-coder:7b")
    s = llm.settings()
    assert s["base_url"] == "http://localhost:11434" and s["num_ctx"] == 16384
    assert llm.model_id() == "ollama:qwen2.5-coder:7b"


def test_empty_values_mean_unset(monkeypatch):
    """CI passes unset repository variables as empty strings."""
    for k in ("SIEMX_PROVIDER", "SIEMX_MODEL", "SIEMX_BASE_URL"):
        monkeypatch.setenv(k, "")
    assert llm.settings()["provider"] == "anthropic"


def test_unknown_provider(monkeypatch):
    monkeypatch.setenv("SIEMX_PROVIDER", "gpt")
    with pytest.raises(ValueError, match="use one of anthropic, ollama, openai"):
        llm.settings()


def test_missing_model_becomes_unsupported_result(monkeypatch, tmp_path):
    monkeypatch.setenv("SIEMX_PROVIDER", "ollama")
    monkeypatch.setattr(llm, "cache_dir", lambda: tmp_path)
    monkeypatch.setattr(llm, "build_prompt", lambda *a, **k: "p")
    r = llm.translate("index=a | x", "kql")
    assert r["unsupported"] and "set SIEMX_MODEL for provider ollama" in r["warnings"][0]


# ---- cache key ------------------------------------------------------------------------------------------

def test_anthropic_cache_key_unchanged():
    """Same formula as before the providers existed: cached answers stay valid."""
    blob = json.dumps({"model": llm.MODEL, "system": llm.SYSTEM, "prompt": "p"}, sort_keys=True)
    assert llm.cache_key("p") == hashlib.sha256(blob.encode()).hexdigest()


def test_cache_key_differs_per_provider(monkeypatch):
    monkeypatch.setenv("SIEMX_MODEL", "m")
    anthropic = llm.cache_key("p")
    monkeypatch.setenv("SIEMX_PROVIDER", "openai")
    openai = llm.cache_key("p")
    monkeypatch.setenv("SIEMX_BASE_URL", "https://gateway.example/v1")
    gateway = llm.cache_key("p")
    assert len({anthropic, openai, gateway}) == 3


# ---- responses ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    '{"query": "x", "confidence": 1}',
    '```json\n{"query": "x", "confidence": 1}\n```',
    'Here is the answer:\n{"query": "x", "confidence": 1}\nDone.',
])
def test_parse_json(text):
    assert llm.parse_json(text) == {"query": "x", "confidence": 1}


def test_ollama_request(monkeypatch, post):
    sent, replies = post
    monkeypatch.setenv("SIEMX_PROVIDER", "ollama")
    monkeypatch.setenv("SIEMX_MODEL", "qwen2.5-coder:7b")
    monkeypatch.setenv("SIEMX_NUM_CTX", "8192")
    replies.append({"message": {"content": json.dumps(ANSWER)}, "prompt_eval_count": 3000,
                    "eval_count": 100})
    out = llm.call_model("PROMPT")
    assert out["query"] == "T | take 1" and out["tokens"] == 3100
    req = sent[0]
    assert req["url"] == "http://localhost:11434/api/chat" and req["headers"] == {}
    assert req["body"]["format"] == "json" and req["body"]["stream"] is False
    assert req["body"]["options"] == {"temperature": 0, "num_ctx": 8192}
    assert req["body"]["messages"] == [{"role": "system", "content": llm.SYSTEM},
                                       {"role": "user", "content": "PROMPT"}]


def test_ollama_cut_prompt_is_an_error(monkeypatch, post):
    sent, replies = post
    monkeypatch.setenv("SIEMX_PROVIDER", "ollama")
    monkeypatch.setenv("SIEMX_MODEL", "m")
    monkeypatch.setenv("SIEMX_NUM_CTX", "2048")
    replies.append({"message": {"content": json.dumps(ANSWER)}, "prompt_eval_count": 2048})
    with pytest.raises(ValueError, match="prompt cut at the context limit"):
        llm.call_model("PROMPT")


def test_openai_compatible_request(monkeypatch, post):
    sent, replies = post
    monkeypatch.setenv("SIEMX_PROVIDER", "openai")
    monkeypatch.setenv("SIEMX_MODEL", "gpt-x")
    monkeypatch.setenv("SIEMX_BASE_URL", "https://gateway.example/v1/")
    monkeypatch.setenv("SIEMX_API_KEY", "k-123")
    replies.append({"choices": [{"message": {"content": json.dumps(ANSWER)}}],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5}})
    out = llm.call_model("PROMPT")
    assert out["tokens"] == 15
    req = sent[0]
    assert req["url"] == "https://gateway.example/v1/chat/completions"
    assert req["headers"] == {"Authorization": "Bearer k-123"}
    assert req["body"]["response_format"] == {"type": "json_object"}
    assert req["body"]["temperature"] == 0


# ---- review gate -----------------------------------------------------------------------------------------

def test_llm_results_are_never_auto_approved_by_default(monkeypatch):
    res = {"query": "q", "confidence": 0.99, "warnings": [], "method": "llm"}
    assert pipeline.status_for(res) == "needs-review"
    assert pipeline.status_for(dict(res, method="rules")) == "auto-approved"
    monkeypatch.setattr(config, "LLM_AUTO_APPROVE", True)           # after the pilot, on purpose
    assert pipeline.status_for(res) == "auto-approved"


def test_meta_records_provider_and_model(workspace, monkeypatch):
    monkeypatch.setenv("SIEMX_PROVIDER", "ollama")
    monkeypatch.setenv("SIEMX_MODEL", "qwen2.5-coder:7b")
    monkeypatch.setattr(llm, "translate", lambda *a, **k: dict(ANSWER))
    f = config.SRC_DIR / "windows" / "tx.spl"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("index=wineventlog | transaction host")
    pipeline.process_file(f, ["kql"], force=False)
    meta = json.loads((config.META_DIR / "windows" / "tx.kql.json").read_text())
    assert meta["model"] == "ollama:qwen2.5-coder:7b" and meta["status"] == "needs-review"


def test_model_saying_unsupported_leaves_no_query(monkeypatch, tmp_path):
    """A model that answers {"query": "unsupported", "unsupported": true} must not leave
    that text in the output file or trigger validator noise."""
    monkeypatch.setattr(llm, "cache_dir", lambda: tmp_path)
    monkeypatch.setattr(llm, "build_prompt", lambda *a, **k: "p")
    monkeypatch.setattr(llm, "call_model", lambda p: {
        "query": "unsupported", "confidence": 0, "unsupported": True,
        "warnings": ["transaction has no XQL equivalent"]})
    r = pipeline.llm_with_retry("index=a | transaction u", "xql")
    assert r["query"] == "" and r["warnings"] == ["transaction has no XQL equivalent"]
    assert pipeline.status_for(r) == "unsupported"


# ---- no model configured ------------------------------------------------------------------------------

def test_default_without_key_is_not_configured(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert llm.configured() is False
    with pytest.raises(ValueError, match="no AI model configured"):
        llm.call_model("p")
    monkeypatch.setenv("SIEMX_PROVIDER", "ollama")
    assert llm.configured() is True


def test_failed_llm_step_is_retried_next_run(workspace, monkeypatch):
    """A setup problem (no key, server down) must not be stored as a final answer."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(llm, "cache_dir", lambda: config.OUT_DIR / "_cache" / "llm")
    f = config.SRC_DIR / "windows" / "tx.spl"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("index=wineventlog | transaction host")
    assert pipeline.run(["kql"], workers=1) == {"unsupported": 1}
    meta = json.loads((config.META_DIR / "windows" / "tx.kql.json").read_text())
    assert meta["warnings"][0].startswith("LLM step failed: no AI model configured")

    monkeypatch.setattr(llm, "translate", lambda *a, **k: dict(ANSWER))   # model now set up
    assert pipeline.run(["kql"], workers=1) == {"needs-review": 1}         # not skipped
    assert pipeline.run(["kql"], workers=1) == {"skipped": 1}              # a real answer is kept
