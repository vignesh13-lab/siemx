"""LLM results are cached by query hash (CLAUDE.md); failures are not cached.
The real API is never called: llm.call_model is replaced."""
import json

import pytest

from siemx import cli, llm, pipeline


GOOD = {"query": "SecurityEvent | take 1", "confidence": 0.7, "warnings": [], "unsupported": False}


@pytest.fixture
def fake_model(workspace, monkeypatch):
    calls = []

    def fake(prompt):
        calls.append(prompt)
        return dict(GOOD, tokens=123)

    monkeypatch.setattr(llm, "call_model", fake)
    return calls


def test_second_call_is_served_from_cache(fake_model):
    first = llm.translate("index=x | transaction host", "kql")
    second = llm.translate("index=x | transaction host", "kql")
    assert len(fake_model) == 1
    assert first["tokens"] == 123 and "cached" not in first
    assert second["cached"] is True and second["tokens"] == 0
    assert second["query"] == GOOD["query"]
    files = list(llm.cache_dir().glob("*.json"))
    assert len(files) == 1 and files[0].stem == llm.cache_key(llm.build_prompt(
        "index=x | transaction host", "kql"))


def test_key_depends_on_query_target_and_model(fake_model, monkeypatch):
    llm.translate("index=x | transaction host", "kql")
    llm.translate("index=x | transaction host", "xql")       # other target
    llm.translate("index=x | transaction user", "kql")       # other query
    monkeypatch.setattr(llm, "MODEL", "another-model")
    llm.translate("index=x | transaction host", "kql")       # other model
    assert len(fake_model) == 4


def test_failures_are_not_cached(workspace, monkeypatch):
    def boom(prompt):
        raise RuntimeError("no API key")

    monkeypatch.setattr(llm, "call_model", boom)
    out = llm.translate("index=x | transaction host", "kql")
    assert out["unsupported"] is True and "no API key" in out["warnings"][0]
    assert not llm.cache_dir().exists() or not list(llm.cache_dir().glob("*.json"))


@pytest.mark.parametrize("bad", [
    {"confidence": 0.5},                         # no query
    {"query": "x"},                              # no confidence
    {"query": "x", "confidence": "high"},
    ["not", "a", "dict"],
])
def test_malformed_answers_are_not_cached(workspace, monkeypatch, bad):
    monkeypatch.setattr(llm, "call_model", lambda prompt: bad)
    out = llm.translate("index=x | transaction host", "kql")
    assert out["unsupported"] is True and "LLM step failed" in out["warnings"][0]
    assert not llm.cache_dir().exists() or not list(llm.cache_dir().glob("*.json"))


def test_model_unsupported_answer_is_cached(workspace, monkeypatch):
    """'No faithful equivalent' is a real answer, not a failure."""
    calls = []
    answer = {"query": "", "confidence": 0.0, "warnings": ["no equivalent"], "unsupported": True}
    monkeypatch.setattr(llm, "call_model", lambda p: calls.append(p) or dict(answer))
    llm.translate("index=x | transaction host", "kql")
    llm.translate("index=x | transaction host", "kql")
    assert len(calls) == 1


def test_meta_model_only_for_llm(workspace, fake_model):
    from siemx import config
    src = config.SRC_DIR / "w"
    src.mkdir(parents=True)
    (src / "rules.spl").write_text("index=wineventlog | stats count by host | sort - count")
    (src / "llm.spl").write_text("index=wineventlog | transaction host")
    pipeline.run(["kql"], workers=1)
    pipeline.run(["kql"], workers=1, force=True)
    meta = {p.stem: json.loads(p.read_text()) for p in config.META_DIR.glob("*.json")}
    assert meta["rules.kql"]["model"] is None and meta["rules.kql"]["method"] == "rules"
    assert meta["llm.kql"]["model"] == llm.MODEL and meta["llm.kql"]["cached"] is True
    assert len(fake_model) == 1                      # second (forced) run hit the cache


def test_review_prints_warnings(workspace, no_llm, capsys, monkeypatch):
    from siemx import config
    src = config.SRC_DIR / "w"
    src.mkdir(parents=True)
    (src / "a.spl").write_text("index=wineventlog | head 5")
    pipeline.run(["kql"], workers=1)
    monkeypatch.setattr("sys.argv", ["siemx", "review"])
    capsys.readouterr()
    cli.main()
    out = capsys.readouterr().out
    assert "needs-review  kql  detections/spl/w/a.spl" in out
    assert "    - KQL: head -> take on rows with no defined order" in out
