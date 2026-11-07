"""Shared fixtures. Tests never depend on the current working directory
or on network access: paths are redirected to tmp_path and the LLM is stubbed."""
import json

import pytest

from siemx import config, llm, rules

SOURCES = {"index=wineventlog": {"kql": "SecurityEvent", "xql": "dataset = xdr_data"}}


@pytest.fixture
def sources_map(tmp_path, monkeypatch):
    """Point rules at a known mappings file (rules binds MAP_FILE at import)."""
    f = tmp_path / "sources.json"
    f.write_text(json.dumps(SOURCES))
    monkeypatch.setattr(rules, "MAP_FILE", f)
    return f


@pytest.fixture
def no_llm(monkeypatch):
    """Fail loudly if a test path reaches the LLM."""

    def fake(spl, target):
        raise AssertionError("LLM must not be called for rule-covered queries")

    monkeypatch.setattr(llm, "translate", fake)


@pytest.fixture
def workspace(tmp_path, monkeypatch, sources_map):
    """Isolated detections/ + converted/ tree."""
    out = tmp_path / "converted"
    monkeypatch.setattr(config, "SRC_DIR", tmp_path / "detections" / "spl")
    monkeypatch.setattr(config, "OUT_DIR", out)
    monkeypatch.setattr(config, "META_DIR", out / "_meta")
    return tmp_path
