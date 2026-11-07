"""Shared fixtures. Tests never depend on the current working directory
or on network access: paths are redirected to tmp_path and the LLM is stubbed."""
import json

import pytest

from siemx import config, llm, rules

SOURCES = {"index=wineventlog": {"kql": "SecurityEvent", "xql": "dataset = xdr_data"}}

# Test-only schema (the real one is mappings/fields.json). Includes `host` and
# `user` so pipeline-mechanics tests are not affected by the field check;
# tests/test_schema.py covers the check itself.
TEST_FIELDS = {
    "kql": {"SecurityEvent": {"fields": ["Computer", "EventID", "host", "user"]}},
    "xql": {"xdr_data": {"fields": ["agent_hostname", "host", "user"]}},
}


@pytest.fixture(autouse=True)
def fields_map(tmp_path, monkeypatch):
    """Never read the repo's mappings/fields.json implicitly (cwd-dependent)."""
    f = tmp_path / "fields.json"
    f.write_text(json.dumps(TEST_FIELDS))
    monkeypatch.setattr(config, "FIELDS_FILE", f)
    return f


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
