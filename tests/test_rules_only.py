"""Rules-only mode: SIEMX_PROVIDER=none / `siemx convert --no-ai`. No model is ever called."""
import json
import sys

import pytest

from siemx import cli, config, llm, pipeline

ANSWER = {"query": "SecurityEvent | take 1", "confidence": 0.5, "warnings": []}


@pytest.fixture
def no_ai(monkeypatch):
    monkeypatch.setenv("SIEMX_PROVIDER", "none")
    monkeypatch.setattr(llm, "translate", lambda *a, **k: pytest.fail("rules-only: no model"))


@pytest.fixture
def det(workspace, sources_map):
    def write(rel, text):
        f = config.SRC_DIR / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
        return f
    return write


def meta(rel, t="kql"):
    return json.loads((config.META_DIR / f"{rel}.{t}.json").read_text())


def test_settings():
    assert "none" in llm.PROVIDERS


def test_rule_gap_is_unsupported_with_the_stages(no_ai, det):
    det("w/tx.spl", "index=wineventlog | eval a=1, b=2 | transaction host | transaction user")
    assert pipeline.run(["kql"], workers=1) == {"unsupported": 1}
    m = meta("w/tx")
    assert m["warnings"][0].startswith(
        "not converted: the rules cannot convert `transaction` (2 stages) (rules-only mode")
    assert m["method"] == "rules" and m["rules_only"] and m["model"] is None
    assert (config.OUT_DIR / "kql" / "w" / "tx.kql").read_text().strip() == ""


def test_base_search_gap_is_named(no_ai, det):
    det("w/free.spl", 'index=wineventlog "free text"')
    pipeline.run(["kql"], workers=1)
    assert "cannot convert the base search (rules-only" in meta("w/free")["warnings"][0]


def test_rule_results_are_unchanged(no_ai, det):
    det("w/ok.spl", "index=wineventlog EventID=4625")
    assert "unsupported" not in pipeline.run(["kql"], workers=1)
    assert meta("w/ok")["method"] == "rules" and "rules_only" not in meta("w/ok")
    assert meta("w/ok")["query_sha"] != pipeline.sha("")


def test_rules_only_results_are_skipped_until_ai_is_on(det, monkeypatch):
    det("w/tx.spl", "index=wineventlog | transaction host")
    monkeypatch.setenv("SIEMX_PROVIDER", "none")
    assert pipeline.run(["kql"], workers=1) == {"unsupported": 1}
    assert pipeline.run(["kql"], workers=1) == {"skipped": 1}          # no retry noise

    monkeypatch.setenv("SIEMX_PROVIDER", "ollama")                     # AI on again
    monkeypatch.setenv("SIEMX_MODEL", "m")
    monkeypatch.setattr(llm, "translate", lambda *a, **k: dict(ANSWER))
    assert pipeline.run(["kql"], workers=1) == {"needs-review": 1}
    assert meta("w/tx")["method"] == "llm"


@pytest.mark.parametrize("source, text, target", [
    ("kql", "SecurityEvent | mv-expand x", "spl"),
    ("elk", "# index: logs-x-*\nfree text", "kql"),
])
def test_other_directions_never_call_a_model(no_ai, sources_map, source, text, target):
    sources_map.write_text(json.dumps({"index=wineventlog": {
        "kql": "SecurityEvent", "xql": "dataset = xdr_data", "elk": "logs-x-*"}}))
    r = pipeline.convert_any(text, target, source)
    assert pipeline.status_for(r) == "unsupported"


def test_cli_flag_sets_the_mode(det, monkeypatch, capsys):
    monkeypatch.setenv("SIEMX_PROVIDER", "")     # "" = unset; recorded, so --no-ai is undone
    monkeypatch.setattr(llm, "translate", lambda *a, **k: pytest.fail("--no-ai: no model"))
    det("w/tx.spl", "index=wineventlog | transaction host")
    monkeypatch.setattr(sys, "argv", ["siemx", "convert", "--no-ai", "--to", "kql",
                                      "--workers", "1"])
    cli.main()
    err = capsys.readouterr().err
    assert "rules-only mode (no AI)" in err and "no AI model configured" not in err
