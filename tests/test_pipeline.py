import json

import pytest

from siemx import config, pipeline

SPL = "index=wineventlog | stats count by host | sort - count | head 10"

EXPECTED = {
    "kql": "SecurityEvent\n| where isnotempty(host)\n| summarize ['count'] = count() by host\n| sort by ['count'] desc\n| take 10",
    "xql": "dataset = xdr_data\n| filter host != null\n| comp count() as count by host\n| sort desc count\n| limit 10",
}


def write_spl(text=SPL, name="top_hosts", sub="windows"):
    d = config.SRC_DIR / sub
    d.mkdir(parents=True, exist_ok=True)
    f = d / f"{name}.spl"
    f.write_text(text)
    return f


def meta(name, target, sub="windows"):
    return json.loads((config.META_DIR / sub / f"{name}.{target}.json").read_text())


@pytest.mark.parametrize("target", ["kql", "xql"])
def test_convert_query_rules_end_to_end(sources_map, no_llm, target):
    res = pipeline.convert_query(SPL, target)
    assert res["query"] == EXPECTED[target]
    assert res["method"] == "rules"
    assert pipeline.status_for(res) == "auto-approved"


def test_process_file_writes_output_and_meta(workspace, no_llm):
    f = write_spl()
    results = pipeline.process_file(f, ["kql", "xql"], force=False)
    assert [r["status"] for r in results] == ["auto-approved", "auto-approved"]
    for t, ext in (("kql", ".kql"), ("xql", ".xql")):   # forward targets
        out = config.OUT_DIR / t / "windows" / f"top_hosts{ext}"
        assert out.read_text() == EXPECTED[t] + "\n"
        m = meta("top_hosts", t)
        assert m["src_hash"] == pipeline.sha(SPL)
        assert m["converter"] == config.CONVERTER_VERSION
        assert m["src"] == "detections/spl/windows/top_hosts.spl"   # repo-relative
        assert m["status"] == "auto-approved"
        assert m["method"] == "rules"


def test_converter_version_change_reconverts(workspace, no_llm, monkeypatch):
    """A rule fix must regenerate output even when the SPL is unchanged."""
    f = write_spl()
    pipeline.process_file(f, ["kql"], force=False)
    assert pipeline.process_file(f, ["kql"], force=False)[0]["status"] == "skipped"

    monkeypatch.setattr(config, "CONVERTER_VERSION", "test-next")
    assert pipeline.process_file(f, ["kql"], force=False)[0]["status"] == "auto-approved"
    assert meta("top_hosts", "kql")["converter"] == "test-next"


def test_old_meta_without_converter_is_reconverted(workspace, no_llm):
    """Meta written before the converter field existed counts as stale."""
    f = write_spl()
    (config.META_DIR / "windows").mkdir(parents=True)
    (config.META_DIR / "windows" / "top_hosts.kql.json").write_text(
        json.dumps({"src_hash": pipeline.sha(SPL), "status": "auto-approved"}))
    assert pipeline.process_file(f, ["kql"], force=False)[0]["status"] == "auto-approved"


def test_unchanged_input_is_skipped(workspace, no_llm, monkeypatch):
    f = write_spl()
    pipeline.process_file(f, ["kql", "xql"], force=False)

    def boom(*a, **k):
        raise AssertionError("convert_query must not run for unchanged input")

    monkeypatch.setattr(pipeline, "convert_query", boom)
    results = pipeline.process_file(f, ["kql", "xql"], force=False)
    assert [r["status"] for r in results] == ["skipped", "skipped"]


def test_changed_input_is_reconverted(workspace, no_llm):
    f = write_spl()
    pipeline.process_file(f, ["kql"], force=False)
    old_hash = meta("top_hosts", "kql")["src_hash"]

    f.write_text(SPL.replace("head 10", "head 5"))
    results = pipeline.process_file(f, ["kql"], force=False)
    assert results[0]["status"] == "auto-approved"
    assert meta("top_hosts", "kql")["src_hash"] != old_hash
    out = config.OUT_DIR / "kql" / "windows" / "top_hosts.kql"
    assert out.read_text().endswith("take 5\n")


def test_force_reconverts_unchanged_input(workspace, no_llm, monkeypatch):
    f = write_spl()
    pipeline.process_file(f, ["kql"], force=False)
    calls = []
    real = pipeline.convert_query

    def spy(spl, target):
        calls.append(target)
        return real(spl, target)

    monkeypatch.setattr(pipeline, "convert_query", spy)
    results = pipeline.process_file(f, ["kql"], force=True)
    assert calls == ["kql"]
    assert results[0]["status"] == "auto-approved"


def test_skip_is_per_target(workspace, no_llm):
    f = write_spl()
    pipeline.process_file(f, ["kql"], force=False)
    results = pipeline.process_file(f, ["kql", "xql"], force=False)
    assert {r["target"]: r["status"] for r in results} == {
        "kql": "skipped", "xql": "auto-approved"}


def test_run_counts_and_status(workspace, no_llm):
    write_spl()
    assert pipeline.run(["kql", "xql"], workers=2) == {"auto-approved": 2}
    assert pipeline.run(["kql", "xql"], workers=2) == {"skipped": 2}
    assert pipeline.status() == {"auto-approved": 2}
    assert pipeline.review_list() == []


def test_unruled_stage_goes_to_llm_and_is_flagged(workspace, monkeypatch):
    """A stage with no rule must reach the LLM; a failed LLM result is unsupported."""
    calls = []

    def stub(spl, target, **kw):
        calls.append(target)
        return {"query": "", "confidence": 0.0, "unsupported": True,
                "warnings": ["LLM step failed: stub"], "tokens": 0}

    monkeypatch.setattr(pipeline.llm, "translate", stub)
    f = write_spl("index=wineventlog | transaction host", name="tx")
    results = pipeline.process_file(f, ["kql"], force=False)
    assert calls == ["kql"]
    assert results[0]["status"] == "unsupported"
    assert [m["target"] for m in pipeline.review_list()] == ["kql"]


def test_flagged_rule_output_is_needs_review(sources_map, no_llm):
    spl = 'index=wineventlog | where user="admin" | stats count by host'
    kql = pipeline.convert_query(spl, "kql")
    assert kql["query"] == ("SecurityEvent\n| where user == \"admin\"\n"
                            "| where isnotempty(host)\n| summarize ['count'] = count() by host")
    assert pipeline.status_for(kql) == "auto-approved"

    xql = pipeline.convert_query(spl, "xql")
    assert xql["query"] == ("dataset = xdr_data\n| filter user = \"admin\"\n"
                            "| filter host != null\n| comp count() as count by host")
    assert xql["method"] == "rules" and xql["warnings"]
    assert pipeline.status_for(xql) == "needs-review"


@pytest.mark.parametrize("res, status", [
    ({"query": "q", "confidence": 0.9, "warnings": []}, "auto-approved"),
    ({"query": "q", "confidence": config.CONF_AUTO_APPROVE, "warnings": []}, "auto-approved"),
    ({"query": "q", "confidence": 0.84, "warnings": []}, "needs-review"),
    ({"query": "q", "confidence": 0.99, "warnings": ["w"]}, "needs-review"),
    ({"query": "", "confidence": 0.99, "warnings": []}, "unsupported"),
    ({"query": "q", "confidence": 0.99, "warnings": [], "unsupported": True}, "unsupported"),
])
def test_status_for(res, status):
    assert pipeline.status_for(res) == status
