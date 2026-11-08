"""Roadmap 4: gold examples (verified pairs) for few-shot prompts."""
import json
from pathlib import Path

import pytest

from siemx import cli, config, gold, llm, rag_eval

REPO_GOLD = Path(__file__).resolve().parent.parent / "gold" / "pairs.jsonl"


def test_repo_gold_still_matches_the_rules():
    """Regression: if a rule changes a verified answer, re-check it and run `siemx gold seed`."""
    pairs = gold.load(REPO_GOLD)
    assert len(pairs) >= 20
    assert gold.check(pairs) == []


def test_repo_gold_is_well_formed():
    ids = set()
    for p in gold.load(REPO_GOLD):
        assert p["id"] not in ids
        ids.add(p["id"])
        assert p["spl"] and (p["kql"] or p["xql"]) and p["verified_by"] and p["added"]


def test_seed_is_strict_about_caveats():
    rows = {r["spl"]: r for r in gold.seed([
        "index=wineventlog | stats dc(user) as users by host",   # KQL dc: preview caveat
        "index=wineventlog | rename src AS s",                   # XQL rename: caveat
        "index=wineventlog | transaction host",                  # no rule at all
        "index=wineventlog | eval n = len(cmd)",                 # clean in both
    ])}
    assert rows["index=wineventlog | stats dc(user) as users by host"]["kql"] is None
    assert "kql: rule caveat" in rows["index=wineventlog | stats dc(user) as users by host"]["notes"]
    assert rows["index=wineventlog | rename src AS s"]["xql"] is None
    assert "index=wineventlog | transaction host" not in rows       # nothing verified: dropped
    clean = rows["index=wineventlog | eval n = len(cmd)"]
    assert clean["kql"] == "SecurityEvent\n| extend n = strlen(cmd)"
    assert clean["xql"] == "dataset = xdr_data\n| alter n = len(cmd)"
    assert clean["verified_by"] == "docs+tests"


def test_seed_does_not_leak_mapping_or_client():
    from siemx import rules
    before = (rules.MAP_FILE, config.CLIENT)
    gold.seed(["index=wineventlog | head 1"])
    assert (rules.MAP_FILE, config.CLIENT) == before


def test_merge_keeps_reviewed_pairs():
    existing = [{"id": "seed-001", "spl": "old"}, {"id": "rev-001", "spl": "x", "kql": "k"}]
    merged = gold.merge_seeds(existing, [{"id": "seed-001", "spl": "new"}])
    assert [p["spl"] for p in merged] == ["new", "x"]


PAIRS = [
    {"id": "seed-001", "spl": "index=a | eval n = len(cmd) | where n > 1",
     "kql": "T | extend n = strlen(cmd) | where n > 1", "xql": "D | alter n = len(cmd)",
     "verified_by": "docs+tests"},
    {"id": "seed-002", "spl": "index=a | stats count by host", "kql": "T | summarize",
     "xql": None, "verified_by": "docs+tests"},
    {"id": "seed-003", "spl": "index=a | where x > 1", "kql": "T | where x > 1",
     "xql": "D | filter x > 1", "verified_by": "docs+tests"},
]


def test_similar_ranks_by_shared_commands_and_functions():
    hits = gold.similar(PAIRS, "index=b | eval size = len(path)", "kql")
    assert hits[0][1]["id"] == "seed-001"
    assert all(p["id"] != "seed-002" for _, p in hits)        # no shared command


def test_similar_skips_pairs_without_the_target_and_exact_matches():
    assert [p["id"] for _, p in gold.similar(PAIRS, "index=a | stats count by host", "xql")] == []
    hits = gold.similar(PAIRS, "index=a | where x > 1", "kql", exclude_spl="index=a  |  where x > 1")
    assert all(p["id"] != "seed-003" for _, p in hits)        # leakage guard (normalised)


def test_add_reviewed_new_and_update():
    pairs = [dict(p) for p in PAIRS]
    row = gold.add_reviewed(pairs, "index=a | transaction host", "kql", "T | scan ...", "alice",
                            source="converted/kql/w/t.kql")
    assert (row["id"], row["verified_by"], row["kql"], row["xql"]) == ("rev-001", "alice", "T | scan ...", None)
    again = gold.add_reviewed(pairs, "index=a |  transaction host", "xql", "D | ...", "bob", source="s")
    assert again is row and row["xql"] == "D | ..." and row["verified_by"] == "bob"
    with pytest.raises(ValueError):
        gold.add_reviewed(pairs, "x", "kql", "y", " ", source="s")


def test_check_detects_drift():
    drifted = [dict(PAIRS[0], spl="index=wineventlog | eval n = len(cmd)",
                    kql="SecurityEvent\n| extend n = OLD(cmd)", xql=None)]
    problems = gold.check(drifted)
    assert problems and problems[0]["now"] == "SecurityEvent\n| extend n = strlen(cmd)"


def test_examples_reach_the_prompt(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "ROOT", tmp_path)          # no docs index
    monkeypatch.setattr(config, "GOLD_DIR", tmp_path / "gold")
    gold.save(PAIRS)
    ctx = llm.retrieve("index=b | eval size = len(path)", "kql")
    assert ctx["docs"] == [] and ctx["examples"][0]["kql"].startswith("T | extend n = strlen")
    prompt = llm.build_prompt("index=b | eval size = len(path)", "kql")
    assert "strlen" in prompt and "illustrative" in prompt


def test_evaluate_examples_with_leakage_guard():
    cases = [{"spl": "index=a | where x > 1", "kql": ["where"], "xql": ["filter"]}]
    rep = rag_eval.evaluate_examples(PAIRS, cases)
    # the exact pair is excluded; seed-001 (also uses where) still shows the operator
    assert rep["kql"]["hit"] == 1.0 and rep["xql"]["hit"] == 0.0


def test_cli_gold_add(workspace, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(config, "ROOT", tmp_path)
    monkeypatch.setattr(config, "GOLD_DIR", tmp_path / "gold")
    src = config.SRC_DIR / "w" / "t.spl"
    src.parent.mkdir(parents=True)
    src.write_text("index=wineventlog | transaction host\n")
    out = config.OUT_DIR / "kql" / "w" / "t.kql"
    out.parent.mkdir(parents=True)
    out.write_text("SecurityEvent\n| reviewed query\n")
    monkeypatch.setattr("sys.argv", ["siemx", "gold", "add", "w/t.spl", "--to", "kql", "--by", "alice"])
    cli.main()
    assert json.loads(capsys.readouterr().out)["added"] == "rev-001"
    row = gold.load()[0]
    assert row["kql"] == "SecurityEvent\n| reviewed query" and row["verified_by"] == "alice"
