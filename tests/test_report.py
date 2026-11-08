"""Roadmap 8 + 9: report and pilot review results."""
import csv
import io
import json

import pytest

from siemx import cli, config, pipeline, report


def meta(src, target="kql", status="needs-review", method="rules", conf=0.9, warnings=(),
         no_rule=(), sha="q1"):
    return {"src": f"detections/spl/{src}", "target": target, "status": status, "method": method,
            "confidence": conf, "warnings": list(warnings), "no_rule": list(no_rule),
            "query_sha": sha}


def review(src, result, target="kql", sha="q1", by="alice"):
    return {"src": f"detections/spl/{src}", "target": target, "result": result, "by": by,
            "query_sha": sha}


@pytest.mark.parametrize("warning, cat", [
    ("LLM step failed: no key", "LLM not available / failed"),
    ("validation: empty output", "no translation produced"),
    ("validation: KQL syntax: Query operator expected.", "validation error"),
    ("KQL: field 'host' mapped to Computer (conditional: x); verify", "field mapping: conditional"),
    ("KQL: field 'user' is ambiguous for SecurityEvent: one of a, b.", "field mapping: ambiguous"),
    ("KQL: field(s) not in SecurityEvent (mappings/fields.json): host. x", "field name not in table"),
    ("XQL: no field list for xdr_data in mappings/fields.json; x", "field name not in table"),
    ("KQL: head -> take on rows with no defined order; x", "row order"),
    ("KQL: lookup 'vip' must exist as a Sentinel watchlist", "lookup table must exist"),
    ("KQL: != null handling may differ from SPL", "!= null handling"),
    ("XQL dedup: null handling and whether all fields are kept are not documented; verify",
     "XQL undocumented behaviour"),
    ("KQL: index=acme was dropped because the table comes from", "dropped index"),
    ("KQL: something new", "other rule caveat"),
])
def test_category(warning, cat):
    assert report.category(warning) == cat


def test_source_type():
    assert report.source_type("detections/spl/windows/a.spl") == "windows"
    assert report.source_type("detections/spl/a.spl") == "(root)"


def test_latest_review_wins_and_stale_detection():
    metas = [meta("w/a.spl", sha="new")]
    reviews = [review("w/a.spl", "wrong", sha="new"), review("w/a.spl", "correct", sha="new")]
    r = report.latest_reviews(metas, reviews)[("detections/spl/w/a.spl", "kql")]
    assert r["review"]["result"] == "correct" and r["stale"] is False
    old = report.latest_reviews(metas, [review("w/a.spl", "correct", sha="old")])
    assert old[("detections/spl/w/a.spl", "kql")]["stale"] is True


def test_stale_reviews_are_not_counted():
    metas = [meta("w/a.spl", sha="new")]
    reviewed = report.latest_reviews(metas, [review("w/a.spl", "correct", sha="old")])
    text = report.reviews_section(metas, reviewed)
    assert "No reviews yet" in text and "1 stale" in text


def test_review_accuracy_tables():
    metas = [meta("w/a.spl", status="auto-approved"), meta("w/b.spl"), meta("w/c.spl")]
    reviewed = report.latest_reviews(metas, [review("w/a.spl", "correct"),
                                             review("w/b.spl", "fixed"), review("w/c.spl", "wrong")])
    text = report.reviews_section(metas, reviewed)
    assert "| auto-approved | 1 | 1 | 0 | 0 | 100% |" in text
    assert "| needs-review | 2 | 0 | 1 | 1 | 0% |" in text


def test_threshold_analysis():
    """Auto-approval needs confidence >= threshold AND no warnings."""
    metas = [meta(f"w/{i}.spl", method="llm", conf=c, warnings=w)
             for i, (c, w) in enumerate([(0.95, []), (0.9, []), (0.7, []), (0.99, ["x"])])]
    results = ["correct", "wrong", "correct", "correct"]
    reviewed = report.latest_reviews(metas, [review(f"w/{i}.spl", r) for i, r in enumerate(results)])
    text = report.threshold_section(metas, reviewed)
    assert "| 0.95 | 1 | 0 | 100% |" in text           # only the 0.95 one
    assert "| 0.85 (current) | 2 | 1 | 50% |" in text  # 0.95 correct + 0.9 wrong
    assert "| 0.70 | 3 | 1 | 67% |" in text
    assert "never silently" in text


def test_threshold_analysis_ignores_rules_and_unreviewed():
    metas = [meta("w/a.spl", method="rules"), meta("w/b.spl", method="llm")]
    assert "Needs reviewed LLM outputs" in report.threshold_section(
        metas, report.latest_reviews(metas, [review("w/a.spl", "correct")]))


def test_missing_rules_ranked():
    metas = [meta("a.spl", no_rule=["transaction"]), meta("b.spl", no_rule=["transaction", "eval"]),
             meta("c.spl")]
    text = report.missing_rules_section(metas)
    assert text.index("`transaction` | 2") < text.index("`eval` | 1")


# ---- pilot sample -----------------------------------------------------------------------------------

def test_pilot_sample_is_stratified_and_deterministic(tmp_path):
    def add(src, i, spl):
        p = tmp_path / src / f"{i}.spl"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(spl)
    for i in range(80):
        add("windows", i, "index=w | stats count by host")            # simple, common
    for i in range(15):
        add("windows", f"h{i}", "index=w | transaction host")          # hard
    for i in range(5):
        add("linux", i, "index=l | eval x=1")                          # medium, rare source
    picked = report.pilot_sample(tmp_path, 20)
    assert len(picked) == 20 and picked == report.pilot_sample(tmp_path, 20)
    rel = [p.relative_to(tmp_path).as_posix() for p in picked]
    assert any(r.startswith("linux/") for r in rel)                    # rare group represented
    assert sum(r.startswith("windows/h") for r in rel) >= 2            # hard ones represented
    assert report.pilot_sample(tmp_path, 500) == sorted(tmp_path.rglob("*.spl"))


# ---- end to end -----------------------------------------------------------------------------------

def test_verdict_and_report_end_to_end(workspace, no_llm, monkeypatch, tmp_path, capsys):
    p = config.SRC_DIR / "windows" / "a.spl"
    p.parent.mkdir(parents=True)
    p.write_text("index=wineventlog | stats count by host | sort - count")
    pipeline.run(["kql"], workers=1)
    monkeypatch.setattr("sys.argv", ["siemx", "verdict", "windows/a.spl", "--to", "kql",
                                     "--result", "fixed", "--by", "alice", "--notes", "n"])
    cli.main()
    assert "siemx gold add windows/a.spl" in capsys.readouterr().out
    out = report.write(mkdocs_dir=tmp_path / "hub")
    md = open(out["report"], encoding="utf-8").read()
    assert "| windows | kql | 1 | 1 |" in md               # auto-approved (host is a test column)
    # ...but the reviewer had to fix it: exactly what the report must expose
    assert "| auto-approved | 1 | 0 | 1 | 0 | 0% |" in md
    rows = list(csv.DictReader(io.StringIO(open(out["csv"], encoding="utf-8").read())))
    assert rows[0]["review"] == "fixed" and rows[0]["reviewed_by"] == "alice"
    hub = open(out["mkdocs"], encoding="utf-8").read()
    assert hub.startswith("---\ntitle: siemx conversion report") and "type: doc" in hub


def test_verdict_requires_conversion(workspace, monkeypatch):
    monkeypatch.setattr("sys.argv", ["siemx", "verdict", "nope.spl", "--to", "kql",
                                     "--result", "correct", "--by", "a"])
    with pytest.raises(SystemExit, match="no conversion found"):
        cli.main()


def test_add_review_validates_input(workspace):
    with pytest.raises(ValueError):
        report.add_review(meta("a.spl"), "great", "alice")
    with pytest.raises(ValueError):
        report.add_review(meta("a.spl"), "correct", " ")
