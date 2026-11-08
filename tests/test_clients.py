"""Per-client mappings, macros, sourcetype mapping with dropped index, output
folders, and re-conversion when mappings change."""
import json

import pytest

from siemx import cli, config, mappings, pipeline, rules


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


@pytest.fixture
def maps(tmp_path, monkeypatch, workspace):
    """Isolated mappings dir with shared files; no client selected."""
    mdir = tmp_path / "mappings"
    monkeypatch.setattr(config, "MAPPINGS_DIR", mdir)
    monkeypatch.setattr(config, "MACROS_FILE", mdir / "macros.json")
    monkeypatch.setattr(rules, "MAP_FILE", mdir / "sources.json")
    monkeypatch.setattr(config, "CLIENT", None)
    write(mdir / "sources.json", {
        "_readme": "comment keys are ignored",
        "sourcetype=XmlWinEventLog:Security": {"kql": "SecurityEvent", "xql": "dataset = xdr_data"},
        "index=wineventlog": {"kql": "SecurityEvent", "xql": "dataset = xdr_data"},
    })
    write(mdir / "macros.json", {"_readme": "x", "win_security": "sourcetype=XmlWinEventLog:Security"})
    return mdir


def use_client(monkeypatch, name):
    monkeypatch.setattr(config, "CLIENT", name)


# ---- source matching ----------------------------------------------------------------

def test_sourcetype_mapping_drops_index_with_warning(maps):
    r = rules.first_stage("index=acme_win sourcetype=XmlWinEventLog:Security EventID=4625", "kql")
    assert r == "SecurityEvent\n| where EventID == 4625"
    assert r.warnings == [rules.INDEX_DROPPED_WARNING.format(
        T="KQL", index="acme_win", by="sourcetype")]


def test_index_star_dropped_without_warning(maps):
    r = rules.first_stage("index=* sourcetype=XmlWinEventLog:Security", "kql")
    assert (r, r.warnings) == ("SecurityEvent", [])


def test_sourcetype_only(maps):
    r = rules.first_stage("sourcetype=xmlwineventlog:security EventID=1", "kql")   # case-insensitive
    assert (r, r.warnings) == ("SecurityEvent\n| where EventID == 1", [])


def test_unmapped_sourcetype_is_none(maps):
    assert rules.first_stage("index=wineventlog sourcetype=other", "kql") is None
    assert rules.first_stage("sourcetype=other", "kql") is None


def test_most_specific_entry_wins(maps):
    write(maps / "sources.json", {
        "sourcetype=st": {"kql": "Generic"},
        "index=dc sourcetype=st": {"kql": "DomainControllers"},
    })
    assert rules.first_stage("index=dc sourcetype=st", "kql") == "DomainControllers"
    r = rules.first_stage("index=other sourcetype=st", "kql")
    assert r == "Generic" and r.warnings


def test_index_wildcard_only_for_index(maps):
    assert rules.first_stage("index=win* sourcetype=XmlWinEventLog:Security", "kql").warnings
    assert rules.first_stage("sourcetype=XmlWin*", "kql") is None


# ---- clients ------------------------------------------------------------------------------

def test_client_index_mapping_overrides_and_is_exact(maps, monkeypatch):
    write(maps / "clients" / "acme" / "sources.json",
          {"index=acme_win": {"kql": "SecurityEvent", "xql": "dataset = xdr_data"}})
    assert rules.first_stage("index=acme_win EventID=1", "kql") is None      # no client yet
    use_client(monkeypatch, "acme")
    r = rules.first_stage("index=acme_win EventID=1", "kql")
    assert (r, r.warnings) == ("SecurityEvent\n| where EventID == 1", [])


def test_client_macros_override_shared(maps, monkeypatch):
    write(maps / "clients" / "acme" / "macros.json", {"win_security": "index=acme_win"})
    assert mappings.expand_macros("`win_security` EventID=1") == (
        "sourcetype=XmlWinEventLog:Security EventID=1")
    use_client(monkeypatch, "acme")
    assert mappings.expand_macros("`win_security` EventID=1") == "index=acme_win EventID=1"


def test_set_client_output_folder_and_validation(monkeypatch):
    monkeypatch.setattr(config, "CLIENT", None)
    monkeypatch.setattr(config, "OUT_DIR", config.OUT_DIR)
    monkeypatch.setattr(config, "META_DIR", config.META_DIR)
    config.set_client("acme")
    assert config.OUT_DIR == config.ROOT / "converted" / "acme"
    assert config.META_DIR == config.OUT_DIR / "_meta"
    assert config.client_dir() == config.MAPPINGS_DIR / "clients" / "acme"
    for bad in ("../x", "a b", "a/b"):
        with pytest.raises(ValueError):
            config.set_client(bad)


def test_empty_client_name_means_no_client(monkeypatch):
    """GitHub Actions passes SIEMX_CLIENT="" on push events; that must not crash."""
    monkeypatch.setattr(config, "CLIENT", None)
    monkeypatch.setattr(config, "OUT_DIR", config.OUT_DIR)
    before = config.OUT_DIR
    config.set_client("")
    assert config.CLIENT is None and config.OUT_DIR == before


def test_cli_convert_with_empty_client_env_like_ci_push(maps, no_llm, monkeypatch, capsys):
    """Reproduces the convert-detections workflow on a push to main."""
    spl_file("w/a.spl")
    monkeypatch.setenv("SIEMX_CLIENT", "")
    monkeypatch.setattr("sys.argv", ["siemx", "convert", "--to", "kql", "--workers", "1"])
    cli.main()
    assert '"summary"' in capsys.readouterr().out
    assert config.CLIENT is None


# ---- macros ----------------------------------------------------------------------------------

@pytest.mark.parametrize("spl, out", [
    ("`win_security` EventID=1", "sourcetype=XmlWinEventLog:Security EventID=1"),
    ("`unknown` EventID=1", "`unknown` EventID=1"),                  # left as is -> no rule
    ("`win_security(x)` EventID=1", "`win_security(x)` EventID=1"),  # with args: not expanded
    ("`outer`", "sourcetype=XmlWinEventLog:Security"),                # nested
    # a macro that refers to itself stops after MAX_MACRO_DEPTH expansions and keeps
    # a backtick term, so no rule matches it (-> LLM / review)
    ("`loop`", "`loop`" + " x" * 10),
])
def test_expand_macros(maps, spl, out):
    write(maps / "macros.json", {"win_security": "sourcetype=XmlWinEventLog:Security",
                                 "outer": "`win_security`", "loop": "`loop` x"})
    assert mappings.MAX_MACRO_DEPTH == 10
    assert mappings.expand_macros(spl) == out


def test_macro_query_end_to_end(maps, no_llm):
    res = pipeline.convert_query("`win_security` EventID=4625 | stats count by Computer", "kql")
    assert res["method"] == "rules"
    assert res["query"].startswith("SecurityEvent\n| where EventID == 4625\n")


def test_unknown_macro_goes_to_llm(maps, monkeypatch):
    calls = []
    monkeypatch.setattr(pipeline.llm, "translate", lambda s, t: calls.append(s) or
                        {"query": "", "confidence": 0, "unsupported": True, "warnings": []})
    pipeline.convert_query("`nope` EventID=4625", "kql")
    assert calls == ["`nope` EventID=4625"]


# ---- pipeline: folders, client output, mapping changes --------------------------------------

def spl_file(rel, text="index=wineventlog | head 1"):
    p = config.SRC_DIR / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def test_same_name_in_two_folders_keeps_both_metas(maps, no_llm):
    spl_file("windows/brute.spl")
    spl_file("linux/brute.spl")
    pipeline.run(["kql"], workers=1)
    metas = sorted(p.relative_to(config.META_DIR).as_posix() for p in config.META_DIR.rglob("*.json"))
    assert metas == ["linux/brute.kql.json", "windows/brute.kql.json"]
    assert pipeline.status() == {"needs-review": 2}


def test_mapping_change_reconverts(maps, no_llm):
    spl_file("w/a.spl")
    assert pipeline.run(["kql"], workers=1) == {"needs-review": 1}
    assert pipeline.run(["kql"], workers=1) == {"skipped": 1}
    write(maps / "macros.json", {"new_macro": "index=x"})          # any mapping change
    assert pipeline.run(["kql"], workers=1) == {"needs-review": 1}


def test_run_path_filter(maps, no_llm):
    spl_file("acme/a.spl")
    spl_file("globex/b.spl")
    assert pipeline.run(["kql"], workers=1, path="acme") == {"needs-review": 1}


def test_cli_client_writes_to_client_folder(maps, no_llm, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(config, "ROOT", tmp_path)
    write(maps / "clients" / "acme" / "sources.json", {"index=acme_win": {"kql": "SecurityEvent"}})
    spl_file("acme/a.spl", "index=acme_win EventID=4625 | head 1")
    monkeypatch.setattr("sys.argv", ["siemx", "convert", "--to", "kql", "--client", "acme",
                                     "--path", "acme", "--workers", "1"])
    cli.main()
    meta = json.loads((tmp_path / "converted" / "acme" / "_meta" / "acme" / "a.kql.json").read_text())
    assert meta["client"] == "acme" and meta["method"] == "rules"
    out = (tmp_path / "converted" / "acme" / "kql" / "acme" / "a.kql").read_text()
    assert out.startswith("SecurityEvent\n| where EventID == 4625")
