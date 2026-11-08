"""Roadmap 6: field mapping (exact / conditional / ambiguous), safe SPL renaming,
importing a client's Splunk props.conf."""
import json
from pathlib import Path

import pytest

from siemx import cli, config, fieldmap, pipeline, rules

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture
def fmap(tmp_path, monkeypatch, sources_map):
    """Real SecurityEvent columns + a small shared field map; no client."""
    monkeypatch.setattr(config, "FIELDS_FILE", REPO / "mappings" / "fields.json")
    mdir = tmp_path / "mappings"
    mdir.mkdir()
    monkeypatch.setattr(config, "MAPPINGS_DIR", mdir)
    monkeypatch.setattr(config, "CLIENT", None)
    (mdir / "field_map.json").write_text(json.dumps({"kql": {"SecurityEvent": {"fields": {
        "EventCode": {"to": "EventID", "level": "exact"},
        "host": {"to": "Computer", "level": "conditional", "note": "not with WEF"},
        "Account_Name": {"level": "ambiguous", "candidates": ["TargetUserName", "SubjectUserName"]},
    }}}}))
    return mdir


# ---- renaming ------------------------------------------------------------------------------------

R = {"host": "Computer", "EventCode": "EventID"}


@pytest.mark.parametrize("spl, out", [
    ("index=w EventCode=4625 host=web01 | stats count by host",
     "index=w EventID=4625 Computer=web01 | stats count by Computer"),
    ('index=w user=host | where host != "host" AND len(host) > 3',          # value / string / call
     'index=w user=host | where Computer != "host" AND len(Computer) > 3'),
    ("index=w | table 'host', EventCode", "index=w | table 'Computer', EventID"),
    ('index=w | rex field=host "(?<hostname>x)"', 'index=w | rex field=Computer "(?<hostname>x)"'),
    ("index=w | eval host_count = 1", "index=w | eval host_count = 1"),     # no partial match
    ("index=w | host x", "index=w | host x"),                               # command word
])
def test_rename_in_spl(spl, out):
    assert fieldmap.rename_in_spl(spl, R) == out


# ---- plan + pipeline -------------------------------------------------------------------------------

def test_exact_applied_silently(fmap, no_llm):
    res = pipeline.convert_query("index=wineventlog EventCode=4625 | stats count by Computer", "kql")
    assert res["query"].startswith("SecurityEvent\n| where EventID == 4625")
    assert res["field_map"] == {"EventCode": {"to": "EventID", "level": "exact"}}
    assert pipeline.status_for(res) == "auto-approved"


def test_conditional_applied_and_flagged(fmap, no_llm):
    res = pipeline.convert_query("index=wineventlog | stats count by host | sort - count | head 5", "kql")
    assert "by Computer" in res["query"] and "host" not in res["query"]
    assert any("'host' mapped to Computer (conditional: not with WEF)" in w for w in res["warnings"])
    assert pipeline.status_for(res) == "needs-review"


def test_ambiguous_not_applied(fmap, no_llm):
    res = pipeline.convert_query("index=wineventlog | stats count by Account_Name", "kql")
    assert "Account_Name" in res["query"] and res["field_map"] == {}
    assert any("ambiguous" in w and "TargetUserName, SubjectUserName" in w for w in res["warnings"])


def test_created_fields_are_never_renamed(fmap, no_llm):
    """`host` is created by eval here, so it is not the source field."""
    res = pipeline.convert_query('index=wineventlog | eval host = "x" | stats count by host', "kql")
    assert "extend host = " in res["query"] and res["field_map"] == {}


def test_known_columns_untouched(fmap, no_llm):
    res = pipeline.convert_query("index=wineventlog EventID=1 | stats count by Computer", "kql")
    assert res["field_map"] == {}


def test_client_overrides_shared(fmap, monkeypatch, no_llm):
    (fmap / "clients" / "acme").mkdir(parents=True)
    (fmap / "clients" / "acme" / "field_map.json").write_text(json.dumps({"kql": {"SecurityEvent": {
        "fields": {"host": {"to": "Computer", "level": "exact"}}}}}))
    monkeypatch.setattr(config, "CLIENT", "acme")
    res = pipeline.convert_query("index=wineventlog | stats count by host | sort - count", "kql")
    assert res["field_map"]["host"]["level"] == "exact"
    assert not any("conditional" in w for w in res["warnings"])


def test_field_map_change_reconverts(fmap, workspace, no_llm):
    p = config.SRC_DIR / "w" / "a.spl"
    p.parent.mkdir(parents=True)
    p.write_text("index=wineventlog | stats count by host")
    assert pipeline.run(["kql"], workers=1) != {"skipped": 1}
    assert pipeline.run(["kql"], workers=1) == {"skipped": 1}
    (fmap / "field_map.json").write_text(json.dumps({"kql": {}}))
    assert pipeline.run(["kql"], workers=1) != {"skipped": 1}


def test_llm_prompt_gets_field_hints(fmap):
    from siemx import llm
    hints = llm.field_hints("index=wineventlog | transaction host | where EventCode=1", "kql")
    assert hints["table"] == "SecurityEvent" and set(hints["fields"]) == {"host", "EventCode"}
    assert "Field mapping for this table" in llm.build_prompt("index=wineventlog | transaction host", "kql")


# ---- the repo's shared map ---------------------------------------------------------------------------

def test_repo_field_map_columns_exist_and_have_evidence():
    data = json.loads((REPO / "mappings" / "field_map.json").read_text())
    fields = set(json.loads((REPO / "mappings" / "fields.json").read_text())["kql"]["SecurityEvent"]["fields"])
    section = data["kql"]["SecurityEvent"]
    assert section["sources"] and all(s.startswith("https://learn.microsoft.com/") for s in section["sources"])
    for name, e in section["fields"].items():
        assert e["level"] in fieldmap.LEVELS, name
        cols = [e["to"]] if "to" in e else e["candidates"]
        assert cols and set(cols) <= fields, name
        assert e.get("note"), name
        assert e["level"] != "exact", "shared defaults are not exact: exact comes from a client's config"


# ---- props.conf import ----------------------------------------------------------------------------------

PROPS = """# SAMPLE props.conf (synthetic, for tests)
[XmlWinEventLog:Security]
FIELDALIAS-user = TargetUserName AS user
FIELDALIAS-net = IpAddress AS src_ip IpPort AS src_port
EVAL-src = coalesce(IpAddress, WorkstationName)
EVAL-dest = Computer
EVAL-action = case(EventCode=4624, "success", EventCode=4625, "failure")
FIELDALIAS-other = SomethingElse AS not_a_column
# FIELDALIAS-commented = Computer AS commented

[WinEventLog:Security]
FIELDALIAS-user = Account_Name AS user
"""


def test_parse_props_one_stanza():
    p = fieldmap.parse_props(PROPS, "XmlWinEventLog:Security")
    assert p["user"] == {"from": ["TargetUserName"], "how": "FIELDALIAS"}
    assert p["src_ip"]["from"] == ["IpAddress"] and p["src_port"]["from"] == ["IpPort"]
    assert p["src"] == {"from": ["IpAddress", "WorkstationName"], "how": "EVAL coalesce"}
    assert p["dest"]["from"] == ["Computer"]
    assert "action" not in p and "commented" not in p          # logic / comments skipped


def test_entries_from_props_only_real_columns():
    cols = set(json.loads((REPO / "mappings" / "fields.json").read_text())["kql"]["SecurityEvent"]["fields"])
    e = fieldmap.entries_from_props(fieldmap.parse_props(PROPS, "XmlWinEventLog:Security"), cols, "props.conf")
    assert e["user"] == {"to": "TargetUserName", "level": "exact", "note": "FIELDALIAS in props.conf"}
    assert e["src"]["level"] == "ambiguous" and e["src"]["candidates"] == ["IpAddress", "WorkstationName"]
    assert "not_a_column" not in e


def test_cli_import_props(fmap, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(config, "ROOT", tmp_path)
    props = tmp_path / "props.conf"
    props.write_text(PROPS)
    monkeypatch.setattr("sys.argv", ["siemx", "fields", "import-props", str(props), "--stanza",
                                     "XmlWinEventLog:Security", "--client", "acme",
                                     "--table", "SecurityEvent"])
    cli.main()
    out = json.loads(capsys.readouterr().out)
    assert out["exact"] == 4 and out["ambiguous"] == 1 and out["skipped_not_a_column"] == ["not_a_column"]
    written = json.loads((fmap / "clients" / "acme" / "field_map.json").read_text())
    assert written["kql"]["SecurityEvent"]["fields"]["user"]["to"] == "TargetUserName"
    config.set_client(None)
