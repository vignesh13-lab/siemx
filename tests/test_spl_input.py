"""SPL input forms that mean the same search: comments and a leading `search` command."""
import pytest

from siemx import llm, pipeline, triage

W = "index=wineventlog"


@pytest.mark.parametrize("raw, normal", [
    (f"search {W} EventID=4625", f"{W} EventID=4625"),
    (f"| search {W} EventID=4625", f"{W} EventID=4625"),
    (f"  SEARCH {W} EventID=4625", f"{W} EventID=4625"),
    (f"{W} EventID=4625 ```failed logons```", f"{W} EventID=4625"),
    (f"```why``` {W} | stats count by host", f"{W} | stats count by host"),
    (f'{W} c="```not a comment```"', f'{W} c="```not a comment```"'),
    (f'{W} c="say \\"```\\""', f'{W} c="say \\"```\\""'),
    (f"{W} EventID=4625 ```unterminated", f"{W} EventID=4625 ```unterminated"),
    ("| tstats count where index=x by host", "| tstats count where index=x by host"),
    (f"searchable=1 {W}", f"searchable=1 {W}"),
])
def test_normalize(raw, normal):
    assert triage.normalize_spl(raw) == normal


@pytest.mark.parametrize("spl", [
    f"search {W} EventID=4625 | stats count by host",
    f"| search {W} EventID=4625 | stats count by host",
    f"{W} EventID=4625 ```failed logons``` | stats count by host",
])
def test_same_result_as_the_plain_form(sources_map, monkeypatch, spl):
    monkeypatch.setattr(llm, "translate", lambda *a, **k: pytest.fail("rules handle this"))
    plain = pipeline.convert_query(f"{W} EventID=4625 | stats count by host", "kql")
    assert pipeline.convert_query(spl, "kql")["query"] == plain["query"]
