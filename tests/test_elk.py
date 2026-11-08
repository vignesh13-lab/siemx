"""Elastic / Kibana KQL ("elk"): grammar port, SPL -> ELK, ELK -> SPL. No network."""
import json

import pytest

from siemx import config, elk, llm, pipeline, reverse_elk

BS = "\\"


# ---- parser: behaviour of Kibana's grammar.peggy -----------------------------------------------

def lit(text, quoted=False, kind="str"):
    return elk.Lit(text, quoted, kind)


def test_and_binds_tighter_than_or():
    assert elk.parse("a: 1 and b: 2 or c: 3") == (
        "or", [("and", [("is", lit("a"), lit("1")), ("is", lit("b"), lit("2"))]),
               ("is", lit("c"), lit("3"))])


def test_not_binds_to_the_next_term():
    assert elk.parse("not a: 1 and b: 2")[0] == "and"


def test_value_list_expands_per_field():
    ast = elk.parse("m: (GET OR post and not x)")
    assert ast == ("or", [("is", lit("m"), lit("GET")),
                          ("and", [("is", lit("m"), lit("post")),
                                   ("not", ("is", lit("m"), lit("x")))])])


@pytest.mark.parametrize("bad", ["a:1 b:2", 'a: "open', "", "a: (b", f"p: *{BS}cmd.exe"])
def test_invalid_queries(bad):
    """No implicit AND; a lone backslash before an ordinary letter is not an escape."""
    with pytest.raises(elk.ParseError):
        elk.parse(bad)


def test_star_inside_quotes_is_literal_and_escaped_star_too():
    assert elk.parse('a: "x*y"')[2] == lit("x*y", True)
    assert elk.parse(f"a: x{BS}*y")[2] == lit("x*y")
    assert elk.parse("a: x*y")[2] == lit(f"x{elk.WILD}y", kind="wild")


def test_special_literals_and_free_text():
    assert elk.parse("a: null")[2].kind == "null"
    assert elk.parse("a: true")[2].kind == "true"
    assert elk.parse("free text") == ("is", None, lit("free text"))


def test_keyword_inside_a_word_is_not_a_keyword():
    assert elk.parse("cannot: x") == ("is", lit("cannot"), lit("x"))


def test_nested_and_range():
    assert elk.parse('u: { f: "A" and l: "W" }')[0] == "nested"
    assert elk.parse("b > 10 and b <= 20")[1][1] == ("range", lit("b"), "<=", lit("20"))


def test_validator_flags_pipes_and_unquoted_spaces():
    assert "no pipeline" in elk.problems("event.code: 4625 | stats count by user")[0]
    assert "unquoted value with spaces" in elk.problems("a: two words")[0]
    assert elk.problems("a: two* words") == []          # wildcards cannot be quoted
    assert elk.problems('a: "two words" and b > 3') == []


# ---- SPL -> ELK ----------------------------------------------------------------------------------

@pytest.fixture
def elk_sources(workspace, sources_map):
    sources_map.write_text(json.dumps({"sourcetype=XmlWinEventLog:Security": {
        "kql": "SecurityEvent", "elk": "logs-system.security-*"}}))
    config.MAPPINGS_DIR.mkdir(parents=True, exist_ok=True)


def spl_to_elk(spl):
    return pipeline.convert_query(spl, "elk")


@pytest.mark.parametrize("spl, want", [
    ("sourcetype=XmlWinEventLog:Security EventCode=4625", "EventCode: 4625"),
    ("sourcetype=XmlWinEventLog:Security user!=admin*", "user: * and not user: admin*"),
    ("sourcetype=XmlWinEventLog:Security NOT user=SYSTEM", 'not (user: "SYSTEM")'),
    ("sourcetype=XmlWinEventLog:Security EventCode IN (4624, 4625)", "EventCode: (4624 or 4625)"),
    ("sourcetype=XmlWinEventLog:Security a=1 (b=x OR c=y)", 'a: 1 and (b: "x" or c: "y")'),
    ("sourcetype=XmlWinEventLog:Security bytes>100", "bytes > 100"),
    ("sourcetype=XmlWinEventLog:Security f=*", "f: *"),
    ('sourcetype=XmlWinEventLog:Security t="*(2)"', f"t: *{BS}(2{BS})"),
    ('sourcetype=XmlWinEventLog:Security p="*\\\\cmd.exe"', f"p: *{BS}{BS}cmd.exe"),
    ('sourcetype=XmlWinEventLog:Security p="a \\"b\\""', f'p: "a {BS}"b{BS}""'),
])
def test_spl_to_elk(elk_sources, spl, want):
    r = spl_to_elk(spl)
    assert r["query"] == want and r["method"] == "rules" and r["index"] == "logs-system.security-*"
    assert elk.problems(r["query"]) == []


def test_keyword_inside_a_wildcard_value_is_escaped(elk_sources):
    r = spl_to_elk('sourcetype=XmlWinEventLog:Security c="*a or b*"')
    assert r["query"] == f"c: *a {BS}u006fr b*"
    assert elk.parse(r["query"])[2] == lit(f"{elk.WILD}a or b{elk.WILD}", kind="wild")


def test_every_rule_output_parses_back_to_the_same_values(elk_sources):
    from siemx import search
    for v in ["x(1)", "a:b", 'q\\"t', "c:\\\\w", "{x}", "<>", "not here", "AND"]:
        spl = f'sourcetype=XmlWinEventLog:Security f="*{v}"'
        spl_value = search.parse(spl)[1][3]
        parsed = elk.parse(spl_to_elk(spl)["query"])[2]
        assert parsed == lit(spl_value.replace("*", elk.WILD), kind="wild"), v


def test_review_warnings(elk_sources):
    r = spl_to_elk("index=clienta sourcetype=XmlWinEventLog:Security user=bob")
    text = " ".join(r["warnings"])
    assert "index=clienta was dropped" in text and "case-sensitively" in text
    assert "field names kept from Splunk (user)" in text
    assert pipeline.status_for(r) == "needs-review"


def test_unmapped_source_still_converts_but_is_flagged(workspace):
    r = spl_to_elk("index=X sourcetype=Y EventCode=4688")
    assert r["query"] == "EventCode: 4688"
    assert r["warnings"][0].startswith("ELK: no index pattern for index=x sourcetype=y")


def test_display_stages_are_dropped_with_a_warning(elk_sources):
    r = spl_to_elk("sourcetype=XmlWinEventLog:Security EventCode=1 | search user=a | table user "
                   "| sort user")
    assert r["query"] == 'EventCode: 1 and user: "a"'
    assert r["warnings"][0].startswith("ELK: `table`, `sort` dropped")


def test_transforming_stage_leaves_only_the_filter_and_unsupported(elk_sources, monkeypatch):
    monkeypatch.setattr(llm, "translate", lambda *a, **k: pytest.fail("no LLM for stats"))
    r = spl_to_elk("sourcetype=XmlWinEventLog:Security EventCode=4625 | stats count by user "
                   "| where count > 10")
    assert r["query"] == "EventCode: 4625" and pipeline.status_for(r) == "unsupported"
    assert "`stats`, `where` have no equivalent" in r["warnings"][0]
    assert r["no_rule"] == ["stats", "where"]


def test_a_search_after_a_transform_is_not_part_of_the_filter(elk_sources):
    r = spl_to_elk("sourcetype=XmlWinEventLog:Security a=1 | eval x=1 | search x=1")
    assert r["query"] == "a: 1" and r["unsupported"]


def test_filter_gap_goes_to_the_llm(elk_sources, monkeypatch):
    calls = []
    monkeypatch.setattr(llm, "translate", lambda text, target, **k: calls.append(target) or
                        {"query": 'message: "x"', "confidence": 0.5, "warnings": []})
    r = spl_to_elk('sourcetype=XmlWinEventLog:Security "free text"')
    assert calls == ["elk"] and r["method"] == "llm" and pipeline.status_for(r) == "needs-review"
    assert r["no_rule"] == ["search"]


def test_field_map_for_elk(elk_sources):
    (config.MAPPINGS_DIR / "field_map.json").write_text(json.dumps({"elk": {
        "logs-system.security-*": {"fields": {
            "EventCode": {"to": "event.code", "level": "exact"},
            "user": {"level": "ambiguous", "candidates": ["user.name", "user.target.name"]}}}}}))
    r = spl_to_elk("sourcetype=XmlWinEventLog:Security EventCode=4625 user=bob")
    assert r["query"] == 'event.code: 4625 and user: "bob"'
    assert r["field_map"] == {"EventCode": "event.code"}
    assert any("'user' is ambiguous: one of user.name" in w for w in r["warnings"])


def test_elk_prompt_uses_the_reference_not_the_rag_index(workspace):
    p = llm.build_prompt("index=a | where x=1", "elk")
    assert "Kibana Query Language" in p and elk.DOC in p and "answer unsupported" in p


# ---- ELK -> SPL ----------------------------------------------------------------------------------

def elk_to_spl(text):
    return pipeline.convert_any(text, "spl", source="elk")


def test_header_maps_the_index_pattern_to_a_splunk_source(elk_sources):
    r = elk_to_spl("# index: logs-system.security-*\n"
                   f"EventCode: 4688 and Process: (*{BS}{BS}powershell.exe or *{BS}{BS}cmd.exe)")
    assert r["query"] == ('sourcetype=XmlWinEventLog:Security EventCode=4688 AND '
                          '(Process="*\\\\powershell.exe" OR Process="*\\\\cmd.exe")')
    assert pipeline.status_for(r) == "needs-review"


def test_round_trip(elk_sources):
    src = f"EventCode: 4688 and (Process: *{BS}{BS}powershell.exe or Process: *{BS}{BS}cmd.exe)"
    spl = elk_to_spl("# index: logs-system.security-*\n" + src)["query"]
    assert spl_to_elk(spl)["query"] == src


@pytest.mark.parametrize("q, want", [
    ("a > 10 and not b: *", "a>10 AND NOT (b=*)"),
    ("not a: 1 or b: 2", "NOT (a=1) OR b=2"),
    ('a: "has \\"q\\""', 'a="has \\"q\\""'),
    ("a: (x or y)", "a=x OR a=y"),
])
def test_elk_to_spl_without_header(workspace, q, want):
    r = elk_to_spl(q)
    assert r["query"] == want and "names no index pattern" in r["warnings"][0]


@pytest.mark.parametrize("q, reason", [
    ('m: "x*"', "literal *"), (f"m: x{BS}*y*", "literal *"), ("free text", "free-text"),
    ("u: { a: 1 }", "nested"), ('t > "2026-01-01"', "range on a non-number"),
    ("a: null", "null"), ("a*: 1", "wildcard"),
])
def test_elk_constructs_without_a_rule(workspace, q, reason):
    r = elk_to_spl(q)
    assert r["unsupported"] and reason in r["warnings"][0]


def test_invalid_or_unmapped_input_never_reaches_the_llm(workspace, monkeypatch):
    monkeypatch.setattr(llm, "translate", lambda *a, **k: pytest.fail("must not call the LLM"))
    assert "invalid Kibana KQL" in elk_to_spl("a:1 b:2")["warnings"][0]
    assert "no SPL source" in elk_to_spl("# index: logs-x-*\na: 1")["warnings"][0]
    assert elk_to_spl("free text")["unsupported"]             # no header -> no base for the LLM


def test_rule_gap_with_a_mapped_index_goes_to_the_llm(elk_sources, monkeypatch):
    seen = {}
    monkeypatch.setattr(llm, "translate", lambda text, target, **k: seen.update(k) or
                        {"query": "sourcetype=XmlWinEventLog:Security x", "confidence": 0.5,
                         "warnings": []})
    r = elk_to_spl("# index: logs-system.security-*\nfree text")
    assert seen["base"] == "sourcetype=XmlWinEventLog:Security" and seen["source"] == "elk"
    assert "Elastic index pattern's column names (logs-system.security-*)" in r["warnings"][-1]


def test_cli_files(elk_sources):
    d = config.SRC_DIR.parent / "elk" / "win"
    d.mkdir(parents=True)
    (d / "q.elk").write_text("# index: logs-system.security-*\nEventCode: 1\n")
    assert pipeline.run(["spl"], workers=1, source="elk") == {"needs-review": 1}
    assert (config.OUT_DIR / "spl" / "win" / "q.spl").read_text().strip() == (
        "sourcetype=XmlWinEventLog:Security EventCode=1")
