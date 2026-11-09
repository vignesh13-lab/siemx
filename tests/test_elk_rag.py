"""Elastic documentation in the RAG corpus: discovery, cleaning, chunking, retrieval."""
import json

from siemx import chunking, docs, llm
from siemx import retrieve as rag
from siemx.chunking import Chunk


def fake_get(pages):
    def get(url):
        if url not in pages:
            raise AssertionError(f"unexpected URL {url}")
        return pages[url]
    return get


# ---- discover --------------------------------------------------------------------------------

def test_discover_elk_lists_language_rules_and_ecs_field_sets():
    tree = {"tree": [{"path": "docs/reference/ecs-event.md"},
                     {"path": "docs/reference/ecs-process.md"},
                     {"path": "docs/reference/ecs-field-reference.md"},       # guide page
                     {"path": "docs/reference/ecs-allowed-values-event-kind.md"},
                     {"path": "docs/reference/ecs-user-usage.md"},
                     {"path": "docs/reference/ecs-ecs.md"},
                     {"path": "docs/reference/index.md"},
                     {"path": "docs/other/ecs-event.md"}]}
    out = docs.discover_elk(fake_get({docs.ECS_TREE: json.dumps(tree)}))
    kinds = [(s["kind"], s["slug"]) for s in out]
    assert ("language", "kql") in kinds and ("language", "kql-overview") in kinds
    assert ("rules", "threshold") in kinds
    assert [s for k, s in kinds if k == "ecs-fields"] == ["ecs-event", "ecs-process"]
    kql = next(s for s in out if s["slug"] == "kql")
    assert kql["fetch_url"] == ("https://raw.githubusercontent.com/elastic/elasticsearch/main/"
                                "docs/reference/query-languages/kql.md")
    assert kql["cite_url"] == "https://www.elastic.co/docs/reference/query-languages/kql"
    ecs = next(s for s in out if s["slug"] == "ecs-event")
    assert ecs["cite_url"] == "https://www.elastic.co/docs/reference/ecs/ecs-event"
    assert all(s["lang"] == "elk" for s in out)


# ---- clean ------------------------------------------------------------------------------------

RAW = """---
description: Syntax reference for KQL.
applies_to:
  stack: ga
---
% a MyST comment

# {{kib}} Query Language (KQL) syntax reference [kuery-query]

Use it in the {{kib}} query bar or the {{esql}} [`KQL` function](/reference/x.md).

## Wildcards [kql-wildcards] {applies_to}`stack: ga 9.1`

:::{note}
An asterisk inside quotation marks is a literal asterisk.
:::

| Field | Description |
| --- | --- |
| $$$field-event-code$$$ [event.code](#field-event-code) | Identification code.<br><br>type: keyword |
"""


def test_clean_elastic_markdown():
    text = docs.clean({"lang": "elk"}, RAW)
    assert text.startswith("# Kibana Query Language (KQL) syntax reference\n\n"
                           "Syntax reference for KQL.\n")
    assert "Use it in the Kibana query bar or the ES|QL `KQL` function." in text
    assert "## Wildcards\n" in text
    assert "NOTE:\nAn asterisk inside quotation marks is a literal asterisk." in text
    assert "| event.code | Identification code. type: keyword |" in text
    for leftover in ("{{", "$$$", ":::", "applies_to", "% a MyST", "[kuery-query]", "](/"):
        assert leftover not in text, leftover


def test_elastic_pages_chunk_with_their_own_label():
    meta = {"lang": "elk", "kind": "language", "slug": "kql",
            "cite_url": "https://www.elastic.co/docs/reference/query-languages/kql"}
    chunks = chunking.chunk_page(docs.clean({"lang": "elk"}, RAW), meta)
    assert chunks and all(c.text.startswith("[Elastic] Kibana Query Language") for c in chunks)
    assert {c.lang for c in chunks} == {"elk"}


# ---- retrieval ----------------------------------------------------------------------------------

def chunk(cid, lang, kind, text, names=()):
    full = f"[{lang}] t > s\n\n{text}"
    return Chunk(id=cid, lang=lang, kind=kind, title="t", section="s", names=list(names),
                 url=f"https://x/{cid}", text=full, chars=len(full))


def index():
    return rag.BM25Index([
        chunk("elk/kql#1", "elk", "language", "wildcards: an asterisk matches any characters"),
        chunk("elk/kql#2", "elk", "language", "escape special characters with a backslash"),
        chunk("elk/ecs-event#1", "elk", "ecs-fields",
              "| event.code | Identification code. type: keyword |"),
        chunk("elk/ecs-source#1", "elk", "ecs-fields", "| source.ip | IP address. type: ip |"),
        chunk("kql/where#0", "kql", "operator", "where filters rows", names=["where"]),
        chunk("kql/contains-cs#0", "kql", "operator", "contains_cs", names=["contains_cs"]),
        chunk("kql/startswith-cs#0", "kql", "operator", "startswith_cs", names=["startswith_cs"]),
        chunk("kql/ipv4#0", "kql", "function", "ipv4_is_in_range", names=["ipv4_is_in_range"]),
        chunk("kql/parse#0", "kql", "function", "event code source ip parse"),      # noise
    ])


def test_elk_to_kql_gets_syntax_ecs_fields_and_the_target_operators():
    r = rag.retrieve_elk(index(), "# index: logs-x-*\nevent.code: 4625 and "
                         "source.ip: 10.0.0.0/8 and p: *enc*", "kql", "elk")
    ids = [d["source"].split("https://x/", 1)[1] for d in r.docs]
    assert "elk/kql#1" in ids
    assert "elk/ecs-event#1" in ids and "elk/ecs-source#1" in ids
    assert {"kql/where#0", "kql/contains-cs#0", "kql/ipv4#0"} <= set(ids)
    assert "kql/parse#0" not in ids                    # no keyword noise for this direction


def test_features():
    f = rag.elk_features('a: *x* and not b: (1 or 2) and c: * and d: 10.0.0.0/8')
    assert f == {"wild", "not", "list", "exists", "cidr"}
    assert rag.elk_features("a:1 b:2") == set()        # invalid input: no features


def test_spl_to_elk_gets_elastic_syntax(monkeypatch):
    r = rag.retrieve_elk(index(), "index=a | where x like y wildcards", "elk", "spl")
    assert r.docs[0]["source"].endswith("elk/kql#1")
    assert all(d["lang"] == "elk" for d in r.docs)


def test_llm_prompt_uses_the_index_when_built(monkeypatch):
    monkeypatch.setattr(rag, "get_index", lambda path: index())
    ctx = llm.retrieve("# index: logs-x-*\nevent.code: 1", "kql", source="elk")
    assert ctx["docs"][0]["title"] == "siemx summary of the Kibana KQL syntax docs"
    assert any(d["source"].endswith("elk/ecs-event#1") for d in ctx["docs"][1:])


def test_llm_prompt_without_index_keeps_the_summary(monkeypatch):
    monkeypatch.setattr(rag, "get_index", lambda path: None)
    ctx = llm.retrieve("index=a x=1", "elk")
    assert [d["title"] for d in ctx["docs"]] == ["siemx summary of the Kibana KQL syntax docs"]
