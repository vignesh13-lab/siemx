"""RAG step A: corpus discovery, cleaning and fetching. No network: http_get is faked."""
import json

import pytest

from siemx import config, docs

SPLUNK_PAGE = """<html><head><script>var x = 1;</script></head><body>
<nav><h2 class="splunk-dropdown-title">Splunk Enterprise</h2></nav>
<h1 class="title topictitle1">stats</h1>
<article class="topic nested1">
 <h2 class="title topictitle2 h2">Description</h2>
 <p>Calculates   aggregate statistics, such as <code>count</code>.</p>
 <h2 class="title topictitle2 h2">Syntax</h2>
 <pre>stats count BY host
| sort - count</pre>
 <ul><li>first</li><li>second</li></ul>
 <table><tr><th>Name</th><th>Type</th></tr><tr><td>count</td><td>int</td></tr></table>
</article>
<div class="dropdown social-sharing-container">Share this page</div>
<div class="right-nav"><ul class="toc-subtree"><li>Description</li></ul></div>
</body></html>"""


def test_splunk_html_to_md_keeps_only_the_article():
    md = docs.splunk_html_to_md(SPLUNK_PAGE)
    assert md.startswith("# stats\n")
    assert "## Description" in md and "## Syntax" in md
    assert "Calculates aggregate statistics, such as `count`." in md   # whitespace collapsed
    assert "```\nstats count BY host\n| sort - count\n```" in md        # code kept verbatim
    assert "- first" in md and "- second" in md
    assert "| Name | Type |" in md and "| count | int |" in md
    for noise in ("var x", "Splunk Enterprise", "Share this page", "toc-subtree"):
        assert noise not in md


def test_page_without_article_title_is_empty():
    assert docs.splunk_html_to_md("<html><body><p>menu</p></body></html>").strip() == ""


MS_PAGE = """---
title:  arg_max() (aggregation function)
description: Learn how to use arg_max().
ms.reviewer: someone
---
# arg_max() (aggregation function)

> [!INCLUDE [applies](../includes/applies.md)] [!INCLUDE [fabric](../includes/fabric.md)]

::: moniker range="azure-data-explorer"
Finds a row.
::: moniker-end

> [!NOTE]
> Null values are ignored.
"""


def test_clean_ms_markdown():
    md = docs.clean_ms_markdown(MS_PAGE)
    assert md.startswith("# arg_max() (aggregation function)\n\nLearn how to use arg_max().\n")
    assert "ms.reviewer" not in md and "INCLUDE" not in md and ":::" not in md
    assert "Finds a row." in md                       # content inside moniker kept
    assert "> NOTE:" in md and "> Null values are ignored." in md


def test_clean_xql_drops_index_banner():
    body = "> For the complete documentation index, see llms.txt ...\n\n# comp\n\nAggregates."
    assert docs.clean({"lang": "xql"}, body) == "# comp\n\nAggregates.\n"


# ---- discover --------------------------------------------------------------------------

def fake_get(pages):
    def get(url):
        if url not in pages:
            raise AssertionError(f"unexpected URL {url}")
        return pages[url]
    return get


def test_discover_kql():
    tree = {"tree": [
        {"path": "data-explorer/kusto/query/summarize-operator.md"},
        {"path": "data-explorer/kusto/query/arg-max-aggregation-function.md"},
        {"path": "data-explorer/kusto/query/index.md"},                 # skipped
        {"path": "data-explorer/kusto/query/includes/x.md"},            # nested: skipped
        {"path": "data-explorer/kusto/management/alter.md"},            # other folder
    ]}
    out = docs.discover_kql(fake_get({docs.KQL_TREE: json.dumps(tree)}))
    assert [(s["slug"], s["kind"]) for s in out] == [
        ("summarize-operator", "operator"), ("arg-max-aggregation-function", "aggregation-function")]
    assert out[0]["cite_url"] == "https://learn.microsoft.com/en-us/kusto/query/summarize-operator"
    assert out[0]["fetch_url"].startswith("https://raw.githubusercontent.com/MicrosoftDocs/")


def test_discover_xql_dedups_and_skips_lists():
    base = "https://cortex-docs.paloaltonetworks.com/xql-command-reference-guide/readme"
    sitemap = (f"- {base}/stages/comp.md\n- {base}/stages/comp.md\n- {base}/functions/len.md\n"
               f"- {base}/stages/stages-list.md\n- https://cortex-docs.paloaltonetworks.com/other/x.md")
    out = docs.discover_xql(fake_get({docs.XQL_INDEX: sitemap}))
    assert [(s["kind"], s["slug"]) for s in out] == [("stage", "comp"), ("function", "len")]
    assert out[0]["cite_url"] == f"{base}/stages/comp"


def test_discover_spl():
    pages = {docs.SPL_BASE + sec: "" for sec in docs.SPL_SECTIONS}
    pages[docs.SPL_BASE + "search-commands"] = (
        '<a href="/x/spl-search-reference/9.4/search-commands/stats">'
        '<a href="/x/spl-search-reference/9.4/search-commands/stats">'
        '<a href="/x/spl-search-reference/9.4/search-commands/search-commands">'
        '<a href="/x/spl-search-reference/9.4/search-commands/eval">')
    out = docs.discover_spl(fake_get(pages))
    assert [s["slug"] for s in out] == ["eval", "stats"]
    assert all(s["kind"] == "command" for s in out)


# ---- fetch --------------------------------------------------------------------------------

@pytest.fixture
def rag_root(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "ROOT", tmp_path)
    return tmp_path


SRC = [{"lang": "xql", "kind": "stage", "slug": "comp", "fetch_url": "u1", "cite_url": "c1"},
       {"lang": "xql", "kind": "function", "slug": "len", "fetch_url": "u2", "cite_url": "c2"}]


def test_fetch_writes_pages_and_manifest(rag_root):
    body = "# comp\n\n" + "Aggregates rows. " * 20
    stats = docs.fetch(SRC, get=fake_get({"u1": body, "u2": body}), delay=0, log=lambda m: None)
    assert stats == {"fetched": 2, "skipped": 0, "failed": 0}
    assert (rag_root / "rag/raw/xql/stage__comp.md").read_text().startswith("# comp")
    manifest = json.loads((rag_root / "rag/raw/_manifest.json").read_text())
    assert manifest["xql/stage__comp.md"]["cite_url"] == "c1"
    assert len(manifest["xql/stage__comp.md"]["sha256"]) == 16


def test_fetch_skips_existing_and_reports_failures(rag_root):
    body = "# comp\n\n" + "Aggregates rows. " * 20
    docs.fetch(SRC[:1], get=fake_get({"u1": body}), delay=0, log=lambda m: None)
    logs = []

    def get(url):
        raise OSError("network down")

    stats = docs.fetch(SRC, get=get, delay=0, log=logs.append)
    assert stats == {"fetched": 0, "skipped": 1, "failed": 1}
    assert "FAILED u2" in logs[0]


def test_interrupted_run_is_recovered(rag_root):
    """A page on disk but missing from the manifest (run stopped before the manifest
    was saved) is re-recorded instead of being silently left out of the index."""
    page = rag_root / "rag/raw/xql/stage__comp.md"
    page.parent.mkdir(parents=True)
    page.write_text("# comp\n\nsaved before the interruption", encoding="utf-8")
    stats = docs.fetch(SRC[:1], get=fake_get({}), delay=0, log=lambda m: None)
    assert stats == {"fetched": 0, "skipped": 1, "failed": 0}
    manifest = json.loads((rag_root / "rag/raw/_manifest.json").read_text())
    assert manifest["xql/stage__comp.md"]["cite_url"] == "c1"


def test_fetch_runs_workers_in_parallel(rag_root):
    import threading
    import time
    active, peak, lock = [0], [0], threading.Lock()

    def slow_get(url):
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        time.sleep(0.05)
        with lock:
            active[0] -= 1
        return "# page\n\n" + "text " * 60

    srcs = [dict(SRC[0], slug=f"s{i}", fetch_url=f"u{i}") for i in range(8)]
    stats = docs.fetch(srcs, get=slow_get, delay=0, log=lambda m: None, workers=4)
    assert stats["fetched"] == 8 and peak[0] > 1


def test_fetch_rejects_pages_that_clean_to_almost_nothing(rag_root):
    stats = docs.fetch(SRC[:1], get=fake_get({"u1": "# x"}), delay=0, log=lambda m: None)
    assert stats["failed"] == 1


def test_sources_roundtrip(rag_root):
    docs.save_sources(SRC)
    data = json.loads((rag_root / "rag/sources.json").read_text())
    assert data["counts"] == {"xql": 2}
    assert docs.load_sources("xql") == SRC and docs.load_sources("kql") == []
