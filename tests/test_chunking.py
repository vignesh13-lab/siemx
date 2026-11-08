"""RAG step B: structure-aware chunking with contextual headers and metadata."""
import json

import pytest

from siemx import chunking

META = {"lang": "kql", "kind": "operator", "slug": "summarize-operator",
        "cite_url": "https://learn.microsoft.com/en-us/kusto/query/summarize-operator"}

PAGE = """# summarize operator

Produces a table that aggregates the content of the input table.

## Syntax

*T* `| summarize` [*Column* `=`] *Aggregation* [`by` *GroupExpression*]

## Examples

### Count per state

```kusto
StormEvents
## not a heading: inside a code block
| summarize count() by State
```
"""


@pytest.mark.parametrize("title, lang, name", [
    ("summarize operator", "kql", "summarize"),
    ("arg_max() (aggregation function)", "kql", "arg_max"),
    ("project-rename operator", "kql", "project-rename"),
    ("stats", "spl", "stats"),
    ("comp", "xql", "comp"),
    ("count (with comp stage)", "xql", "count"),
    ("", "kql", ""),
])
def test_page_name(title, lang, name):
    assert chunking.page_name(title, lang) == name


def test_markdown_escapes_removed_from_titles_and_names():
    """XQL pages are titled 'count\\_distinct'; the name must be count_distinct."""
    chunks = chunking.chunk_page("# count\\_distinct\n\nCounts distinct values.",
                                 {"lang": "xql", "kind": "function", "slug": "count_distinct",
                                  "cite_url": "u"})
    assert chunks[0].title == "count_distinct" and chunks[0].names == ["count_distinct"]
    assert chunks[0].text.startswith("[XQL] count_distinct > Overview")


def test_sections_follow_headings_and_ignore_code():
    title, parts = chunking.sections(PAGE)
    assert title == "summarize operator"
    assert [p for p, _ in parts] == [[], ["Syntax"], ["Examples", "Count per state"]]
    assert "## not a heading" in parts[2][1]


def test_chunk_page_headers_and_metadata():
    chunks = chunking.chunk_page(PAGE, META)
    assert [c.section for c in chunks] == ["Overview", "Syntax", "Examples > Count per state"]
    c = chunks[1]
    assert c.text.startswith("[KQL] summarize operator > Syntax\n\n*T* `| summarize`")
    assert (c.id, c.lang, c.kind, c.names, c.url) == (
        "kql/summarize-operator#1", "kql", "operator", ["summarize"], META["cite_url"])
    assert c.chars == len(c.text)


def test_function_headings_add_names():
    page = "# Text functions\n\n## len(<str>)\n\nReturns the length." + " x" * 50 + \
           "\n\n## lower(<str>)\n\nLower case." + " y" * 50
    chunks = chunking.chunk_page(page, {"lang": "spl", "kind": "eval-functions",
                                        "slug": "text-functions", "cite_url": "u"})
    assert [c.names for c in chunks] == [["text", "len"], ["text", "lower"]]


def test_long_section_split_at_blank_lines_not_inside_code():
    code = "```\n" + "\n\n".join(f"line {i}" for i in range(40)) + "\n```"   # blank lines inside
    para = ("word " * 60).strip()
    page = "# t\n\n## S\n\n" + "\n\n".join([para] * 6) + "\n\n" + code
    chunks = chunking.chunk_page(page, {**META, "lang": "kql"}, max_chars=700)
    assert len(chunks) > 1
    assert all(c.chars <= 700 or "```" in c.text for c in chunks)
    code_chunks = [c for c in chunks if "```" in c.text]
    assert len(code_chunks) == 1 and code_chunks[0].text.count("```") == 2   # code kept whole


def test_big_table_split_by_rows_with_header_repeated():
    rows = "\n".join(f"| zone_{i:03d} | UTC+{i % 12} | description of zone {i} |" for i in range(200))
    page = f"# timezone\n\n## Zones\n\n| Name | Offset | Description |\n|--|--|--|\n{rows}"
    chunks = chunking.chunk_page(page, META, max_chars=800)
    assert len(chunks) > 5 and all(c.chars <= 800 for c in chunks)
    for c in chunks:
        assert "| Name | Offset | Description |\n|--|--|--|" in c.text      # header kept
    assert sum(c.text.count("| zone_") for c in chunks) == 200            # no row lost


def test_huge_code_block_split_and_refenced_but_medium_kept_whole():
    huge = "```kusto\n" + "\n".join(f"print {i}, {'x' * 40}" for i in range(200)) + "\n```"
    medium = "```kusto\n" + "\n".join(f"print {i}" for i in range(150)) + "\n```"
    chunks = chunking.chunk_page(f"# t\n\n## A\n\n{huge}\n\n## B\n\n{medium}", META, max_chars=700)
    a = [c for c in chunks if c.section == "A"]
    b = [c for c in chunks if c.section == "B"]
    assert len(a) > 1 and all(c.text.count("```") == 2 and c.chars <= 700 for c in a)
    assert len(b) == 1                                    # <= 3x limit: complete example kept


def test_huge_single_line_truncated_with_marker():
    coords = "let p = dynamic([" + ", ".join(f"[{i}.123456,{i}.654321]" for i in range(600)) + "]);"
    chunks = chunking.chunk_page(f"# t\n\n## A\n\n```kusto\n{coords}\nprint p\n```", META, max_chars=700)
    assert all(c.chars <= 700 for c in chunks)
    assert any(chunking.TRUNCATED in c.text for c in chunks)
    assert any("print p" in c.text for c in chunks)


def test_run_the_query_links_dropped():
    page = ('# t\n\n## A\n\n> <a href="https://dataexplorer.azure.com/clusters/help?query=H4sI'
            + "A" * 3000 + '" target="_blank">Run the query</a>\n\nReal text stays.')
    chunks = chunking.chunk_page(page, META)
    assert len(chunks) == 1 and "Run the query" not in chunks[0].text
    assert "Real text stays." in chunks[0].text


def test_long_paragraph_split_by_sentences():
    para = " ".join(f"Sentence number {i} explains something important." for i in range(80))
    chunks = chunking.chunk_page(f"# t\n\n## S\n\n{para}", META, max_chars=600)
    assert len(chunks) > 3 and all(c.chars <= 600 for c in chunks)
    assert all(c.text.rstrip().endswith(".") for c in chunks)


def test_tiny_tail_merged_into_previous_chunk():
    para = ("word " * 60).strip()
    page = f"# t\n\n## S\n\n{para}\n\n{para}\n\nok."
    chunks = chunking.chunk_page(page, META, max_chars=400)
    assert chunks[-1].text.endswith("ok.") and not any(c.text.endswith("> S\n\nok.") for c in chunks)


def test_build_and_load(tmp_path):
    raw = tmp_path / "raw"
    (raw / "kql").mkdir(parents=True)
    (raw / "kql" / "operator__summarize-operator.md").write_text(PAGE, encoding="utf-8")
    (raw / "_manifest.json").write_text(json.dumps(
        {"kql/operator__summarize-operator.md": META, "kql/missing.md": META}))
    out = tmp_path / "index" / "chunks.jsonl"
    stats = chunking.build(raw, out)
    assert stats == {"pages": 1, "chunks": 3, "per_lang": {"kql": 3}}
    loaded = chunking.load(out)
    assert [c.id for c in loaded] == [f"kql/summarize-operator#{i}" for i in range(3)]
