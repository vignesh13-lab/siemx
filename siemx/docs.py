"""RAG step A: build the documentation corpus.

    siemx docs discover   -> rag/sources.json   (committed: URLs only, no doc text)
    siemx docs fetch      -> rag/raw/<lang>/<slug>.md + rag/raw/_manifest.json (git-ignored)

Why only URLs are committed: Microsoft's KQL docs are CC BY 4.0, but Splunk and
Palo Alto docs are copyrighted and this repo is public. Anyone can rebuild the
corpus from the URL list.

Sources (official only):
  KQL  MicrosoftDocs/dataexplorer-docs on GitHub (Markdown), cited as learn.microsoft.com
  XQL  Cortex XQL command reference (pages are served as Markdown with a .md suffix)
  SPL  help.splunk.com SPL search reference 9.4 (HTML, converted to Markdown here)
"""
from __future__ import annotations

import hashlib
import html
import json
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

from . import config

USER_AGENT = "siemx-docs-fetcher"          # generic client name, no personal data
FETCH_DELAY = 0.3                          # seconds between requests (be polite)

KQL_TREE = "https://api.github.com/repos/MicrosoftDocs/dataexplorer-docs/git/trees/main?recursive=1"
KQL_RAW = "https://raw.githubusercontent.com/MicrosoftDocs/dataexplorer-docs/main/{path}"
KQL_CITE = "https://learn.microsoft.com/en-us/kusto/query/{slug}"
XQL_INDEX = "https://cortex-docs.paloaltonetworks.com/sitemap.md"
XQL_PAGE = re.compile(r"https://cortex-docs\.paloaltonetworks\.com/xql-command-reference-guide/"
                      r"readme/(stages|functions)/([a-z0-9_-]+)\.md")
SPL_BASE = "https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/9.4/"
SPL_SECTIONS = {   # index page -> kind
    "search-commands": "command",
    "evaluation-functions": "eval-functions",
    "statistical-and-charting-functions": "stats-functions",
}


def rag_dir() -> Path:
    return config.ROOT / "rag"


def sources_file() -> Path:
    return rag_dir() / "sources.json"


def raw_dir() -> Path:
    return rag_dir() / "raw"


def index_dir() -> Path:
    return rag_dir() / "index"


# ---- network (tests replace http_get) ----------------------------------------------

def http_get(url: str) -> str:
    # help.splunk.com returns 403 without an Accept header (curl sends */*)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode("utf-8", errors="replace")


# ---- discover: build the URL list from the official indexes -------------------------

def discover_kql(get=http_get) -> list[dict]:
    """Every Markdown page directly under data-explorer/kusto/query/."""
    tree = json.loads(get(KQL_TREE))
    out = []
    for item in tree["tree"]:
        p = item["path"]
        if p.startswith("data-explorer/kusto/query/") and p.endswith(".md") and p.count("/") == 3:
            slug = p.rsplit("/", 1)[1][:-3]
            if slug in ("index", "toc"):
                continue
            out.append({"lang": "kql", "kind": _kql_kind(slug), "slug": slug,
                        "fetch_url": KQL_RAW.format(path=p), "cite_url": KQL_CITE.format(slug=slug)})
    return out


def _kql_kind(slug: str) -> str:
    for suffix, kind in (("-aggregation-function", "aggregation-function"),
                         ("-function", "function"), ("-operator", "operator"),
                         ("-plugin", "plugin"), ("-statement", "statement")):
        if slug.endswith(suffix):
            return kind
    return "concept"


def discover_xql(get=http_get) -> list[dict]:
    """Stage and function pages listed in the Cortex sitemap."""
    seen, out = set(), []
    for kind, slug in XQL_PAGE.findall(get(XQL_INDEX)):
        if (kind, slug) in seen or slug.endswith("-list") or slug == "index":
            continue
        seen.add((kind, slug))
        url = (f"https://cortex-docs.paloaltonetworks.com/xql-command-reference-guide/"
               f"readme/{kind}/{slug}.md")
        out.append({"lang": "xql", "kind": "stage" if kind == "stages" else "function",
                    "slug": slug, "fetch_url": url, "cite_url": url[:-3]})
    return out


def discover_spl(get=http_get) -> list[dict]:
    """Search commands and function pages linked from the SPL reference indexes."""
    out = []
    for section, kind in SPL_SECTIONS.items():
        page = get(SPL_BASE + section)
        slugs = sorted(set(re.findall(rf"spl-search-reference/9\.4/{section}/([a-z0-9_-]+)", page)))
        for slug in slugs:
            if slug == section:            # the index page itself
                continue
            url = f"{SPL_BASE}{section}/{slug}"
            out.append({"lang": "spl", "kind": kind, "slug": slug,
                        "fetch_url": url, "cite_url": url})
    return out


def discover(get=http_get) -> list[dict]:
    sources = discover_spl(get) + discover_kql(get) + discover_xql(get)
    sources.sort(key=lambda s: (s["lang"], s["kind"], s["slug"]))
    return sources


# ---- clean: Splunk HTML -> Markdown ------------------------------------------------------

class _SplunkHTML(HTMLParser):
    """Keep only the article: start at <h1 class="... topictitle1">, turn headings,
    lists, code and tables into Markdown, drop scripts/menus/footers."""

    SKIP = {"script", "style", "nav", "button", "svg", "footer", "noscript", "form"}
    # page furniture after the article: share/feedback block, "On this page" TOC
    END_CLASSES = ("social-sharing-anchor", "social-sharing-container", "right-nav")
    HEAD = {"h1": "#", "h2": "##", "h3": "###", "h4": "####", "h5": "#####"}
    BLOCK = {"p", "div", "section", "article", "br", "dl", "dt", "dd", "ul", "ol", "table"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.started = False
        self.skip = 0
        self.pre = 0
        self.done = False

    def handle_starttag(self, tag, attrs):
        cls = dict(attrs).get("class") or ""
        if self.done:
            return
        if self.started and any(c in cls.split() for c in self.END_CLASSES):
            self.done = True
            return
        if not self.started:
            if tag == "h1" and "topictitle1" in cls:
                self.started = True
            else:
                return
        if self.skip or tag in self.SKIP:
            self.skip += tag in self.SKIP
            return
        if tag in self.HEAD:
            self.out.append(f"\n\n{self.HEAD[tag]} ")
        elif tag == "pre":
            self.pre += 1
            self.out.append("\n\n```\n")
        elif tag == "code" and not self.pre:
            self.out.append("`")
        elif tag == "li":
            self.out.append("\n- ")
        elif tag == "tr":
            self.out.append("\n|")
        elif tag in ("td", "th"):
            self.out.append(" ")
        elif tag in self.BLOCK:
            self.out.append("\n")

    def handle_endtag(self, tag):
        if not self.started or self.done:
            return
        if self.skip:
            self.skip -= tag in self.SKIP
            return
        if tag == "pre":
            self.pre -= 1
            self.out.append("\n```\n")
        elif tag == "code" and not self.pre:
            self.out.append("`")
        elif tag in ("td", "th"):
            self.out.append(" |")
        elif tag in self.HEAD or tag in ("p", "table", "ul", "ol"):
            self.out.append("\n")

    def handle_data(self, data):
        if not self.started or self.skip or self.done:
            return
        self.out.append(data if self.pre else re.sub(r"\s+", " ", data))


def splunk_html_to_md(page: str) -> str:
    p = _SplunkHTML()
    p.feed(page)
    text = "".join(p.out)
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return html.unescape(text).strip() + "\n"


def clean(source: dict, body: str) -> str:
    """Raw download -> Markdown text for the corpus."""
    if source["lang"] == "spl":
        return splunk_html_to_md(body)
    if source["lang"] == "xql":   # drop the "complete documentation index" banner line
        body = re.sub(r"\A> For the complete documentation index.*?\n\n", "", body, flags=re.S)
    if source["lang"] == "kql":
        body = clean_ms_markdown(body)
    return body.strip() + "\n"


def clean_ms_markdown(body: str) -> str:
    """Microsoft Learn Markdown -> plain Markdown: drop the YAML front matter (keep
    the description as a line), [!INCLUDE] / moniker / zone directives, and turn
    '> [!NOTE]' style callouts into plain quotes."""
    desc = ""
    m = re.match(r"\A---\n(.*?)\n---\n", body, re.S)
    if m:
        d = re.search(r"^description:\s*(.+)$", m.group(1), re.M)
        desc = d.group(1).strip() if d else ""
        body = body[m.end():]
    lines = []
    for line in body.splitlines():
        s = line.strip()
        if s.startswith(":::") or "[!INCLUDE" in s:
            continue                                  # moniker/zone/include directives
        line = re.sub(r"^(\s*>\s*)\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*$", r"\1\2:", line)
        lines.append(line)
    text = "\n".join(lines)
    if desc:                                          # description right under the title
        text = re.sub(r"\A(\s*# [^\n]+\n)", rf"\1\n{desc}\n", text, count=1)
    return re.sub(r"\n{3,}", "\n\n", text)


# ---- fetch -------------------------------------------------------------------------------

def page_path(source: dict) -> Path:
    return raw_dir() / source["lang"] / f"{source['kind']}__{source['slug']}.md"


def _entry(src: dict, text: str, when: str) -> dict:
    return {**src, "sha256": hashlib.sha256(text.encode()).hexdigest()[:16],
            "fetched": when, "chars": len(text)}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fetch_one(src: dict, get, delay: float) -> str:
    """Download + clean one page (runs in a worker thread). Raises on failure."""
    try:
        text = clean(src, get(src["fetch_url"]))
    finally:
        time.sleep(delay)                     # politeness pause per worker
    # Quality gate for a broken layout (nothing extracted). Short pages are fine:
    # alias pages like "bucket is an alias for bin" are real and useful.
    if not text.startswith("# ") or len(text) < 80:
        raise ValueError("no title or almost no text after cleaning (layout changed?)")
    return text


def fetch(sources: list[dict], refresh: bool = False, get=http_get, delay: float = FETCH_DELAY,
          log=print, workers: int = 4) -> dict:
    """Download + clean pages with a few parallel workers (network-bound work).

    Only the main thread writes files and the manifest, and the manifest is saved
    regularly, so an interrupted run can simply be restarted: existing pages are
    skipped, and a page on disk that is missing from the manifest is re-recorded."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    manifest_file = raw_dir() / "_manifest.json"
    manifest = json.loads(manifest_file.read_text()) if manifest_file.exists() else {}
    stats = {"fetched": 0, "skipped": 0, "failed": 0}

    def save():
        manifest_file.parent.mkdir(parents=True, exist_ok=True)
        manifest_file.write_text(json.dumps(manifest, indent=1, sort_keys=True))

    todo = []
    for src in sources:
        path = page_path(src)
        rel = path.relative_to(raw_dir()).as_posix()
        if path.exists() and not refresh:
            stats["skipped"] += 1
            if rel not in manifest:            # recovered from an interrupted run
                manifest[rel] = _entry(src, path.read_text(encoding="utf-8"), _now())
            continue
        todo.append(src)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(_fetch_one, s, get, delay): s for s in todo}
        for n, fut in enumerate(as_completed(futs), 1):
            src = futs[fut]
            try:
                text = fut.result()
            except Exception as e:  # keep going; report at the end
                stats["failed"] += 1
                log(f"FAILED {src['fetch_url']}: {e}")
                continue
            path = page_path(src)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            manifest[path.relative_to(raw_dir()).as_posix()] = _entry(src, text, _now())
            stats["fetched"] += 1
            if n % 25 == 0:
                log(f"[{n}/{len(todo)}] fetched")
                save()
    save()
    return stats


def load_sources(lang: str | None = None) -> list[dict]:
    data = json.loads(sources_file().read_text(encoding="utf-8"))
    return [s for s in data["sources"] if lang in (None, s["lang"])]


def save_sources(sources: list[dict]) -> None:
    sources_file().parent.mkdir(parents=True, exist_ok=True)
    counts = {}
    for s in sources:
        counts[s["lang"]] = counts.get(s["lang"], 0) + 1
    data = {"_readme": "Official documentation pages for RAG. Generated by `siemx docs "
                       "discover`; the text is downloaded by `siemx docs fetch` into rag/raw/ "
                       "(git-ignored).",
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "counts": counts, "sources": sources}
    sources_file().write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":   # quick manual check: python -m siemx.docs <html file>
    print(splunk_html_to_md(Path(sys.argv[1]).read_text(encoding="utf-8"))[:3000])
