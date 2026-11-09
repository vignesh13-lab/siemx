"""RAG step B: split cleaned doc pages into chunks with metadata.

    siemx docs build  -> rag/index/chunks.jsonl (git-ignored)

Design (see the module tests for examples):
  1. Structure-aware: split at Markdown headings (##, ###), because docs are
     already organised as Syntax / Parameters / Examples.
  2. Size cap MAX_CHARS: longer sections are split at blank lines, never inside
     a ``` code block.
  3. Contextual header: every chunk starts with "[LANG] page title > section",
     so it is understandable (and findable) on its own.
  4. Metadata: lang, kind, names (command/function names the chunk is about),
     title, section, url, chunk id. Used for filtering, boosting and citations.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

MAX_CHARS = 1500          # ~400 tokens; long enough for a syntax block + parameters
MIN_CHARS = 80            # smaller pieces are merged into the previous chunk
LANG_LABEL = {"spl": "SPL", "kql": "KQL", "xql": "XQL", "elk": "Elastic"}
_HEADING = re.compile(r"^(#{1,4}) +(.+?)\s*$")
_SIGNATURE = re.compile(r"^`?([A-Za-z_][A-Za-z0-9_.-]*)\s*\(")   # "len(<str>)" -> len


@dataclass
class Chunk:
    id: str
    lang: str
    kind: str
    title: str
    section: str
    names: list[str]
    url: str
    text: str
    chars: int = 0
    extra: dict = field(default_factory=dict)


def page_name(title: str, lang: str) -> str:
    """Command/function name from a page title.
    'arg_max() (aggregation function)' -> arg_max; 'summarize operator' -> summarize;
    'project-rename operator' -> project-rename; 'stats' -> stats."""
    t = title.strip().strip("`")
    t = re.sub(r"\s*\(.*?\)\s*", " ", t).strip()          # drop "()" and "(aggregation function)"
    t = re.sub(r"\s+(operator|function|plugin|statement|command|stage)$", "", t, flags=re.I)
    return t.split()[0].lower() if t else ""


def unescape_md(text: str) -> str:
    """Markdown escapes in titles/headings: 'count\\_distinct' -> 'count_distinct'."""
    return re.sub(r"\\([\\`*_{}\[\]()#+\-.!|<>])", r"\1", text)


def sections(md: str) -> tuple[str, list[tuple[list[str], str]]]:
    """-> (page title, [(heading path, body), ...]). '#' is the title; '##'..'####'
    start sections. Heading-like lines inside code blocks are ignored."""
    title, path, buf, in_code, out = "", [], [], False, []
    for line in md.splitlines():
        if line.strip().startswith("```"):
            in_code = not in_code
        m = None if in_code else _HEADING.match(line)
        if m:
            level, text = len(m.group(1)), unescape_md(m.group(2).strip())
            if level == 1:
                title = title or text
                continue
            if "".join(buf).strip():          # skip headings with no text of their own
                out.append((list(path), "\n".join(buf).strip()))
            buf = []
            path = path[: level - 2] + [text]
            continue
        buf.append(line)
    if "".join(buf).strip():
        out.append((list(path), "\n".join(buf).strip()))
    return title, out


def _split_long(body: str, limit: int) -> list[str]:
    """Split at blank lines outside code blocks so each piece is <= limit (a single
    code block longer than limit stays whole: half an example is useless)."""
    blocks, cur, in_code = [], [], False
    for line in body.splitlines():
        if line.strip().startswith("```"):
            in_code = not in_code
        cur.append(line)
        if not in_code and not line.strip():
            blocks.append("\n".join(cur).strip())
            cur = []
    if cur:
        blocks.append("\n".join(cur).strip())
    small = []
    for b in filter(None, blocks):
        small.extend(_split_block(b, limit) if len(b) > limit else [b])
    pieces, piece = [], ""
    for b in small:
        if piece and len(piece) + len(b) + 2 > limit:
            pieces.append(piece)
            piece = b
        else:
            piece = f"{piece}\n\n{b}" if piece else b
    if piece:
        pieces.append(piece)
    return pieces


CODE_KEEP_FACTOR = 3      # a code block up to 3x the limit stays whole (complete example)
TRUNCATED = " …(truncated)"
# website features that are not documentation, e.g. Microsoft's "Run the query"
# links whose URL contains the whole encoded query
_NOISE_LINE = re.compile(r"^\s*>?\s*<a href=\"https://dataexplorer\.azure\.com/.*Run the query", re.I)


def drop_noise(md: str) -> str:
    return "\n".join(ln for ln in md.splitlines() if not _NOISE_LINE.match(ln))


def _pack(lines: list[str], limit: int, prefix: str = "", suffix: str = "", sep: str = "\n"):
    """Greedy-pack lines into pieces of <= limit chars, each wrapped in prefix/suffix."""
    out, cur = [], []
    room = max(limit - len(prefix) - len(suffix), 1)
    for ln in lines:
        if len(ln) > room:                 # one huge line (e.g. 7,000 chars of coordinates)
            ln = ln[: room - len(TRUNCATED)] + TRUNCATED
        if cur and len(sep.join(cur + [ln])) > room:
            out.append(prefix + sep.join(cur) + suffix)
            cur = []
        cur.append(ln)
    if cur:
        out.append(prefix + sep.join(cur) + suffix)
    return out


def _split_block(block: str, limit: int) -> list[str]:
    """One oversized block -> pieces, with a strategy per content type."""
    lines = block.splitlines()
    if block.lstrip().startswith("```"):                       # code block
        if len(block) <= limit * CODE_KEEP_FACTOR:
            return [block]
        fence, body = lines[0], [ln for ln in lines[1:] if not ln.strip().startswith("```")]
        return _pack(body, limit, prefix=fence + "\n", suffix="\n```")
    if len(lines) > 2 and all(ln.lstrip().startswith("|") for ln in lines[:2]):   # table
        header = "\n".join(lines[:2]) + "\n"                   # header row + |---| row
        return _pack(lines[2:], limit, prefix=header)
    if len(lines) > 1:                                         # several lines
        return [p for ln in _pack(lines, limit) for p in ([ln] if len(ln) <= limit
                                                          else _split_block(ln, limit))]
    sentences = re.split(r"(?<=[.!?])\s+", block)              # one long line
    return _pack(sentences, limit, sep=" ")


def chunk_page(md: str, meta: dict, max_chars: int = MAX_CHARS) -> list[Chunk]:
    lang, kind = meta["lang"], meta["kind"]
    title, parts = sections(drop_noise(md))
    title = title or meta.get("slug", "")
    page = page_name(title, lang)
    intro_names = [page] if page else []
    out: list[Chunk] = []
    for path, body in parts:
        if not body:
            continue
        section = " > ".join(path) if path else "Overview"
        names = list(intro_names)
        for h in path:                                # function pages: "len(<str>)" headings
            m = _SIGNATURE.match(h)
            if m and m.group(1).lower() not in names:
                names.append(m.group(1).lower())
        header = f"[{LANG_LABEL[lang]}] {title} > {section}"
        for piece in _split_long(body, max_chars - len(header) - 2):
            if (out and len(piece) < MIN_CHARS and out[-1].section == section
                    and out[-1].chars + len(piece) + 2 <= max_chars):
                out[-1].text += "\n\n" + piece        # tiny tail: merge into the previous chunk
                out[-1].chars = len(out[-1].text)
                continue
            text = f"{header}\n\n{piece}"
            out.append(Chunk(id=f"{lang}/{meta['slug']}#{len(out)}", lang=lang, kind=kind,
                             title=title, section=section, names=names, url=meta["cite_url"],
                             text=text, chars=len(text)))
    return out


def build(raw_dir: Path, out_file: Path, max_chars: int = MAX_CHARS) -> dict:
    """All pages in raw_dir (+ _manifest.json for URLs) -> chunks.jsonl."""
    manifest = json.loads((raw_dir / "_manifest.json").read_text(encoding="utf-8"))
    stats = {"pages": 0, "chunks": 0, "per_lang": {}}
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w", encoding="utf-8", newline="\n") as fh:
        for rel, meta in sorted(manifest.items()):
            path = raw_dir / rel
            if not path.exists():
                continue
            chunks = chunk_page(path.read_text(encoding="utf-8"), meta, max_chars)
            for c in chunks:
                fh.write(json.dumps(asdict(c), ensure_ascii=False) + "\n")
            stats["pages"] += 1
            stats["chunks"] += len(chunks)
            stats["per_lang"][meta["lang"]] = stats["per_lang"].get(meta["lang"], 0) + len(chunks)
    return stats


def load(chunks_file: Path) -> list[Chunk]:
    with chunks_file.open(encoding="utf-8") as fh:
        return [Chunk(**json.loads(line)) for line in fh if line.strip()]
