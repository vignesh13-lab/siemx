"""RAG step C: keyword retrieval (BM25) over doc chunks, with metadata filters.

How llm.retrieve() uses it for one SPL query and a target language:
  1. Split the SPL into stages; take each stage's command (and eval/stats
     function names used in it).
  2. Hop 1 - SPL docs: exact name lookup of each SPL command/function in the SPL
     chunks (metadata `names`), so the prompt explains what the SPL does.
  3. Hop 2 - target docs: BM25 search in the target language only. The query is
     the stage text PLUS the overview text of the SPL doc found in hop 1. That
     bridges the vocabulary gap (KQL docs never say "transaction"; they say
     "session", "window"...).
  4. Merge, de-duplicate, and stop at a character budget.

BM25 (Robertson/Sparck Jones), per query term t in chunk d:
    idf(t) * tf(t,d) * (k1 + 1) / (tf(t,d) + k1 * (1 - b + b * len(d) / avg_len))
  idf    rare terms count more than common ones
  k1     saturation: the 10th repeat of a word adds little
  b      length normalisation: long chunks do not win just by being long
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .chunking import Chunk, load

K1, B = 1.5, 0.75
NAME_BOOST = 3.0           # added when a query word equals a chunk's command/function name
BUDGET_CHARS = 12000       # docs text per prompt
TOP_TARGET_PER_STAGE = 3
TOP_SPL_PER_NAME = 2

_WORD = re.compile(r"[a-z0-9_]+(?:-[a-z0-9_]+)*")
# English filler words. Words that are KEYWORDS in SPL/KQL/XQL (where, if, not, has,
# filter, top, ...) must NOT be here, or BM25 cannot see them: an earlier list dropped
# `where`, `if`, `not` and `has`, which hid the KQL where/has operators and SPL if().
STOP = set("""a an and are as at be by can for from have in into is it its of on or
that the their this to was were will with you your which when what how
returns return use used using example examples query following""".split())
CODE_KEYWORDS = {"where", "if", "not", "has", "filter", "top", "limit", "sort", "join", "in"}
assert not STOP & CODE_KEYWORDS - {"in"}, "keywords must not be stopwords"


def tokens(text: str) -> list[str]:
    """Lowercase words; keeps snake_case and kebab-case names (arg_max, project-rename)
    and also adds their parts, so 'project-rename' matches 'project' and 'rename'."""
    out = []
    for w in _WORD.findall(text.lower()):
        if w in STOP or len(w) < 2:
            continue
        out.append(w)
        if "-" in w or "_" in w:
            out.extend(p for p in re.split(r"[-_]", w) if len(p) > 1 and p not in STOP)
    return out


@dataclass
class Hit:
    score: float
    chunk: Chunk


class BM25Index:
    def __init__(self, chunks: list[Chunk], bridge: dict | None = None):
        self.chunks = chunks
        self.bridge = bridge or {}            # {"kql": {"stats": ["summarize"], ...}}
        self.by_id = {c.id: c for c in chunks}
        self.vec = None                       # vectors.VectorIndex, attached by get_index()
        # title and names are part of the indexed text twice: field boosting
        self.docs = [Counter(tokens(f"{c.title} {' '.join(c.names)} " * 2 + c.text)) for c in chunks]
        self.lens = [sum(d.values()) for d in self.docs]
        self.avg = sum(self.lens) / max(len(self.lens), 1)
        df = Counter()
        for d in self.docs:
            df.update(d.keys())
        n = len(chunks)
        self.idf = {t: math.log(1 + (n - f + 0.5) / (f + 0.5)) for t, f in df.items()}

    def search(self, query: str, lang: str | None = None, k: int = 5,
               names: set[str] | None = None) -> list[Hit]:
        q = Counter(tokens(query))
        hits = []
        for i, c in enumerate(self.chunks):
            if lang and c.lang != lang:
                continue                                     # metadata filter
            d, dl = self.docs[i], self.lens[i]
            s = 0.0
            for t in q:
                tf = d.get(t)
                if tf:
                    s += self.idf[t] * tf * (K1 + 1) / (tf + K1 * (1 - B + B * dl / self.avg))
            if names and names & set(c.names):
                s += NAME_BOOST
            if s > 0:
                hits.append(Hit(s, c))
        hits.sort(key=lambda h: (-h.score, h.chunk.id))
        return hits[:k]

    def by_name(self, name: str, lang: str, k: int = TOP_SPL_PER_NAME) -> list[Chunk]:
        """Exact metadata lookup: chunks about command/function `name` (overview first)."""
        found = [c for c in self.chunks if c.lang == lang and name in c.names]

        def rank(c):
            last = c.section.split(" > ")[-1]           # "strftime(...) > Description"
            return (c.names[0] != name, last not in ("Overview", "Description"),
                    "example" in c.section.lower(), int(c.id.rsplit("#", 1)[1]))
        found.sort(key=rank)
        return found[:k]


# ---- query construction ---------------------------------------------------------------

_FUNC = re.compile(r"\b([a-z_][a-z0-9_]*)\s*\(")


def spl_names(stage: str) -> list[str]:
    """Command of a stage plus function names used in it: 'eval x=strftime(_time,...)'
    -> ['eval', 'strftime']."""
    from .triage import command_of
    cmd = command_of(stage)
    names = [cmd] if cmd else []
    for f in _FUNC.findall(stage.lower()):
        if f not in names:
            names.append(f)
    return names


@dataclass
class Retrieved:
    docs: list[dict]          # [{"source", "lang", "title", "section", "text"}]
    trace: list[str]          # why each chunk was picked (for learning / debugging)


@dataclass
class Options:
    """Switches for the ablation study (`siemx docs eval --ablation`)."""
    skip_base: bool = True        # do not search docs for the base search (rules handle it)
    use_bridge: bool = True       # official SPL -> target name map (bridge.json)
    expansion_chars: int = 0      # SPL description text added to the hop-2 query (0 = off:
                                  # it hurt on the real corpus, see `docs eval --ablation`)
    mode: str = "hybrid"          # "bm25" | "vector" | "hybrid"; hybrid won the ablation and
                                  # falls back to BM25 when there is no vector index
    pool: int = 20                # candidates per ranking before fusion
    per_name_best: bool = True    # also keep the best vector hit of EACH SPL command/function
                                  # (coverage: fusion alone favours chunks many rankings agree on)


def first_sentence(chunk_text: str, limit: int) -> str:
    """Body of a chunk (without the [LANG] header), first sentence(s) up to limit chars."""
    body = chunk_text.split("\n\n", 1)[-1]
    body = re.sub(r"\s+", " ", body)
    m = re.match(r"(.+?[.!?])(\s|$)", body)
    return (m.group(1) if m else body)[:limit]


def kql_names(stage: str) -> list[str]:
    """KQL operator of a stage plus function names: 'extend n = strlen(x)' -> ['extend', 'strlen']."""
    from .reverse import Unsupported, operator_of
    try:
        op = operator_of(stage)[0].replace(" by", "")       # 'sort by' -> 'sort'
    except Unsupported:
        return []
    names = [op]
    for f in _FUNC.findall(stage.lower()):
        if f not in names:
            names.append(f)
    return names


def invert_bridge(bridge: dict[str, list[str]]) -> dict[str, list[str]]:
    """{'stats': ['summarize']} -> {'summarize': ['stats']} (for KQL -> SPL)."""
    out: dict[str, list[str]] = {}
    for spl_name, targets in bridge.items():
        for t in targets:
            out.setdefault(t, [])
            if spl_name not in out[t]:
                out[t].append(spl_name)
    return out


def retrieve(index: BM25Index, spl: str, target: str, budget: int = BUDGET_CHARS,
             opts: Options | None = None, source: str = "spl") -> Retrieved:
    """Docs for translating `spl` (a query in `source`) into `target`. For KQL -> SPL the
    same steps run with the roles swapped: KQL docs by name, the official bridge
    inverted (summarize -> stats), then BM25/vectors over the SPL docs."""
    from .triage import split_stages
    opts = opts or Options()
    picked: dict[str, Chunk] = {}
    trace: list[str] = []
    if source == "kql":
        from .reverse import split_pipes
        stages = split_pipes(spl)
        bridge = invert_bridge(index.bridge.get("kql", {})) if opts.use_bridge else {}
        names_of = kql_names
    else:
        stages = split_stages(spl)
        bridge = index.bridge.get(target, {}) if opts.use_bridge else {}
        names_of = spl_names
    S = source.upper()
    for i, st in enumerate(stages):
        if i == 0 and opts.skip_base:
            continue
        names = names_of(st) if i else []           # first stage = base search / table
        # hop 1: source-language docs for the commands/functions in this stage
        spl_context = []
        for n in names:
            for c in index.by_name(n, source):
                picked.setdefault(c.id, c)
                spl_context.append(c.text)
                trace.append(f"stage {i}: {S} '{n}' -> {c.id} (name match)")
        # hop 1b: official bridge (e.g. Microsoft's Splunk-to-KQL cheat sheet)
        bridged = [t for n in names for t in bridge.get(n, [])]
        for t in bridged:
            for c in index.by_name(t, target, k=1):
                if c.id not in picked:
                    picked[c.id] = c
                    trace.append(f"stage {i}: bridge -> {target.upper()} '{t}' -> {c.id}")
        # hop 2: target-language docs (BM25, vectors, or both fused with RRF)
        expansion = " ".join(first_sentence(t, opts.expansion_chars) for t in spl_context[:1])
        query = f"{st} {expansion}" if opts.expansion_chars else st
        bm25 = index.search(query, lang=target, k=opts.pool, names=set(names) | set(bridged))
        rankings, how = [], {}
        if opts.mode in ("bm25", "hybrid"):
            rankings.append([h.chunk.id for h in bm25])
            how.update({h.chunk.id: f"BM25 {h.score:.1f}" for h in bm25})
        best_per_name = []
        if opts.mode in ("vector", "hybrid") and index.vec is not None:
            # one query per SPL command/function: the first sentence of ITS description,
            # compared with target docs written in the same descriptive style
            for n in names:
                spl_doc = index.by_name(n, source, k=1)
                if not spl_doc:
                    continue
                vq = first_sentence(spl_doc[0].text, 300)
                hits = index.vec.search(vq, lang=target, k=opts.pool)
                rankings.append([cid for _, cid in hits])
                for sim, cid in hits:
                    how.setdefault(cid, f"vector {sim:.2f} via {S} '{n}'")
                if hits:
                    best_per_name.append((n, hits[0]))
        from .vectors import rrf
        fused = rrf(*rankings) if len(rankings) > 1 else [(0.0, c) for c in (rankings or [[]])[0]]
        added = 0
        for score, cid in fused:
            if added == TOP_TARGET_PER_STAGE:
                break
            c = index.by_id.get(cid)
            if c is None or cid in picked:
                continue
            picked[cid] = c
            added += 1
            label = how.get(cid, "")
            if len(rankings) > 1:
                label += f", RRF {score:.4f}"
            trace.append(f"stage {i}: {target.upper()} {label} -> {cid}")
        # coverage AFTER the fused results, so ranking quality (MRR) is kept
        if opts.per_name_best:
            for n, (sim, cid) in best_per_name:
                c = index.by_id.get(cid)
                if c is not None and cid not in picked:
                    picked[cid] = c
                    trace.append(f"stage {i}: {target.upper()} best vector for {S} '{n}' "
                                 f"{sim:.2f} -> {cid}")
    docs, used = [], 0
    for c in picked.values():
        if used + c.chars > budget:
            trace.append(f"budget: skipped {c.id}")
            continue
        used += c.chars
        docs.append({"source": c.url, "lang": c.lang, "title": c.title,
                     "section": c.section, "names": c.names, "text": c.text})
    return Retrieved(docs, trace)


# ---- loading (once per process) -------------------------------------------------------

_INDEX: dict[str, BM25Index] = {}


def get_index(chunks_file: Path) -> BM25Index | None:
    if not chunks_file.exists():
        return None
    key = f"{chunks_file}:{chunks_file.stat().st_mtime_ns}"
    if key not in _INDEX:
        _INDEX.clear()
        bridge_file = chunks_file.parent / "bridge.json"
        bridge = json.loads(bridge_file.read_text(encoding="utf-8")) if bridge_file.exists() else {}
        _INDEX[key] = BM25Index(load(chunks_file), bridge)
        from . import vectors
        _INDEX[key].vec = vectors.get_index(chunks_file.parent / "chroma")
    return _INDEX[key]


# ---- the official bridge -------------------------------------------------------------
# Microsoft's "Splunk to Kusto cheat sheet" (in the KQL corpus) maps SPL commands and
# functions to KQL ones. Parsed into {"kql": {spl_name: [kql_names]}}. It is an
# independent official source; the eval labels come from this project's rules, so
# using the bridge is not evaluation leakage. The Cortex "Translate to XQL" table is
# malformed (SPL pipes break the Markdown cells), so there is no XQL bridge.

_CODE = re.compile(r"`([^`]+)`")


def _cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def _code_names(cell: str) -> list[str]:
    out = []
    for raw in _CODE.findall(cell):
        name = re.sub(r"\(.*?\)?$", "", raw.strip()).strip().lower()
        name = re.sub(r"\s+-$", "", name)          # "fields -" -> "fields"
        if re.fullmatch(r"[a-z_][a-z0-9_-]*( regex)?", name):
            out.append(name.split()[0] if name.endswith(" regex") else name)
    return out


def parse_cheat_sheet(md: str) -> dict[str, list[str]]:
    """Three table styles on the page:
      | `spl` | `kql()` | notes |                          (functions)
      | Splunk | `spl` | ... |  then  | Kusto | `kql` | ...  (operators)
      | `stats` | example | `summarize` | example |          (aggregation)"""
    bridge: dict[str, list[str]] = {}

    def add(spl_names, kql_names):
        for s in spl_names:
            for k in kql_names:
                if k not in bridge.setdefault(s, []):
                    bridge[s].append(k)

    last_splunk = None
    for line in md.splitlines():
        if not line.lstrip().startswith("|") or set(line.replace("|", "").strip()) <= set("-: "):
            continue
        cells = _cells(line)
        if cells[0] == "Splunk" and len(cells) > 1:
            last_splunk = _code_names(cells[1])
        elif cells[0] == "Kusto" and len(cells) > 1 and last_splunk:
            add(last_splunk, _code_names(cells[1]))
            last_splunk = None
        elif len(cells) >= 4 and _code_names(cells[0]) and _code_names(cells[2]):
            add(_code_names(cells[0]), _code_names(cells[2]))
        elif len(cells) >= 2 and _code_names(cells[0]) and _code_names(cells[1]):
            left, right = _code_names(cells[0]), _code_names(cells[1])
            if len(left) == len(right) > 1:      # `upper`<br>`lower` | `toupper()`<br>`tolower()`
                for s, k in zip(left, right):
                    add([s], [k])
            else:
                add(left, right)
    return bridge


def build_bridge(raw_dir: Path) -> dict:
    sheet = raw_dir / "kql" / "concept__splunk-cheat-sheet.md"
    if not sheet.exists():
        return {}
    return {"kql": parse_cheat_sheet(sheet.read_text(encoding="utf-8"))}
