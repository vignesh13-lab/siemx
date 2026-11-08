"""RAG step D: vector (embedding) search with Chroma, and hybrid ranking.

    siemx docs embed   -> rag/index/chroma/   (git-ignored; optional: pip install -e ".[rag]")

Embeddings map text to vectors so that similar MEANING gives nearby vectors (cosine
similarity), even when the words differ: SPL "count of characters in a string" is
close to KQL strlen "length, in characters, of the input string". Keyword search
(BM25) cannot make that link.

Model: Chroma's default all-MiniLM-L6-v2 (384 dimensions), run locally with ONNX,
so no documentation text is sent to any service.

Hybrid ranking: BM25 scores (0..40) and cosine distances (0..2) are not comparable,
so results are combined by RANK with Reciprocal Rank Fusion:
    rrf(chunk) = sum over rankings of 1 / (RRF_K + rank)
RRF_K = 60 is the usual constant; it keeps the very first ranks from dominating.
"""
from __future__ import annotations

from pathlib import Path

from .chunking import Chunk

COLLECTION = "siemx_docs"
BATCH = 500
RRF_K = 60


def available() -> bool:
    try:
        import chromadb  # noqa: F401
        return True
    except ImportError:
        return False


def _client(path: Path):
    import chromadb
    return chromadb.PersistentClient(path=str(path))


def _default_ef():
    from chromadb.utils import embedding_functions
    return embedding_functions.DefaultEmbeddingFunction()


def build(chunks: list[Chunk], path: Path, embedding_function=None, log=print) -> int:
    """(Re)create the collection from the same chunks BM25 uses (fair comparison)."""
    client = _client(path)
    try:
        client.delete_collection(COLLECTION)
    except Exception:  # first build: nothing to delete
        pass
    col = client.create_collection(
        COLLECTION, embedding_function=embedding_function or _default_ef(),
        metadata={"hnsw:space": "cosine"})              # cosine distance = 1 - similarity
    for i in range(0, len(chunks), BATCH):
        part = chunks[i:i + BATCH]
        col.add(ids=[c.id for c in part], documents=[c.text for c in part],
                metadatas=[{"lang": c.lang, "kind": c.kind, "names": " ".join(c.names),
                            "section": c.section, "url": c.url} for c in part])
        log(f"embedded {min(i + BATCH, len(chunks))}/{len(chunks)}")
    return col.count()


class VectorIndex:
    def __init__(self, path: Path, embedding_function=None):
        self.col = _client(path).get_collection(
            COLLECTION, embedding_function=embedding_function or _default_ef())

    def search(self, query: str, lang: str | None = None, k: int = 10) -> list[tuple[float, str]]:
        """-> [(cosine similarity, chunk id)], best first, filtered by language."""
        res = self.col.query(query_texts=[query], n_results=k,
                             where={"lang": lang} if lang else None)
        return [(1 - d, cid) for d, cid in zip(res["distances"][0], res["ids"][0])]


def rrf(*rankings: list[str], k: int = RRF_K) -> list[tuple[float, str]]:
    """Reciprocal Rank Fusion of several ranked id lists -> [(score, id)], best first."""
    scores: dict[str, float] = {}
    for ranking in rankings:
        for rank, cid in enumerate(ranking, 1):
            scores[cid] = scores.get(cid, 0.0) + 1.0 / (k + rank)
    return sorted(((s, cid) for cid, s in scores.items()), key=lambda x: (-x[0], x[1]))


_VEC: dict = {}


def get_index(path: Path) -> VectorIndex | None:
    """Cached per process; None if Chroma is not installed or the index is not built."""
    if not available() or not path.exists():
        return None
    key = str(path)
    if key not in _VEC:
        try:
            _VEC[key] = VectorIndex(path)
        except Exception:  # collection missing
            return None
    return _VEC[key]
