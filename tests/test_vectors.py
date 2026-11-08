"""RAG step D: Chroma vector index, RRF fusion, hybrid retrieval.

Uses a fake, deterministic embedding (hashed bag of words) so tests are fast and do
not need the real model. Skipped when chromadb is not installed (it is optional)."""
import hashlib
import math

import pytest

from siemx import retrieve, vectors
from tests.test_retrieve import CHUNKS, ch

chromadb = pytest.importorskip("chromadb")
from chromadb import Documents, EmbeddingFunction, Embeddings  # noqa: E402

DIM = 64


class HashEmbedding(EmbeddingFunction):
    """Each word adds 1 to a hashed dimension; vectors are normalised."""

    def __init__(self):
        pass

    def __call__(self, input: Documents) -> Embeddings:
        out = []
        for text in input:
            v = [0.0] * DIM
            for w in retrieve.tokens(text):
                v[int(hashlib.md5(w.encode()).hexdigest(), 16) % DIM] += 1.0
            n = math.sqrt(sum(x * x for x in v)) or 1.0
            out.append([x / n for x in v])
        return out

    @staticmethod
    def name() -> str:
        return "siemx-test-hash"

    def get_config(self):
        return {}

    @staticmethod
    def build_from_config(config):
        return HashEmbedding()


def test_rrf():
    fused = vectors.rrf(["a", "b", "c"], ["b", "c", "d"])
    assert [cid for _, cid in fused][:2] == ["b", "c"]          # in both lists -> on top
    assert fused[0][0] == pytest.approx(1 / 62 + 1 / 61)
    assert vectors.rrf(["x"]) == [(pytest.approx(1 / 61), "x")]


@pytest.fixture
def vindex(tmp_path):
    ef = HashEmbedding()
    assert vectors.build(CHUNKS, tmp_path / "chroma", embedding_function=ef,
                         log=lambda m: None) == len(CHUNKS)
    return vectors.VectorIndex(tmp_path / "chroma", embedding_function=ef)


def test_vector_search_language_filter_and_similarity(vindex):
    hits = vindex.search("session start time", lang="kql", k=3)
    assert hits[0][1] == "kql/row-window-session#0"
    assert all(cid.startswith("kql/") for _, cid in hits)
    assert 0 < hits[0][0] <= 1                                     # cosine similarity


def test_rebuild_replaces_collection(tmp_path):
    ef = HashEmbedding()
    vectors.build(CHUNKS, tmp_path / "c", embedding_function=ef, log=lambda m: None)
    assert vectors.build(CHUNKS[:2], tmp_path / "c", embedding_function=ef, log=lambda m: None) == 2


def test_vector_mode_uses_spl_description_as_query(vindex):
    """Vector query = the SPL doc's first sentence ('...session of related events...')."""
    index = retrieve.BM25Index(CHUNKS)
    index.vec = vindex
    res = retrieve.retrieve(index, "index=x | transaction host", "kql",
                            opts=retrieve.Options(mode="vector"))
    assert "row-window-session#0" in " ".join(d["source"] for d in res.docs)
    assert any("vector" in t and "via SPL 'transaction'" in t for t in res.trace)


def test_hybrid_fuses_both_rankings(vindex):
    index = retrieve.BM25Index(CHUNKS)
    index.vec = vindex
    res = retrieve.retrieve(index, "index=x | stats count", "kql",
                            opts=retrieve.Options(mode="hybrid"))
    assert any("RRF" in t for t in res.trace)
    assert res.docs


def test_per_name_best_is_added_after_fused_results(vindex):
    """Coverage for every SPL function, without pushing fused results down (MRR)."""
    index = retrieve.BM25Index(CHUNKS)
    index.vec = vindex
    spl = "index=x | transaction host | stats count"
    base = retrieve.retrieve(index, spl, "kql", opts=retrieve.Options(mode="hybrid"))
    more = retrieve.retrieve(index, spl, "kql",
                             opts=retrieve.Options(mode="hybrid", per_name_best=True))
    # nothing the plain hybrid picked is lost
    assert {d["source"] for d in base.docs} <= {d["source"] for d in more.docs}
    # within each stage, the extra "best vector" chunks come after the fused ones
    for stage in (1, 2):
        lines = [t for t in more.trace if t.startswith(f"stage {stage}: KQL")]
        fused = [k for k, t in enumerate(lines) if "RRF" in t]
        best = [k for k, t in enumerate(lines) if "best vector" in t]
        if fused and best:
            assert min(best) > max(fused)


def test_vector_mode_without_index_falls_back_quietly():
    index = retrieve.BM25Index(CHUNKS)                    # index.vec is None
    res = retrieve.retrieve(index, "index=x | stats count", "kql",
                            opts=retrieve.Options(mode="vector"))
    assert all(d["lang"] == "spl" for d in res.docs)      # only hop-1 SPL docs


def test_get_index_none_when_not_built(tmp_path):
    assert vectors.get_index(tmp_path / "missing") is None
