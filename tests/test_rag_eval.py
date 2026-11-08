"""RAG step E: retrieval metrics."""
import pytest

from siemx import rag_eval, retrieve
from tests.test_retrieve import CHUNKS


@pytest.mark.parametrize("names, expected, hit, recall, mrr, missing", [
    ([["summarize"], ["count"]], ["summarize", "count"], True, 1.0, 1.0, []),
    ([["take"], ["summarize"]], ["summarize", "count"], True, 0.5, 0.5, ["count"]),
    ([["a"], ["b"], ["count", "x"]], ["count"], True, 1.0, 1 / 3, []),
    ([["a"]], ["count"], False, 0.0, 0.0, ["count"]),
    ([], ["count"], False, 0.0, 0.0, ["count"]),
])
def test_score_case(names, expected, hit, recall, mrr, missing):
    s = rag_eval.score_case(names, expected)
    assert (s["hit"], s["recall"], s["missing"]) == (hit, recall, missing)
    assert s["mrr"] == pytest.approx(mrr)


def test_evaluate_on_toy_index():
    index = retrieve.BM25Index(CHUNKS)
    cases = [{"spl": "index=x | transaction host maxspan=5m", "kql": ["row_window_session"]},
             {"spl": "index=x | stats count", "kql": ["summarize"], "xql": ["comp"]}]
    rep = rag_eval.evaluate(index, cases, retrieve.retrieve)
    assert rep["kql"]["cases"] == 2 and rep["xql"]["cases"] == 1
    # default (no expansion): 'transaction' shares no word with row_window_session
    assert rep["kql"]["hit"] == 0.5 and rep["kql"]["misses"][0]["missing"] == ["row_window_session"]
    with_exp = rag_eval.evaluate(index, cases, lambda i, s, t: retrieve.retrieve(
        i, s, t, opts=retrieve.Options(expansion_chars=200)))
    assert with_exp["kql"]["hit"] == 1.0          # on this toy set expansion helps


def test_eval_file_is_well_formed():
    from pathlib import Path
    cases = rag_eval.load_cases(Path(__file__).resolve().parent.parent / "rag" / "eval.jsonl")
    assert len(cases) >= 20
    for c in cases:
        assert c["spl"].startswith("index=") and c["kql"] and c["xql"]
