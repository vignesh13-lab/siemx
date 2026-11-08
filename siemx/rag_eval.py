"""RAG step E: measure retrieval quality on a labelled set (rag/eval.jsonl).

Each line: {"spl": "...", "kql": [names], "xql": [names]} - the target-language
command/function docs a good retriever must return for that SPL. Labels only use
mappings verified against the official docs.

Metrics (target-language chunks only, in retrieval order):
  hit     at least one expected name was retrieved
  recall  share of expected names retrieved
  mrr     1 / rank of the first retrieved chunk with an expected name (0 if none)
Measuring retrieval separately from generation tells you which half failed.
"""
from __future__ import annotations

import json
from pathlib import Path


def load_cases(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def score_case(retrieved_names: list[list[str]], expected: list[str]) -> dict:
    """retrieved_names: the `names` of each retrieved target chunk, in order."""
    found = {e for e in expected if any(e in names for names in retrieved_names)}
    rank = next((i for i, names in enumerate(retrieved_names, 1)
                 if any(e in names for e in expected)), None)
    return {"hit": bool(found), "recall": len(found) / len(expected),
            "mrr": 1 / rank if rank else 0.0, "missing": sorted(set(expected) - found)}


def names_in_query(query: str) -> set[str]:
    """Words of a translated query, e.g. 'extend n = strlen(cmd)' -> {'extend', 'strlen', ...}."""
    from .retrieve import tokens
    return set(tokens(query))


def evaluate_examples(pairs: list[dict], cases: list[dict], k: int = 3) -> dict:
    """Do the retrieved gold examples SHOW an expected target name (e.g. strlen)?
    The exact SPL of a case is excluded from its own examples (no leakage)."""
    from . import gold
    report = {}
    for target in ("kql", "xql"):
        rows = []
        for case in cases:
            if not case.get(target):
                continue
            ex = gold.similar(pairs, case["spl"], target, k=k, exclude_spl=case["spl"])
            shown = [names_in_query(p[target]) for _, p in ex]
            rows.append({"spl": case["spl"], **score_case([list(s) for s in shown], case[target])})
        n = len(rows) or 1
        report[target] = {"cases": len(rows),
                          "hit": round(sum(r["hit"] for r in rows) / n, 3),
                          "recall": round(sum(r["recall"] for r in rows) / n, 3),
                          "misses": [r for r in rows if r["missing"]]}
    return report


def reverse_cases(pairs: list[dict], source: str = "kql") -> list[dict]:
    """KQL/XQL -> SPL cases from gold pairs read backwards: the query is the pair's KQL
    (or XQL), the expected names are the SPL commands of its verified SPL (base search
    excluded)."""
    from .triage import split_stages
    out = []
    for p in pairs:
        if not p.get(source):
            continue
        cmds = [st.split()[0].lower() for st in split_stages(p["spl"])[1:] if st.split()]
        if cmds:
            out.append({"query": p[source], "spl": list(dict.fromkeys(cmds))})
    return out


def evaluate_reverse(index, cases: list[dict], retrieve_fn, source: str = "kql") -> dict:
    """retrieve_fn(index, query, 'spl', source=source) -> Retrieved; scores SPL chunks only."""
    rows = []
    for case in cases:
        res = retrieve_fn(index, case["query"], "spl", source=source)
        names = [d["names"] for d in res.docs if d["lang"] == "spl"]
        rows.append({"query": case["query"], **score_case(names, case["spl"])})
    n = len(rows) or 1
    return {"cases": len(rows),
            "hit": round(sum(r["hit"] for r in rows) / n, 3),
            "recall": round(sum(r["recall"] for r in rows) / n, 3),
            "mrr": round(sum(r["mrr"] for r in rows) / n, 3),
            "misses": [r for r in rows if r["missing"]]}


def reverse_prompt_coverage(index, pairs: list[dict], source: str, retrieve_fn, k: int = 3) -> dict:
    """What the reverse PROMPT shows: per case, are the expected SPL commands in the
    retrieved docs or in the gold examples (the case's own pair excluded: no leakage)?"""
    from .gold import similar_reverse
    cases = reverse_cases(pairs, source)
    ex_hit = ex_recall = covered = 0
    for c in cases:
        shown = {w for _, p in similar_reverse(pairs, c["query"], source, k, exclude=c["query"])
                 for w in names_in_query(p["spl"])}
        got = [e for e in c["spl"] if e in shown]
        ex_hit += bool(got)
        ex_recall += len(got) / len(c["spl"])
        res = retrieve_fn(index, c["query"], "spl", source=source)
        doc_names = {n for d in res.docs if d["lang"] == "spl" for n in d["names"]}
        covered += all(e in shown or e in doc_names for e in c["spl"])
    n = len(cases) or 1
    return {"cases": len(cases), "examples_hit": round(ex_hit / n, 3),
            "examples_recall": round(ex_recall / n, 3), "covered": round(covered / n, 3)}


def evaluate(index, cases: list[dict], retrieve_fn) -> dict:
    """retrieve_fn(index, spl, target) -> Retrieved (docs with 'lang' and 'names')."""
    report = {}
    for target in ("kql", "xql"):
        rows = []
        for case in cases:
            if not case.get(target):
                continue
            res = retrieve_fn(index, case["spl"], target)
            names = [d["names"] for d in res.docs if d["lang"] == target]
            rows.append({"spl": case["spl"], **score_case(names, case[target])})
        n = len(rows) or 1
        report[target] = {
            "cases": len(rows),
            "hit": round(sum(r["hit"] for r in rows) / n, 3),
            "recall": round(sum(r["recall"] for r in rows) / n, 3),
            "mrr": round(sum(r["mrr"] for r in rows) / n, 3),
            "misses": [r for r in rows if r["missing"]],
        }
    return report
