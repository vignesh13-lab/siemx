import argparse
import json
import os

from . import config, pipeline


def main():
    p = argparse.ArgumentParser(prog="siemx")
    sub = p.add_subparsers(dest="cmd", required=True)

    client = argparse.ArgumentParser(add_help=False)
    # `or None`: GitHub Actions passes SIEMX_CLIENT="" on push events (no workflow input)
    client.add_argument("--client", default=os.environ.get("SIEMX_CLIENT") or None,
                        help="use mappings/clients/<client>/ and write to converted/<client>/ "
                             "(default: $SIEMX_CLIENT, else shared mappings only)")

    c = sub.add_parser("convert", parents=[client],
                       help="convert detections/spl/** (skips unchanged files)")
    c.add_argument("--to", default="kql,xql")
    c.add_argument("--workers", type=int, default=4)
    c.add_argument("--force", action="store_true")
    c.add_argument("--path", help="only convert detections/spl/<path>/** (e.g. a client folder)")

    sub.add_parser("status", parents=[client], help="counts per status")
    sub.add_parser("review", parents=[client], help="list needs-review / unsupported")

    d = sub.add_parser("docs", help="RAG corpus: official documentation")
    dsub = d.add_subparsers(dest="docs_cmd", required=True)
    dsub.add_parser("discover", help="list official doc pages -> rag/sources.json")
    f = dsub.add_parser("fetch", help="download + clean pages -> rag/raw/ (git-ignored)")
    f.add_argument("--lang", choices=["spl", "kql", "xql"])
    f.add_argument("--limit", type=int, help="only the first N pages (for a quick test)")
    f.add_argument("--refresh", action="store_true", help="download again even if present")
    dsub.add_parser("build", help="split pages into chunks -> rag/index/chunks.jsonl")
    dsub.add_parser("embed", help="vector index of the chunks -> rag/index/chroma "
                                  '(needs pip install -e ".[rag]")')
    s = dsub.add_parser("search", help="BM25 search over the chunks (to explore retrieval)")
    s.add_argument("query")
    s.add_argument("--lang", choices=["spl", "kql", "xql"])
    s.add_argument("-k", type=int, default=5)
    r = dsub.add_parser("retrieve", help="show what the LLM prompt would get for an SPL query")
    r.add_argument("spl")
    r.add_argument("--to", choices=["kql", "xql"], default="kql")
    e = dsub.add_parser("eval", help="measure retrieval on rag/eval.jsonl (hit, recall, MRR)")
    e.add_argument("--verbose", action="store_true", help="list every miss")
    e.add_argument("--ablation", action="store_true",
                   help="score each retrieval option on its own (what helps, what hurts)")

    a = p.parse_args()
    if a.cmd == "docs":
        return _docs(a)
    config.set_client(a.client)
    if a.cmd == "convert":
        counts = pipeline.run(a.to.split(","), a.workers, a.force, a.path)
        print(json.dumps({"summary": counts}))
    elif a.cmd == "status":
        print(json.dumps(pipeline.status(), indent=2))
    elif a.cmd == "review":
        for m in sorted(pipeline.review_list(), key=lambda m: (m["src"], m["target"])):
            print(f"{m['status']:13} {m['target']}  {m['src']}  conf={m.get('confidence')}"
                  f"  method={m.get('method')}")
            for w in m.get("warnings") or []:
                print(f"    - {w}")


def _docs(a):
    from . import docs
    if a.docs_cmd == "discover":
        sources = docs.discover()
        docs.save_sources(sources)
        counts = {}
        for s in sources:
            counts[s["lang"]] = counts.get(s["lang"], 0) + 1
        print(json.dumps({"sources": len(sources), "per_language": counts}))
    elif a.docs_cmd == "fetch":
        sources = docs.load_sources(a.lang)[: a.limit]
        print(json.dumps(docs.fetch(sources, refresh=a.refresh)))
    elif a.docs_cmd == "build":
        from . import chunking
        from . import retrieve as rag
        stats = chunking.build(docs.raw_dir(), docs.index_dir() / "chunks.jsonl")
        bridge = rag.build_bridge(docs.raw_dir())
        (docs.index_dir() / "bridge.json").write_text(json.dumps(bridge, indent=1, sort_keys=True))
        stats["bridge"] = {t: len(m) for t, m in bridge.items()}
        print(json.dumps(stats))
    elif a.docs_cmd == "embed":
        from . import chunking, vectors
        if not vectors.available():
            raise SystemExit('chromadb is not installed: pip install -e ".[rag]"')
        chunks = chunking.load(docs.index_dir() / "chunks.jsonl")
        n = vectors.build(chunks, docs.index_dir() / "chroma")
        print(json.dumps({"embedded": n}))
    elif a.docs_cmd == "eval":
        from . import rag_eval
        from . import retrieve as rag
        index = rag.get_index(docs.index_dir() / "chunks.jsonl")
        if index is None:
            raise SystemExit("no index: run `siemx docs fetch` and `siemx docs build` first")
        cases = rag_eval.load_cases(docs.rag_dir() / "eval.jsonl")
        if a.ablation:
            configs = [
                ("v0 first version", rag.Options(skip_base=False, use_bridge=False, expansion_chars=600, mode="bm25")),
                ("+ skip base search", rag.Options(skip_base=True, use_bridge=False, expansion_chars=600, mode="bm25")),
                ("+ short expansion", rag.Options(skip_base=True, use_bridge=False, expansion_chars=200, mode="bm25")),
                ("+ no expansion", rag.Options(skip_base=True, use_bridge=False, expansion_chars=0, mode="bm25")),
                ("+ bridge, expansion", rag.Options(expansion_chars=200, mode="bm25")),
                ("+ bridge, no expansion", rag.Options(expansion_chars=0, mode="bm25")),
            ]
            if index.vec is not None:
                configs += [
                    ("vector only", rag.Options(mode="vector")),
                    ("hybrid (BM25+vector)", rag.Options(mode="hybrid")),
                    ("hybrid + best per name", rag.Options(mode="hybrid", per_name_best=True)),
                ]
            else:
                print("(no vector index: run `siemx docs embed` to add vector/hybrid rows)")
            print(f"{'configuration':22} {'KQL hit':>8} {'recall':>7} {'mrr':>6} | {'XQL hit':>8} {'recall':>7} {'mrr':>6}")
            for label, opts in configs:
                rep = rag_eval.evaluate(index, cases, lambda i, s, t: rag.retrieve(i, s, t, opts=opts))
                k, x = rep["kql"], rep["xql"]
                print(f"{label:22} {k['hit']:8.3f} {k['recall']:7.3f} {k['mrr']:6.3f} | "
                      f"{x['hit']:8.3f} {x['recall']:7.3f} {x['mrr']:6.3f}")
            return
        rep = rag_eval.evaluate(index, cases, rag.retrieve)
        for t, r in rep.items():
            print(f"{t.upper()}: cases={r['cases']} hit={r['hit']} recall={r['recall']} mrr={r['mrr']}")
            for m in r["misses"] if a.verbose else []:
                print(f"    miss {m['missing']}  <- {m['spl']}")
    elif a.docs_cmd in ("search", "retrieve"):
        from . import retrieve as rag
        index = rag.get_index(docs.index_dir() / "chunks.jsonl")
        if index is None:
            raise SystemExit("no index: run `siemx docs fetch` and `siemx docs build` first")
        if a.docs_cmd == "search":
            for h in index.search(a.query, lang=a.lang, k=a.k):
                print(f"{h.score:6.2f}  {h.chunk.id:55} {h.chunk.section[:40]}")
        else:
            res = rag.retrieve(index, a.spl, a.to)
            print("\n".join(res.trace))
            print(f"\n{len(res.docs)} chunks, {sum(len(d['text']) for d in res.docs)} chars")


if __name__ == "__main__":
    main()
