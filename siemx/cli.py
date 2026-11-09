import argparse
import json
import os
import sys
from pathlib import Path

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
    c.add_argument("--to", help="targets, comma-separated. From spl: kql, xql, elk (default "
                                "kql,xql). From kql or xql: spl (default) or elk. From elk: spl (default), kql, xql")
    c.add_argument("--workers", type=int, default=None,
                   help="parallel conversions (default 4; 1 with ollama, which runs one request at a time)")
    c.add_argument("--force", action="store_true")
    c.add_argument("--no-ai", action="store_true",
                   help="rules only: never call an AI model (same as SIEMX_PROVIDER=none)")
    c.add_argument("--path", help="only convert detections/spl/<path>/** (e.g. a client folder)")
    c.add_argument("--from", dest="source", choices=["spl", "kql", "xql", "elk"],
                   default="spl",
                   help="input language (reads detections/<lang>); elk = Kibana KQL "
                        "(Elastic)")

    sub.add_parser("status", parents=[client], help="counts per status")
    sub.add_parser("review", parents=[client], help="list needs-review / unsupported")

    d = sub.add_parser("docs", help="RAG corpus: official documentation")
    dsub = d.add_subparsers(dest="docs_cmd", required=True)
    dsub.add_parser("discover", help="list official doc pages -> rag/sources.json")
    f = dsub.add_parser("fetch", help="download + clean pages -> rag/raw/ (git-ignored)")
    f.add_argument("--lang", choices=["spl", "kql", "xql", "elk"])
    f.add_argument("--limit", type=int, help="only the first N pages (for a quick test)")
    f.add_argument("--refresh", action="store_true", help="download again even if present")
    dsub.add_parser("build", help="split pages into chunks -> rag/index/chunks.jsonl")
    dsub.add_parser("embed", help="vector index of the chunks -> rag/index/chroma "
                                  '(needs pip install -e ".[rag]")')
    s = dsub.add_parser("search", help="BM25 search over the chunks (to explore retrieval)")
    s.add_argument("query")
    s.add_argument("--lang", choices=["spl", "kql", "xql", "elk"])
    s.add_argument("-k", type=int, default=5)
    r = dsub.add_parser("retrieve", help="show what the LLM prompt would get for an SPL query")
    r.add_argument("spl")
    r.add_argument("--to", choices=["kql", "xql"], default="kql")
    e = dsub.add_parser("eval", help="measure retrieval on rag/eval.jsonl (hit, recall, MRR)")
    e.add_argument("--verbose", action="store_true", help="list every miss")
    e.add_argument("--ablation", action="store_true",
                   help="score each retrieval option on its own (what helps, what hurts)")
    e.add_argument("--reverse", action="store_true",
                   help="KQL -> SPL retrieval, scored on the gold pairs read backwards")

    g = sub.add_parser("gold", help="verified SPL -> KQL/XQL examples (gold/pairs.jsonl)")
    gsub = g.add_subparsers(dest="gold_cmd", required=True)
    gsub.add_parser("seed", help="(re)generate rule-verified pairs; keeps human-reviewed ones")
    ga = gsub.add_parser("add", parents=[client],
                         help="add a reviewed conversion: detections/spl/<file> + its output")
    ga.add_argument("spl_file", help="path under detections/spl, e.g. windows/brute_force.spl")
    ga.add_argument("--to", choices=["kql", "xql"], required=True)
    ga.add_argument("--by", required=True, help="who reviewed the translation")
    ga.add_argument("--notes", default="")
    gs = gsub.add_parser("show", help="which examples a query would get")
    gs.add_argument("spl")
    gs.add_argument("--to", choices=["kql", "xql"], default="kql")
    gsub.add_parser("check", help="do the rules still produce the rule-verified answers?")

    rp = sub.add_parser("report", parents=[client],
                        help="report.md + summary.csv in converted/<client>/_report/")
    rp.add_argument("--mkdocs", help="also write a SIEM Hub docs page into this folder")
    vd = sub.add_parser("verdict", parents=[client], help="record a review result (pilot)")
    vd.add_argument("spl_file", help="path under detections/spl, e.g. windows/brute_force.spl")
    vd.add_argument("--to", choices=["kql", "xql", "elk"], required=True)
    vd.add_argument("--result", choices=["correct", "fixed", "wrong"], required=True)
    vd.add_argument("--by", required=True, help="who reviewed it")
    vd.add_argument("--notes", default="")

    ps = sub.add_parser("pilot-sample", help="stratified sample of detections for the pilot")
    ps.add_argument("folder", help="folder with .spl files (e.g. a full export)")
    ps.add_argument("-n", type=int, default=50)
    ps.add_argument("--seed", type=int, default=7)

    mp = sub.add_parser("mappings", help="data-source mapping (mappings/sources.json)")
    msub = mp.add_subparsers(dest="mappings_cmd", required=True)
    mm = msub.add_parser("missing", parents=[client],
                         help="Splunk sources the detections use that are not mapped yet")
    mm.add_argument("--write", action="store_true",
                    help="add them to sources.json with EDIT_ME_ placeholders to fill in")

    fl = sub.add_parser("fields", help="field mapping (mappings/field_map.json)")
    fsub = fl.add_subparsers(dest="fields_cmd", required=True)
    fi = fsub.add_parser("import-props",
                         help="import FIELDALIAS/EVAL from a client's Splunk props.conf")
    fi.add_argument("props", help="path to props.conf (e.g. from Splunk_TA_windows/default)")
    fi.add_argument("--stanza", required=True, help='e.g. "XmlWinEventLog:Security"')
    fi.add_argument("--client", required=True)
    fi.add_argument("--table", required=True, help="target table, e.g. SecurityEvent")
    fi.add_argument("--to", choices=["kql", "xql"], default="kql")
    fsh = fsub.add_parser("show", parents=[client], help="the field map for a table")
    fsh.add_argument("--table", required=True)
    fsh.add_argument("--to", choices=["kql", "xql"], default="kql")

    v = sub.add_parser("validate", help="check a KQL/XQL query (official KQL parser, XQL names)")
    v.add_argument("query", nargs="?", help="the query (omit to only show which validators run)")
    v.add_argument("--to", choices=["kql", "xql", "elk", "spl"], default="kql")

    a = p.parse_args()
    if a.cmd == "pilot-sample":
        from . import report
        root = Path(a.folder)
        for f in report.pilot_sample(root, a.n, a.seed):
            print(f.relative_to(root).as_posix())
        return
    if a.cmd in ("report", "verdict"):
        from . import report
        config.set_client(a.client)
        if a.cmd == "report":
            print(json.dumps(report.write(Path(a.mkdocs) if a.mkdocs else None)))
            return
        meta_path = pipeline.meta_path_for(config.SRC_DIR / a.spl_file, a.to)
        if not meta_path.exists():
            raise SystemExit(f"no conversion found for {a.spl_file} ({a.to}): run siemx convert")
        row = report.add_review(json.loads(meta_path.read_text()), a.result, a.by, a.notes)
        print(json.dumps(row))
        if a.result == "fixed":
            print(f"tip: once the fixed query is in converted/, `siemx gold add {a.spl_file} "
                  f"--to {a.to} --by {a.by}` makes it a verified example")
        return
    if a.cmd == "fields":
        return _fields(a)
    if a.cmd == "mappings":
        return _mappings(a)
    if a.cmd == "validate":
        from . import validate
        print(json.dumps(validate.status()))
        if a.query:
            problems = validate.check(a.query, a.to)
            print("\n".join(problems) if problems else "no problems found")
            raise SystemExit(1 if problems else 0)
        return
    if a.cmd == "docs":
        return _docs(a)
    if a.cmd == "gold":
        return _gold(a)
    config.set_client(a.client)
    if a.cmd == "convert":
        from . import llm
        if a.no_ai:
            os.environ["SIEMX_PROVIDER"] = "none"
        if llm.rules_only():
            print("note: rules-only mode (no AI). Queries without a rule are marked "
                  "unsupported with the command that has no rule.", file=sys.stderr)
        elif not llm.configured():
            print(f"note: {llm.NO_MODEL}. Queries that need the AI will be marked "
                  "unsupported and retried on the next run.", file=sys.stderr)
        allowed = {"spl": ("kql", "xql", "elk"), "kql": ("spl", "elk"),
                   "xql": ("spl", "elk"), "elk": ("spl", "kql", "xql")}[a.source]
        targets = (a.to or ("kql,xql" if a.source == "spl" else "spl")).split(",")
        bad = [t for t in targets if t not in allowed]
        if bad:
            p.error(f"--to from {a.source}: unknown target {', '.join(bad)} "
                    f"(use {', '.join(allowed)})")
        workers = a.workers or llm.default_workers()
        counts = pipeline.run(targets, workers, a.force, a.path, a.source)
        print(json.dumps({"summary": counts}))
    elif a.cmd == "status":
        print(json.dumps(pipeline.status(), indent=2))
    elif a.cmd == "review":
        for m in sorted(pipeline.review_list(), key=lambda m: (m["src"], m["target"])):
            print(f"{m['status']:13} {m['target']}  {m['src']}  conf={m.get('confidence')}"
                  f"  method={m.get('method')}")
            for w in m.get("warnings") or []:
                print(f"    - {w}")


def _mappings(a):
    from . import mappings
    config.set_client(a.client)
    files = sorted(config.SRC_DIR.rglob("*.spl"))
    missing = mappings.missing_sources(files)
    if not missing:
        print("every Splunk source in detections/spl is mapped")
        return
    for label, used in sorted(missing.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        name = mappings.placeholder_entry(label)["kql"]
        print(f"{len(used):4}  {label:45} -> {name}")
        for f in used[:5]:
            print(f"        {f.relative_to(config.SRC_DIR).as_posix()}")
        if len(used) > 5:
            print(f"        ... and {len(used) - 5} more")
    if a.write:
        cdir = config.client_dir()
        path = (cdir / "sources.json") if cdir else config.MAP_FILE
        added = mappings.write_placeholders(list(missing), path)
        print(f"added {len(added)} placeholder entries to {path}: replace each EDIT_ME_ "
              "value with the real table / dataset / index pattern")
    else:
        print("run with --write to add them to sources.json as EDIT_ME_ placeholders")


def _fields(a):
    from . import fieldmap, schema
    if a.fields_cmd == "show":
        config.set_client(a.client)
        for k, e in sorted(fieldmap.table_map(a.to, a.table).items()):
            right = e.get("to") or " | ".join(e.get("candidates", []))
            print(f"{e.get('level', '?'):11} {k:28} -> {right}")
        return
    config.set_client(a.client)
    columns = set(schema.known_fields(a.table, a.to) or [])
    if not columns:
        raise SystemExit(f"no column list for {a.table} in mappings/fields.json")
    props = Path(a.props)
    parsed = fieldmap.parse_props(props.read_text(encoding="utf-8", errors="replace"), a.stanza)
    entries = fieldmap.entries_from_props(parsed, columns, f"{props.name} [{a.stanza}]")
    out = config.client_dir() / "field_map.json"
    data = json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}
    section = data.setdefault(a.to, {}).setdefault(a.table, {"fields": {}})
    section.setdefault("sources", []).append(f"{props.name} [{a.stanza}]")
    section["fields"].update(entries)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    skipped = sorted(set(parsed) - set(entries))
    print(json.dumps({"written": str(out.relative_to(config.ROOT)), "imported": len(entries),
                      "exact": sum(1 for e in entries.values() if e["level"] == "exact"),
                      "ambiguous": sum(1 for e in entries.values() if e["level"] == "ambiguous"),
                      "skipped_not_a_column": skipped}))


def _gold(a):
    from . import gold
    if a.gold_cmd == "seed":
        pairs = gold.merge_seeds(gold.load(), gold.seed())
        gold.save(pairs)
        print(json.dumps({"pairs": len(pairs),
                          "kql": sum(1 for p in pairs if p.get("kql")),
                          "xql": sum(1 for p in pairs if p.get("xql"))}))
    elif a.gold_cmd == "add":
        config.set_client(a.client)
        src = config.SRC_DIR / a.spl_file
        out = config.OUT_DIR / a.to / Path(a.spl_file).with_suffix(config.EXT[a.to])
        if not src.exists() or not out.exists():
            raise SystemExit(f"need both {src} and {out} (convert first, review/edit the output)")
        pairs = gold.load()
        row = gold.add_reviewed(pairs, src.read_text().strip(), a.to, out.read_text().strip(),
                                a.by, source=out.relative_to(config.ROOT).as_posix(),
                                notes=a.notes)
        gold.save(pairs)
        print(json.dumps({"added": row["id"], "target": a.to, "verified_by": a.by}))
    elif a.gold_cmd == "show":
        for score, p in gold.similar(gold.load(), a.spl, a.to):
            print(f"{score:.2f}  {p['id']}  ({p['verified_by']})  {p['spl']}")
            print("      " + p[a.to].replace("\n", "\n      "))
    elif a.gold_cmd == "check":
        problems = gold.check(gold.load())
        for pr in problems:
            print(f"{pr['id']} {pr['target']}: rules now give\n{pr['now']}\n  gold:\n{pr['gold']}\n"
                  f"  caveats: {pr['caveats']}")
        print(json.dumps({"mismatches": len(problems)}))
        if problems:
            raise SystemExit(1)


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
        if a.reverse:
            from . import gold
            configs = [("bm25, no bridge", rag.Options(use_bridge=False,
                                                         use_rule_bridge=False, mode="bm25")),
                       ("bm25 + bridge", rag.Options(mode="bm25"))]
            if index.vec is not None:
                configs.append(("hybrid, no rule bridge", rag.Options(use_rule_bridge=False)))
                configs.append(("hybrid (default)", rag.Options()))
            for src in ("kql", "xql"):
                rcases = rag_eval.reverse_cases(gold.load(), src)
                print(f"{src.upper()} -> SPL  {'configuration':22} {'hit':>6} {'recall':>7} "
                      f"{'mrr':>6}  ({len(rcases)} cases)")
                rep = None
                for label, opts in configs:
                    rep = rag_eval.evaluate_reverse(
                        index, rcases,
                        lambda i, q, t, source, o=opts: rag.retrieve(i, q, t, opts=o, source=source),
                        source=src)
                    print(f"            {label:22} {rep['hit']:6.3f} {rep['recall']:7.3f} {rep['mrr']:6.3f}")
                cov = rag_eval.reverse_prompt_coverage(
                    index, gold.load(), src, lambda i, q, t, source: rag.retrieve(i, q, t, source=source))
                print(f"            examples (own pair excluded): hit={cov['examples_hit']} "
                      f"recall={cov['examples_recall']}; prompt shows every expected SPL "
                      f"command (docs OR examples): {cov['covered']}")
                if a.verbose and rep:
                    for m in rep["misses"]:
                        print(f"  miss {m['missing']}: {m['query'][:90]!r}")
            return
        cases = rag_eval.load_cases(docs.rag_dir() / "eval.jsonl")
        if a.ablation:
            configs = [
                ("v0 first version", rag.Options(skip_base=False, use_bridge=False, use_rule_bridge=False, expansion_chars=600, mode="bm25")),
                ("+ skip base search", rag.Options(skip_base=True, use_bridge=False, use_rule_bridge=False, expansion_chars=600, mode="bm25")),
                ("+ short expansion", rag.Options(skip_base=True, use_bridge=False, use_rule_bridge=False, expansion_chars=200, mode="bm25")),
                ("+ no expansion", rag.Options(skip_base=True, use_bridge=False, use_rule_bridge=False, expansion_chars=0, mode="bm25")),
                ("+ bridge, expansion", rag.Options(expansion_chars=200, use_rule_bridge=False, mode="bm25")),
                ("+ bridge, no expansion", rag.Options(expansion_chars=0, use_rule_bridge=False, mode="bm25")),
                ("+ rule bridge (bm25)", rag.Options(expansion_chars=0, mode="bm25")),
            ]
            if index.vec is not None:
                configs += [
                    ("vector only", rag.Options(mode="vector")),
                    ("hybrid (BM25+vector)", rag.Options(mode="hybrid", use_rule_bridge=False)),
                    ("hybrid + best per name", rag.Options(mode="hybrid", per_name_best=True, use_rule_bridge=False)),
                    ("hybrid + rule bridge", rag.Options(mode="hybrid", per_name_best=True)),
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
        from . import gold
        official = rag_eval.evaluate(index, cases, lambda i, s, t: rag.retrieve(
            i, s, t, opts=rag.Options(use_rule_bridge=False)))
        for t, r in official.items():
            print(f"{t.upper()}: docs, official bridge only  hit={r['hit']} recall={r['recall']} "
                  f"mrr={r['mrr']}")
        rep = rag_eval.evaluate(index, cases, rag.retrieve)
        exa = rag_eval.evaluate_examples(gold.load(), cases)
        for t, r in rep.items():
            e = exa[t]
            # combined: a name counts as covered if the docs OR the examples show it
            doc_miss = {m["spl"]: set(m["missing"]) for m in r["misses"]}
            ex_miss = {m["spl"]: set(m["missing"]) for m in e["misses"]}
            both = {s: doc_miss[s] & ex_miss.get(s, set()) for s in doc_miss}
            both = {s: m for s, m in both.items() if m}
            n = r["cases"] or 1
            print(f"{t.upper()}: docs      hit={r['hit']} recall={r['recall']} mrr={r['mrr']}")
            print(f"{t.upper()}: examples  hit={e['hit']} recall={e['recall']}")
            print(f"{t.upper()}: prompt    cases with an expected name missing from docs AND "
                  f"examples: {len(both)}/{r['cases']} (covered {1 - len(both) / n:.3f})")
            for s, m in both.items() if a.verbose else []:
                print(f"    still missing {sorted(m)}  <- {s}")
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
