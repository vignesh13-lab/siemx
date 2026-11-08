# siemx: SIEM query translator (SPL <-> KQL <-> XQL)

## Goal
Convert ~1000 Splunk SPL detections to KQL (Microsoft Sentinel) and XQL (Palo Alto Cortex),
and later in reverse (KQL/XQL -> SPL). Accuracy matters more than speed. Output is reviewed
through PRs; low-confidence results must be flagged, never guessed.

## Architecture
SPL -> split into pipe stages (triage.py)
   -> first stage: base search -> table/dataset + filter (rules.first_stage + search.py)
   -> other stages: deterministic rules (rules.py; expressions in expr.py)
   -> checks on rule output (schema.py): unknown/removed field names, row order
      (head/dedup after unordered stages), uniqueness for join max=1
   -> if any stage has no rule: RAG + Claude fallback (llm.py, cached by prompt hash)
      -> validate.py (+ retry)
   -> write converted/<lang>/... and converted/_meta/<name>.<lang>.json (pipeline.py)
CLI in cli.py: `siemx convert | status | review` (review prints the warnings).
Unchanged inputs are skipped by src_hash + CONVERTER_VERSION + mappings_hash (sources,
macros, fields). Meta files mirror the detections/spl folder structure.
CI: .github/workflows/convert.yml runs convert and opens a PR on bot/siemx-conversions;
.github/workflows/tests.yml runs pytest on every PR (Python 3.10 and 3.12).

## Repo layout
detections/spl/<source>/*.spl   originals (source of truth)
converted/{kql,xql}/...         generated output (never edit by hand)
converted/_meta/*.json          status, confidence, warnings, method, model, src_hash, converter
converted/_cache/llm/*.json     LLM answers keyed by sha256(model + system + prompt)
mappings/sources.json           shared: base-search metadata (sourcetype=..., index=...) ->
                                table/dataset. Most specific entry wins; an extra index in the
                                SPL is dropped (flagged unless index=*)
mappings/macros.json            shared Splunk macro definitions (`name` -> text), expanded first
mappings/clients/<client>/      per-client sources.json / macros.json (override shared);
                                select with `--client <client>` or $SIEMX_CLIENT; output goes
                                to converted/<client>/ (index names differ per client)
mappings/fields.json            known columns (+ types) per target table, copied from official
                                schema docs with source URL; used by the field check
siemx/rules.py                  stage rules; every rule's doc links are listed at the top
siemx/search.py                 SPL base-search semantics -> where / filter
siemx/expr.py                   SPL eval/where expressions -> KQL / XQL
siemx/schema.py                 field, order and uniqueness checks over rule outputs
gold/                           (to build) human-verified translation pairs
rag/sources.json                RAG corpus: ~1,009 official doc URLs (SPL 9.4, KQL, XQL). Committed.
rag/raw/, rag/index/            downloaded pages / chunks.jsonl + bridge.json. Git-ignored
                                (Splunk/Palo Alto docs are copyrighted; rebuild with siemx docs ...)
rag/eval.jsonl                  retrieval test set (labels from verified rule mappings)
siemx/docs.py                   RAG step A: discover + fetch + clean (Splunk HTML -> Markdown)
siemx/chunking.py               RAG step B: heading-aware chunks with metadata
siemx/retrieve.py               RAG step C: BM25, language filter, name lookup, official bridge
siemx/rag_eval.py               RAG step E: hit / recall / MRR

## How rule output works
- A rule returns None (no faithful rule -> LLM fallback), a str, rules.Out (str + what it
  reads/creates/drops, order and uniqueness markers) or rules.Flagged (Out + warnings ->
  needs-review). Prefer Flagged over guessing, None over Flagged when semantics differ.
- Bump CONVERTER_VERSION in config.py whenever rule output changes, so unchanged SPL
  is converted again.
- Known open questions are recorded in warnings and in the rule's comment block.

## Rules for working here
- Rules in rules.py are STARTER rules. Verify each against official docs before relying on it.
- Never invent syntax. If no faithful equivalent exists, mark `unsupported` with an explanation.
- Every new rule needs a test in tests/ with an SPL input and the expected KQL and XQL.
- Keep statuses: auto-approved / needs-review / unsupported. Do not loosen the thresholds in config.py silently.
- Do not call the LLM for stages a rule can handle. Cache LLM results by query hash.
- Never commit API keys. ANTHROPIC_API_KEY comes from env / CI secrets.
- Python 3.10+, type hints, small functions, no heavy frameworks.

## Commands
pip install -e ".[dev]"
siemx convert --to kql,xql [--force] [--workers 4] [--client acme] [--path acme]
siemx status
siemx review
siemx docs discover && siemx docs fetch && siemx docs build   # RAG corpus + index
siemx docs eval --ablation                                      # retrieval quality
pytest -q

## Roadmap (do in order; each item = a PR-sized change with tests)
1. DONE tests/: pytest setup, tests for triage.split_stages, rules, pipeline skip-by-hash.
2. DONE Expand rules: where, eval (basic functions), dedup, rex, timechart, top, rename,
   lookup (always flagged), join; plus base search, stats aggregations, fields -,
   multi-field sort. Doc page for each mapping cited in rules.py / search.py / expr.py.
   Follow-ups: eval part 2 (case, match, replace, substr, tonumber, strftime ...),
   stats values/list, timechart by, top by.
3. RAG. DONE (keyword): siemx docs discover | fetch | build | search | retrieve | eval.
   Retrieval per pipe stage: SPL doc by name, then target docs via Microsoft's official
   Splunk-to-KQL cheat sheet ("bridge") and BM25 filtered to the target language.
   Measured (siemx docs eval --ablation): skipping the base search and turning query
   expansion OFF helped; KQL hit 0.21 -> 0.63, XQL 0.46 -> 0.50. Remaining misses are
   renamed functions (len->strlen, rex->extract, head->take/limit).
   NEXT: embeddings (Chroma) + hybrid ranking; keep it only if eval improves.
   Do not build a bridge from the eval labels (evaluation leakage).
4. gold/ format (JSONL: spl, kql, xql, notes, verified_by) and loader; feed nearest examples into the prompt.
5. validate.py: real validation (KQL parser or dry-run; XQL dry-run if API available); feed errors into the retry loop.
6. Field mapping: mappings/field_map.json (CIM <-> ASIM <-> XDM) applied to field names in
   outputs (mappings/fields.json already lists the known target columns for the check).
7. Reverse direction: KQL/XQL -> SPL (parsers for KQL and XQL into the same stage/IR form).
8. Reporting: `siemx report` writing a markdown/CSV summary per source type; hook into the MkDocs catalog.
9. Pilot: run 50 real SPLs, measure accuracy per command, tune confidence thresholds.

## Open questions (need a human with access)
- XQL: field list for xdr_data; `count` as an alias; whether `fields - x` keeps all other fields.

## Definition of done for any task
Tests pass, a sample SPL converts correctly end to end, and no secrets or real detection content is committed outside detections/.
