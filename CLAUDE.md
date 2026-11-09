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
gold/pairs.jsonl                verified SPL -> KQL/XQL pairs (siemx/gold.py): few-shot examples
                                in the LLM prompt. verified_by "docs+tests" = rule output with no
                                caveat (siemx gold seed); a person's name = human-reviewed
                                (siemx gold add <file> --to kql --by <name>). siemx gold check
                                (and tests) fail if the rules no longer give a gold answer.
rag/sources.json                RAG corpus: ~1,009 official doc URLs (SPL 9.4, KQL, XQL). Committed.
rag/raw/, rag/index/            downloaded pages / chunks.jsonl + bridge.json. Git-ignored
                                (Splunk/Palo Alto docs are copyrighted; rebuild with siemx docs ...)
rag/eval.jsonl                  retrieval test set (labels from verified rule mappings)
siemx/docs.py                   RAG step A: discover + fetch + clean (Splunk HTML -> Markdown)
siemx/chunking.py               RAG step B: heading-aware chunks with metadata
siemx/retrieve.py               RAG step C: BM25, language filter, name lookup, official bridge
siemx/rag_eval.py               RAG step E: hit / recall / MRR
siemx/vectors.py                RAG step D (optional, pip install -e ".[rag]"): Chroma +
                                local all-MiniLM-L6-v2 embeddings, RRF fusion; index in
                                rag/index/chroma (siemx docs embed)

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
- Never commit API keys. ANTHROPIC_API_KEY / SIEMX_API_KEY come from env / CI secrets.
- The LLM is a setting (siemx/llm.py docstring): SIEMX_PROVIDER anthropic | ollama |
  openai (any OpenAI-compatible API), SIEMX_MODEL, SIEMX_BASE_URL; CI reads them from
  repository variables. Anthropic cache keys are unchanged; other providers add
  provider + base_url to the key. Meta records llm.model_id().
- LLM results are never auto-approved (config.LLM_AUTO_APPROVE = False) until the pilot
  shows the model's confidence is trustworthy. Do not turn it on without that data.
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
   Step D (optional extra [rag]): local embeddings in Chroma; vector query = first sentence
   of the SPL command's own description; BM25 and vector rankings fused with RRF (k=60),
   plus the best vector hit per SPL function added after the fused results.
   Measured: vector-only is worse than BM25+bridge for KQL (0.54 vs 0.63); hybrid +
   best-per-name keeps KQL at 0.63 and lifts XQL hit 0.50 -> 0.75 (no official XQL bridge).
   Default mode = hybrid; falls back to BM25 when Chroma / the vector index is missing.
   Do not build a bridge from the eval labels (evaluation leakage).
4. DONE gold/pairs.jsonl + loader; the 3 most similar pairs (shared SPL commands/functions)
   go into the prompt; examples are SYNTAX, field names illustrative (said in the prompt).
   Seeds only include caveat-free rule output. Measured (siemx docs eval): docs + examples
   cover 83% of KQL / 92% of XQL eval cases (docs alone: 63% / 75% hit). Remaining gaps
   (dc, concat/strcat, lookup, join, strftime) need human-reviewed pairs, not guesses.
   Evaluation excludes the exact query from its own examples (leakage guard).
   Never put SPL/KQL/XQL keywords (where, if, not, has...) in the BM25 stopword list.
5. DONE validate.py: KQL with Microsoft's official parser (Kusto.Language, npm
   @kusto/language-service-next 12.4.1) in one long-running Node process
   (tools/kql-validate; install: npm ci --prefix tools/kql-validate). Syntax always;
   semantic analysis with the table schema from fields.json (unknown functions/columns,
   type errors only when column types are known). XQL: no public parser; stage and
   function names are checked against the official reference (rag/sources.json).
   Rule output and gold are validated with scope="rules" (syntax + unknown functions);
   LLM output with scope="all". The retry prompt gets the previous query and the exact
   errors with line/column. All 56 rule outputs of the 40-query test set and all 44 gold
   targets pass. A Cortex dry-run (real XQL check) would need a tenant + API key.
6. DONE (framework + Windows defaults) field mapping, siemx/fieldmap.py:
   mappings/field_map.json (shared) + mappings/clients/<client>/field_map.json, per target
   table, with an evidence level: exact (applied), conditional (applied + flagged with its
   condition), ambiguous (not applied; candidates flagged). No official full crosswalk
   exists (Microsoft's Splunk migration guide says to build your own). Shared SecurityEvent
   defaults come from Microsoft's Windows event docs (label <-> XML name) and are never
   exact; `siemx fields import-props <props.conf> --stanza ... --client ... --table ...`
   turns a client's own FIELDALIAS lines into exact entries (EVAL coalesce -> ambiguous).
   Only fields READ from the source table and never CREATED in the query are renamed
   (schema.field_reads), so the SPL identifier rename is safe. The LLM prompt gets the
   matching entries. XQL / XDM entries: TODO (needs the xdr_data field list).
7. PART 1 DONE: KQL -> SPL by rules (siemx/reverse.py, siemx/kql_expr.py):
   `siemx convert --from kql` reads detections/kql/**/*.kql, writes converted/spl/.
   Input checked with Microsoft's parser; table -> base search from sources.json read
   backwards; TimeGenerated > ago(N) -> earliest=-N; where/project/project-away/
   project-rename/extend/summarize/count/take/sort/top/distinct. KQL sort is DESC by
   default; sort 0 avoids SPL's 10,000-row cap; =~/contains use lower() + like() with
   lowercased values (SPL like/in case sensitivity is undocumented); `has` -> unsupported.
   Round-trip tests: KQL -> SPL -> KQL gives the original for exact cases.
   PART 2 DONE: LLM fallback for KQL -> SPL, only for rule gaps (operator/expression).
   Invalid KQL, no table first, or a table with no SPL source -> unsupported, no LLM
   (the model cannot know the client's index). The prompt fixes the SPL base search from
   sources.json; RAG reuses retrieve.py with source="kql" (KQL docs by name, Microsoft's
   bridge inverted, SPL docs by BM25/vectors) and gold pairs read backwards (shared KQL
   operators/functions). Output validated by an SPL command-name check against the
   official Search Reference (validate.spl_problems; functions are not checked, the docs
   group them). Every LLM result warns that column names are still the KQL table's ->
   always needs-review. Forward prompt text unchanged (cache keys stay valid).
   `siemx docs eval --reverse`: 24 gold pairs read backwards, hybrid hit 0.96 / recall
   0.92 / MRR 0.50 (BM25 alone 0.29). Known misses: arg_max->dedup, extract->rex,
   bin->timechart (KQL function vs SPL command).
   PART 3 DONE: XQL -> SPL (siemx/reverse_xql.py, siemx/xql_expr.py), `--from xql`.
   No official XQL parser: input checked for balance + stage/function names against the
   official reference (// comments stripped first); failing input -> unsupported, no LLM.
   config timeframe = N<S|M|H|D|W> -> earliest= (M = minutes; MO/Y not translated);
   no dataset stage = xdr_data (documented default); dataset in/preset/datamodel -> no LLM.
   XQL string comparison is case-INSENSITIVE by default (stages/config.md) -> lower(x)==
   "<lowercased>"; config case_sensitive = true -> plain ==. "..." * wildcard -> like().
   and/or mixed without parentheses, `not` without parentheses -> unsupported (XQL
   precedence not documented). sort needs asc/desc and comp needs `as` (defaults not
   documented). filter/alter/fields/comp/sort/limit/dedup; other stages -> LLM fallback
   with the base search (+ earliest). All 19 gold XQL targets convert back by rules.
   Retrieval: no official XQL bridge exists (the Cortex "Translate to XQL" page lost its
   XQL column: the cells hold the SPL query's tail), and a bridge from our own rules
   would make the eval circular. Docs alone: hybrid hit 0.45; gold examples read
   backwards: hit 0.95; prompt shows every expected SPL command (docs OR examples) 0.95.
   FIXED (converter 20): forward SPL -> XQL. A where/eval string comparison (SPL:
   case-sensitive) now starts the XQL with `config case_sensitive = true` (config.md:
   default false) instead of a "verify" warning; search terms already lowercase both
   sides and need no switch. Inside a join subquery: review warning (whether config
   reaches into a join is not documented); with a join elsewhere: warning that the
   switch may also affect join keys. The forward LLM prompt states this for XQL only
   (KQL prompt text unchanged, its cache stays valid).
8. DONE siemx report (siemx/report.py): converted/<client>/_report/report.md + summary.csv
   (summary per source, warning categories, SPL commands without rules, review accuracy by
   status/method/target/command, LLM auto-approval threshold analysis), --mkdocs writes a
   SIEM Hub page (type: doc).
9. TOOLING DONE, pilot pending (needs real detections in a private repo): PILOT.md runbook;
   siemx pilot-sample (stratified by source type x complexity); siemx verdict
   (correct|fixed|wrong, append-only converted/<client>/_reviews.jsonl, stale when the
   judged query changes). Thresholds change only in a reviewed PR, based on the report.

10. DONE Elastic, as Kibana KQL ("elk", never confused with Microsoft KQL; ext .elk).
   siemx/elk.py: a port of Kibana's grammar.peggy (validator + reader), SPL -> ELK rules
   from the search.py AST; siemx/reverse_elk.py: ELK -> SPL. Sources in elk.py docstring.
   Kibana KQL only filters: base search + later `search` stages convert; table/fields/sort
   are dropped with a warning; any transforming command (stats, eval, ...) -> unsupported
   with the filter part kept in the file (no LLM: a model cannot express stats in a filter
   either). Filter gaps (free text, where) go to the LLM with elk.REFERENCE as its doc.
   Always flagged: keyword case sensitivity vs SPL, unmapped field names (ECS names are
   not seeded: map them in field_map.json under "elk"), missing "elk" index pattern in
   sources.json. ELK input files may start with `# index: <pattern>` (mapped back to a
   Splunk source). Not done: ES|QL and EQL.
11. DONE KQL / XQL -> ELK directly (siemx/to_elk.py; `--from kql|xql --to elk`), reading the
   input with kql_expr / xql_expr and reverse(_xql) pipes/heads. Same filter-only policy as
   SPL -> ELK. Time filters -> note (rule look-back). Case notes follow the source's
   operator semantics. Field names chain through field_map.json: source column -> Splunk
   field (exact kql/xql entry) -> Elastic field ("elk" entry). Gaps (has, regex, ...) go to
   the LLM with build_to_elk_prompt (no base search).
12. DONE ELK -> KQL / XQL directly (siemx/from_elk.py; `--from elk --to kql,xql`). Table from
   the sources.json entry with the same "elk" index pattern (`# index:` header required; no
   header / no mapping -> unsupported, never the LLM). Keyword semantics kept: KQL == /
   contains_cs / startswith_cs / endswith_cs / matches regex "^...$"; XQL with
   `config case_sensitive = true` when strings are compared. Flagged: text-field word
   matching, isnotempty vs `f: *` and "", XQL not/null handling. XQL needs plain field
   names: an unmapped dotted ECS name -> unsupported (map it). Field names chain through
   field_map.json (Elastic -> Splunk via exact "elk" entries -> target).
13. DONE Windows Security mappings from the docs (mappings/SOURCES.md) and editable
   placeholders: an unmapped Splunk source no longer goes to the LLM for the base search;
   rules.first_stage uses EDIT_ME_<Splunk name as written> (kql / xql only; elk keeps it as
   the meta index) and flags it. The LLM prompt names the placeholder when later stages need
   the model. `siemx mappings missing [--write]` lists / adds EDIT_ME_ entries; any
   EDIT_ME_ value in sources.json stays flagged until replaced. CONVERTER_VERSION 22.
14. DONE Rules-only mode: SIEMX_PROVIDER=none or `siemx convert --no-ai`. llm_with_retry
   returns an unsupported {"rules_only": True} result without calling a model;
   process_file writes W_RULES_ONLY naming the stages (no_rule, counted). Meta keeps
   rules_only, so the result is skipped while AI stays off and re-tried once a provider is
   set (is_current).
15. DONE Elastic in the RAG: docs.discover_elk (Kibana KQL pages from elastic/elasticsearch and
   elastic/docs-content, Security rule types, every ECS field set from elastic/ecs; Markdown
   on GitHub, cited as elastic.co/docs), clean_elastic_markdown (MyST: front matter,
   {{subs}} from docs-content docset.yml, $$$anchors$$$, :::{note}, {applies_to}),
   retrieve.retrieve_elk (Kibana syntax chunks + the ECS definition of each dotted field +
   for ELK -> KQL/XQL/SPL the target operators each construct becomes). llm.retrieve keeps
   elk.REFERENCE first and adds these when the index is built.

## Open questions (need a human with access)
- Elastic: index patterns per sourcetype and the ECS field names in use (field_map.json "elk").
- XQL: field list for xdr_data; `count` as an alias; whether `fields - x` keeps all other fields.

## Definition of done for any task
Tests pass, a sample SPL converts correctly end to end, and no secrets or real detection content is committed outside detections/.
