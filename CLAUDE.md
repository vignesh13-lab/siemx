# siemx: SIEM query translator (SPL <-> KQL <-> XQL)

## Goal
Convert ~1000 Splunk SPL detections to KQL (Microsoft Sentinel) and XQL (Palo Alto Cortex),
and later in reverse (KQL/XQL -> SPL). Accuracy matters more than speed. Output is reviewed
through PRs; low-confidence results must be flagged, never guessed.

## Architecture
SPL -> split into pipe stages (triage.py) -> deterministic rules (rules.py)
   -> if any stage has no rule: RAG + Claude fallback (llm.py) -> validate.py (+ retry)
   -> write converted/<lang>/... and converted/_meta/<name>.<lang>.json (pipeline.py)
CLI in cli.py: `siemx convert | status | review`. Unchanged inputs are skipped by hash.
CI: .github/workflows/convert.yml runs convert and opens a PR on bot/siemx-conversions.

## Repo layout
detections/spl/<source>/*.spl   originals (source of truth)
converted/{kql,xql}/...         generated output (never edit by hand)
converted/_meta/*.json          status, confidence, warnings, model, src_hash
mappings/sources.json           index/sourcetype -> table/dataset (and later field maps)
gold/                           human-verified translation pairs (RAG examples + test set)
docs_index/                     (to build) chunked official docs + vector store

## Rules for working here
- Rules in rules.py are STARTER rules. Verify each against official docs before relying on it.
- Never invent syntax. If no faithful equivalent exists, mark `unsupported` with an explanation.
- Every new rule needs a test in tests/ with an SPL input and the expected KQL and XQL.
- Keep statuses: auto-approved / needs-review / unsupported. Do not loosen the thresholds in config.py silently.
- Do not call the LLM for stages a rule can handle. Cache LLM results by query hash.
- Never commit API keys. ANTHROPIC_API_KEY comes from env / CI secrets.
- Python 3.10+, type hints, small functions, no heavy frameworks.

## Commands
pip install -e .
siemx convert --to kql,xql [--force] [--workers 4]
siemx status
siemx review
pytest -q

## Roadmap (do in order; each item = a PR-sized change with tests)
1. tests/: pytest setup, tests for triage.split_stages, rules (simple stats/sort/head/table), pipeline skip-by-hash.
2. Expand rules: where, eval (basic functions), dedup, rex, timechart, top, rename, lookup (flag for review), join. Cite the doc page for each mapping in a comment.
3. RAG ingestion: script to load official docs (Splunk SPL reference, Microsoft KQL reference, Cortex XQL reference) from local exports into chunks by command/function with metadata (language, command, version, url); embed into Chroma; implement llm.retrieve() per pipe stage with a language filter.
4. gold/ format (JSONL: spl, kql, xql, notes, verified_by) and loader; feed nearest examples into the prompt.
5. validate.py: real validation (KQL parser or dry-run; XQL dry-run if API available); feed errors into the retry loop.
6. Field mapping: mappings/fields.json (CIM <-> ASIM <-> XDM) applied to field names in outputs.
7. Reverse direction: KQL/XQL -> SPL (parsers for KQL and XQL into the same stage/IR form).
8. Reporting: `siemx report` writing a markdown/CSV summary per source type; hook into the MkDocs catalog.
9. Pilot: run 50 real SPLs, measure accuracy per command, tune confidence thresholds.

## Definition of done for any task
Tests pass, a sample SPL converts correctly end to end, and no secrets or real detection content is committed outside detections/.
