# siemx pilot: 50 real detections

Goal: measure how well siemx converts **your** detections before converting all ~1,000.
The pilot answers four questions:

1. How many detections convert by rules, by the LLM, or not at all?
2. Of the results marked **auto-approved**, how many were actually correct?
3. Which SPL commands cause the most work (the next rules to build)?
4. Can the LLM's own confidence be trusted for auto-approval (threshold in `siemx/config.py`)?

Questions 2 and 4 need human review. Plan about 15 minutes per detection per target.

## 1. Before you start

| | Why | How |
|---|---|---|
| **Private repository** | Real detections and client index names must not be public | Create a private repo or move this one |
| `ANTHROPIC_API_KEY` | Detections without rules go to the LLM | Repo secret (CI) or environment variable (local) |
| Official KQL parser | Validates every KQL output | `npm ci --prefix tools/kql-validate` |
| Docs index (optional, better LLM output) | RAG over the official docs | `siemx docs discover && siemx docs fetch && siemx docs build`; vectors: `pip install -e ".[rag]"` and `siemx docs embed` |
| Client mappings | Index names, macros and field names differ per client | `mappings/clients/<client>/sources.json` and `macros.json`; field map: `siemx fields import-props <props.conf> --stanza "XmlWinEventLog:Security" --client <client> --table SecurityEvent` |

## 2. Pick the 50

Export the detections as `.spl` files, one folder per source type (`windows/`, `linux/`, ...).
Then pick a stratified sample (proportional per source type and complexity, at least one of
each, repeatable with the same seed):

```
siemx pilot-sample path/to/export -n 50 > pilot.txt
```

Copy the listed files to `detections/spl/` (keep their folders).

## 3. Convert

```
siemx convert --client <client> --to kql,xql
siemx review  --client <client>        # what needs review, and why
```

## 4. Review: how to judge a result

For each output (`converted/<client>/<kql|xql>/...`):

1. Read the warnings (`siemx review`): they say exactly what to check.
2. **Best check: run both queries over the same time window** (Splunk and Sentinel/Cortex)
   and compare the results (row counts, top values). Same data, same answer = correct.
3. Record the verdict:

| Verdict | Meaning |
|---|---|
| `correct` | Right as generated, no edits |
| `fixed` | Usable after an edit. Commit the edited query, then `siemx gold add <file> --to kql --by <you>` so it becomes a verified example |
| `wrong` | Not usable (wrong logic, wrong data, cannot be fixed quickly) |

```
siemx verdict windows/brute_force.spl --to kql --result correct --by <you> [--notes "..."]
```

A verdict stores which query it judged. If the query changes later (new rules or mappings),
the verdict is shown as stale and must be repeated.

## 5. Read the report

```
siemx report --client <client>                       # converted/<client>/_report/report.md + summary.csv
siemx report --client <client> --mkdocs <siem-hub>/docs/reports   # optional SIEM Hub page
```

| Section | What to decide |
|---|---|
| Summary per source | Coverage: rules vs LLM vs unsupported |
| Why outputs need review | Which caveats cost the most review time |
| SPL commands without a rule | Build rules for the top rows first |
| Review results, **by status** | `auto-approved` correct % should be 100%. Any wrong auto-approved result is a bug to fix before scaling up |
| Auto-approval threshold | The lowest threshold with acceptable precision. Change `CONF_AUTO_APPROVE` only in a reviewed PR |

## 6. Suggested exit criteria (agree on these before starting)

- Auto-approved: 100% correct (no exceptions in the sample).
- Rules + reviewed LLM output: at least 80% `correct` or `fixed`.
- Every `wrong` result has a recorded reason (rule bug, mapping, LLM, unsupported feature).

If the criteria are met, convert the rest in batches by source type. If not, fix the top
causes from the report and repeat the pilot on a new sample (`--seed 8`).
