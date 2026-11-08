# siemx: how it works and how to use it

siemx converts Splunk detections (SPL) into Microsoft Sentinel (KQL) and Palo Alto
Cortex XDR/XSIAM (XQL), and back. It is built for accuracy, not speed: every result
gets a status, and anything uncertain goes to a person for review.

- [1. What it does, in one picture](#1-what-it-does-in-one-picture)
- [2. What it will never do](#2-what-it-will-never-do)
- [3. One-time setup](#3-one-time-setup)
- [4. Mappings for many clients (MSSP)](#4-mappings-for-many-clients-mssp)
- [5. Convert your detections](#5-convert-your-detections)
- [6. Read the results](#6-read-the-results)
- [7. Review and measure](#7-review-and-measure)
- [8. Running it from GitHub instead of a laptop](#8-running-it-from-github-instead-of-a-laptop)
- [9. Choosing the AI model](#9-choosing-the-ai-model)
- [10. A 15-minute demo script](#10-a-15-minute-demo-script)
- [11. Questions people ask](#11-questions-people-ask)

## 1. What it does, in one picture

```
 detections/spl/windows/brute_force_login.spl
                 |
                 v
   +-----------------------------+
   | 1. Rules (deterministic)    |  each SPL command has a rule checked against the
   |    + mappings               |  official docs; sourcetype -> table, field names
   +-----------------------------+
          | a command has no rule
          v
   +-----------------------------+
   | 2. AI fallback (LLM)        |  gets official doc excerpts + verified examples;
   |                             |  told to flag, not guess
   +-----------------------------+
                 |
                 v
   +-----------------------------+
   | 3. Validator                |  KQL: Microsoft's own parser
   |                             |  XQL/SPL: names checked against official references
   +-----------------------------+
                 |
                 v
   status per output:  auto-approved | needs-review | unsupported
                 |
                 v
   4. A person reviews, records a verdict; the report measures accuracy
```

Most common detections are handled entirely by **rules** (step 1). Rules give the same
answer every time and every rule cites the official documentation it was checked
against. The AI is only used for what the rules cannot do, and its answers are always
reviewed.

## 2. What it will never do

| Never | Instead |
|---|---|
| Invent syntax or field names it cannot verify | Marks the output **needs-review** with the exact reason |
| Auto-approve an AI answer | AI results always go to review (`LLM_AUTO_APPROVE = False`) until the pilot proves a model is reliable |
| Silently drop something that changes the meaning | Writes a warning (for example: "index=clienta_win was dropped ...") |
| Guess a client's Splunk index | Uses the sourcetype mapping, or marks the query **unsupported** |
| Send data anywhere with the local model | With Ollama, everything stays on the PC |

## 3. One-time setup

On a Windows PC with Python 3.10+ and Node.js:

```powershell
git clone <your private siemx repo URL>
cd siemx
python -m venv .venv
.venv\Scripts\activate
pip install -e .                          # installs the `siemx` command
npm ci --prefix tools/kql-validate        # Microsoft's official KQL parser
```

Optional, for better AI answers (downloads official documentation; a few minutes):

```powershell
siemx docs discover
siemx docs fetch
siemx docs build
```

Check: `siemx --help` lists the commands.

## 4. Mappings for many clients (MSSP)

A Splunk query starts with *where the data is* (`index=...`, `sourcetype=...`). KQL and
XQL need a **table** instead (`SecurityEvent`, `dataset = xdr_data`). The file
`mappings/sources.json` tells siemx which table belongs to which data.

**You do not need each client's index names.** Map by **sourcetype**, which is the same
for every client:

```json
{
  "sourcetype=XmlWinEventLog:Security": {"kql": "SecurityEvent", "xql": "dataset = xdr_data"}
}
```

Tested result:

| Detection starts with | Result |
|---|---|
| `index=clienta_win sourcetype=XmlWinEventLog:Security ...` | `SecurityEvent`, with a warning that the index was dropped |
| `index=clientb_sec sourcetype=XmlWinEventLog:Security ...` | `SecurityEvent` (same) |
| `sourcetype=XmlWinEventLog:Security ...` | `SecurityEvent` |
| `index=something ...` (index only, no sourcetype) | no rule; sent to the AI, which has to guess, so it is reviewed |

Shared macros work the same way. If detections start with `` `win_security` ``, define it
once for everyone in `mappings/macros.json`:

```json
{ "win_security": "sourcetype=XmlWinEventLog:Security" }
```

Per-client folders (`mappings/clients/<client>/`) are **optional**. Use them only when a
client really differs (for example, a client whose index holds only part of the data).

## 5. Convert your detections

siemx reads **one SPL query per `.spl` file** from `detections/spl/`. Folders are up
to you; one folder per source type works well for reports:

```
detections/spl/
  windows/
    brute_force_login.spl       sourcetype=XmlWinEventLog:Security EventCode=4625 | stats count as failures by user | where failures > 10
    added_to_admin_group.spl    `win_security` EventCode=4732 | stats count by user, host
  linux/
    ...
```

If your detections are stored another way in git (for example Splunk `savedsearches.conf`
or YAML files), they need to be exported to `.spl` files first. siemx has no importer for
those formats yet.

Then:

```powershell
$env:SIEMX_PROVIDER = "ollama"; $env:SIEMX_MODEL = "qwen2.5-coder:7b"   # AI model, see section 9
siemx convert --to kql,xql
```

Output:

```
converted/
  kql/windows/brute_force_login.kql        the Sentinel query
  xql/windows/brute_force_login.xql        the Cortex query
  _meta/windows/brute_force_login.kql.json status, method, warnings, model, ...
```

Running `convert` again only converts files that changed (or files affected by a
mapping or converter change), so it is cheap to rerun.

Useful options:

| Option | Does |
|---|---|
| `--to kql` | only one target |
| `--path windows` | only `detections/spl/windows/**` |
| `--force` | convert everything again |
| `--client acme` | use `mappings/clients/acme/` and write to `converted/acme/` |
| `--from kql` / `--from xql` | the reverse: KQL or XQL files from `detections/kql` or `detections/xql` into SPL |

## 6. Read the results

```powershell
siemx status        # counts per status
siemx review        # every output that needs a person, with the reasons
```

The three statuses:

| Status | Meaning | What you do |
|---|---|---|
| **auto-approved** | Rules only, no warnings, validator passed | Spot-check during the pilot |
| **needs-review** | A result exists but something must be confirmed | Read the warnings, check, fix if needed |
| **unsupported** | No faithful translation | Convert by hand, or add a rule |

Example from a test run with 5 sample detections:

**Rule result** (brute force):

```
SecurityEvent
| where EventID == 4625
| where isnotempty(user)
| summarize failures = count() by user
| where failures > 10
```

Review reason: *"field 'user' is ambiguous for SecurityEvent: one of TargetUserName,
SubjectUserName ... choose the right column"*. The tool knows two columns fit and refuses
to pick one; a person decides.

**AI result** (`transaction user maxspan=5m`, no rule exists):

```
SecurityEvent | where EventID == 4625 | summarize EventCount = dcount(TargetUserName) by TargetUserName | where EventCount > 5
```

Valid syntax, **wrong meaning** (the count is always 1, and the 5-minute window is gone).
This is why AI results are never approved automatically. For XQL the model answered
that `transaction` has no equivalent, so that output is **unsupported**.

Totals for that run (5 detections x 2 targets = 10 outputs, 38 seconds):

| | KQL | XQL |
|---|---|---|
| by rules | 4 | 4 |
| by AI | 1 | 1 |
| needs-review | 5 | 4 |
| unsupported | 0 | 1 |

## 7. Review and measure

After checking an output, record the result:

```powershell
siemx verdict windows/brute_force_login.spl --to kql --result correct --by "<your name>"
siemx verdict windows/failed_login_burst.spl --to kql --result wrong --by "<your name>" --notes "lost the 5-minute window"
```

`--result` is `correct` (as is), `fixed` (needed an edit) or `wrong`.

The best check for a result: **run the SPL in Splunk and the KQL in Sentinel over the same
time range and compare the counts.**

Then:

```powershell
siemx report
```

writes `converted/_report/report.md` and `summary.csv`:

- outputs per source and target: auto-approved / needs-review / unsupported, by rules / by AI
- the most common review reasons
- **SPL commands without a rule, ranked**: the next rules worth building
- **accuracy from the verdicts**, including how often auto-approved results were really correct

For the first real run, follow [PILOT.md](PILOT.md): 50 detections, chosen with
`siemx pilot-sample`, before converting all of them.

## 8. Running it from GitHub instead of a laptop

The workflow `convert-detections` runs on GitHub:

1. A change to `detections/spl/**` or `mappings/**` is merged into `main`
   (or someone starts it by hand: **Actions -> convert-detections -> Run workflow**,
   optionally with a client name).
2. It converts what changed and opens a pull request **"siemx: converted detections"**
   with the new files under `converted/`.
3. A reviewer reads the PR, then merges it. The run's summary page shows the status counts.

Note: GitHub's servers cannot reach a model on your PC (Ollama). There, AI fallback needs a
hosted model (section 9); without one, those detections are simply marked unsupported.

## 9. Choosing the AI model

The model is a setting, not code:

| Setting | Open-source, local (now) | Paid API (later) |
|---|---|---|
| `SIEMX_PROVIDER` | `ollama` | `anthropic`, or `openai` for Azure OpenAI / OpenAI / a company gateway |
| `SIEMX_MODEL` | `qwen2.5-coder:7b` | for example `claude-sonnet-5-5` |
| `SIEMX_BASE_URL` | (default) | `openai` only: the API address |
| key | none | a secret (`ANTHROPIC_API_KEY` or `SIEMX_API_KEY`), never in a file |

On a laptop these are environment variables. On GitHub they are repository
**variables** (Settings -> Secrets and variables -> Actions), and keys are **secrets**.
Each result records which model produced it, so two models can be compared on the same
pilot detections. Rule results do not depend on the model at all.

## 10. A 15-minute demo script

Prepare: setup done (section 3), Ollama running, a folder with 5-10 sample detections,
`converted/` deleted so the run starts clean.

| Min | Show | Say |
|---|---|---|
| 0-2 | Section 1 picture | "Rules first, AI only for gaps, a validator on everything, people decide." |
| 2-4 | `detections/spl/` and `mappings/sources.json` | "One file per detection. Mapping is by sourcetype, so it works for every client." |
| 4-6 | Run `siemx convert --to kql,xql` | "Each detection becomes a Sentinel and a Cortex query." |
| 6-8 | Open a `.kql` file next to its `.spl` | Walk through the brute force example (section 6). |
| 8-10 | `siemx review` | "It tells us exactly what to check, for example which user column." |
| 10-12 | The AI result for `transaction` | "Valid syntax, wrong meaning. That is why AI answers are never auto-approved." |
| 12-14 | `siemx report`, open `report.md` | "This tells us which rules to build next and, after the pilot, how accurate it really is." |
| 14-15 | Next steps | Pilot with 50 real detections (PILOT.md), then decide on the model and the rollout. |

## 11. Questions people ask

**Does it need every client's index names?** No. Map by sourcetype (section 4).
Per-client mappings are only for exceptions.

**Can it convert all ~1,000 detections now?** It can run on all of them, but first run
the 50-detection pilot. That measures real accuracy and shows which missing rules matter
most.

**Is our data sent anywhere?** With the local model (Ollama): no. With a paid API, only
detections that need the AI are sent, as text, to that provider; get approval for that
first. Rule-based conversion never sends anything.

**Who can change the rules or mappings?** Changes go through pull requests, and every
pull request runs the test suite (800+ tests). Restricting who may approve (a
`CODEOWNERS` file plus branch protection) is not set up yet for this repository.

**What if a result is wrong?** Record `siemx verdict ... --result wrong` with a note.
Wrong patterns become new rules or tests, so the same mistake is caught next time.

**What does it not handle yet?** Splunk commands without rules (for example
`transaction`; the report lists them), XQL field names (needs the xdr_data field list),
and importing `savedsearches.conf` / YAML directly.
