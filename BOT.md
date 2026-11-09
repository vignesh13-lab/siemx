# The conversion bot (GitHub automation)

How siemx converts detections on GitHub by itself, what the "bot branch" is, and how to
review, run and configure it. No prior knowledge assumed. For siemx itself, see
[GUIDE.md](GUIDE.md).

## Contents

1. [What the bot does, in one picture](#1-what-the-bot-does-in-one-picture)
2. [When it runs](#2-when-it-runs)
3. [What one run does, step by step](#3-what-one-run-does-step-by-step)
4. [The bot branch and its pull request](#4-the-bot-branch-and-its-pull-request)
5. [Reviewing and merging a bot pull request](#5-reviewing-and-merging-a-bot-pull-request)
6. [Running it by hand (a client, a folder)](#6-running-it-by-hand-a-client-a-folder)
7. [Settings: AI, keys, permissions](#7-settings-ai-keys-permissions)
8. [What it does not do](#8-what-it-does-not-do)
9. [Troubleshooting](#9-troubleshooting)
10. [Questions people ask](#10-questions-people-ask)

---

## 1. What the bot does, in one picture

The "bot" is a GitHub Actions workflow called **convert-detections**
(`.github/workflows/convert.yml`). Nobody has to run siemx on a laptop: when detections
or mappings change, GitHub converts them and proposes the result as a pull request.

```
 You merge a change into main            (detections, mappings, siemx code)
             |
             v
 GitHub starts "convert-detections" on a fresh cloud machine
             |
             v
 It runs:  siemx convert --to kql,xql,elk      (unchanged detections are skipped)
             |
             v
 It commits ONLY the changed converted/ files to the branch
 bot/siemx-conversions and opens or updates the pull request
 "siemx: converted detections"
             |
             v
 A person reviews it and merges it into main
```

The bot never merges anything itself. Every converted query reaches `main` through a
person.

## 2. When it runs

| Trigger | When | Notes |
|---|---|---|
| A merge into `main` that changes `detections/spl/**`, `mappings/**`, `gold/**` or `siemx/**` | automatically, minutes after the merge | the usual way |
| **Actions -> convert-detections -> Run workflow** | when you click it | optional client name and folder (section 6) |
| Every Sunday at 02:00 UTC | automatically | today it usually finds nothing to do (section 8) |

It does **not** run for:

- changes to `converted/**` (so merging the bot's own pull request does not start it
  again: there is no loop)
- changes to guides, tests or `rag/`
- files in `detections/kql/`, `detections/xql/` or `detections/elk/`: the bot converts
  **Splunk detections only**. The other directions are run on a laptop (GUIDE.md section 11).
- anything on other branches: only merges into `main` count

## 3. What one run does, step by step

| Step | What happens |
|---|---|
| 1. Check out | GitHub copies the repository at the latest `main` |
| 2. Install | Python 3.12, `pip install -e .` (siemx), `npm ci --prefix tools/kql-validate` (Microsoft's KQL checker) |
| 3. Convert | `siemx convert --to kql,xql,elk --workers 4` (with the folder, if one was given). Detections whose file, mappings and siemx version are unchanged are skipped, because the `converted/_meta` files committed by earlier runs record what was converted |
| 4. Summary | `siemx status` is written to the run's summary page: how many are auto-approved, needs-review, unsupported |
| 5. Pull request | the changed files under `converted/` are committed to the bot branch, and the pull request is opened or updated |

Each run takes a few minutes. Watch it under **Actions -> convert-detections -> the run**.

## 4. The bot branch and its pull request

| Item | Value |
|---|---|
| Branch | `bot/siemx-conversions` (with a client: `bot/siemx-conversions-<client>`) |
| Pull request title | `siemx: converted detections` (with a client: `... (<client>)`) |
| Commit message | `siemx: update converted queries` |
| Files it may change | only `converted/**` (queries, `_meta`, the AI answer cache) |

How it behaves:

- **One pull request at a time** (per client). If one is already open, the next run
  updates it instead of opening another.
- **Nothing to change, no pull request.** A run that changes no files exits quietly. An open
  bot pull request that is no longer needed (because `main` already has the same files) is
  closed automatically.
- **Always built on the latest `main`.** Each run starts from `main`, so the pull request
  holds the complete current result, not just the last change.
- **Treat the branch as read-only.** The tool behind it (create-pull-request) updates the
  branch on every run, and its documentation does not promise that commits added by hand
  survive. Do not fix queries on the bot branch (section 5).

## 5. Reviewing and merging a bot pull request

### What to look at

1. **The run's summary page** (linked from the pull request's checks, or under Actions): the
   counts per status.
2. **Files changed** in the pull request:

| File | Look for |
|---|---|
| `converted/kql/...kql`, `converted/xql/...xql`, `converted/elk/...elk` | the new or changed queries |
| `converted/_meta/...json` | `status` and `warnings`: what a person must check |
| `converted/_cache/...` | saved AI answers; nothing to review |

3. **The readable list**, easier than reading JSON. On your PC:

```powershell
git fetch
git checkout bot/siemx-conversions
siemx review              # every result that needs a person, with the reasons
git checkout main
```

### Then

- **Looks right:** approve and merge.
- **Something is wrong in a query:** merge anyway or not, but **do not fix it on the bot
  branch**. Fix the cause instead (a mapping, a macro, the detection itself) on a normal
  branch, merge that, and the bot produces a corrected pull request.
- **Record what you checked:** `siemx verdict <file> --to kql --result correct|fixed|wrong
  --by "<name>"` (GUIDE.md section 12), on a normal branch.

Why fix the cause and not the output: a hand-edited query in `converted/` is replaced the
next time that detection is converted (for example after a mapping change or a siemx
update). Keeping reviewed fixes across reconversions is a planned feature.

### "Why did this pull request change hundreds of files?"

That is expected after:

- a change in `mappings/` (every detection using it is converted again)
- a siemx update that changes output (the converter version goes up, so everything is
  redone once)

The commit list of `main` shows which merge started the run.

## 6. Running it by hand (a client, a folder)

1. On GitHub: **Actions** (top menu) -> **convert-detections** (left) -> **Run workflow**
   (right).
2. Fill in, both optional:

| Field | Example | Effect |
|---|---|---|
| Client name | `acme` | uses `mappings/clients/acme/` and writes to `converted/acme/`; the branch becomes `bot/siemx-conversions-acme` |
| Folder | `windows` | converts only `detections/spl/windows/**` |

3. Click **Run workflow**. A pull request appears when the run ends (if anything changed).

## 7. Settings: AI, keys, permissions

All under the repository's **Settings**. Only maintainers can change them.

### AI model (Settings -> Secrets and variables -> Actions)

| Name | Kind | Value | Meaning |
|---|---|---|---|
| `SIEMX_PROVIDER` | **Variable** | `none` | rules only, no AI (recommended until the pilot is done) |
| | | `anthropic` / `openai` | a paid AI (needs approval and a key) |
| | | not set | defaults to `anthropic`; with no key, AI steps fail and are retried every run |
| `SIEMX_MODEL` | Variable | e.g. `claude-sonnet-5-5` | the model name |
| `SIEMX_BASE_URL` | Variable | the API address | only for `openai` (Azure OpenAI, a company gateway) |
| `ANTHROPIC_API_KEY` | **Secret** | the key | for `anthropic` |
| `SIEMX_API_KEY` | Secret | the key | for `openai` |

Variables are readable settings; secrets are hidden keys. Never put a key in a file.
The bot cannot reach Ollama on anyone's PC.

### Permission the bot needs (Settings -> Actions -> General -> Workflow permissions)

**"Allow GitHub Actions to create and approve pull requests"** must be ticked, or the
last step fails. (It is ticked in this repository: the bot has opened pull requests.)

### Branch protection and the bot

Pull requests opened by the bot do **not** start other workflows (GitHub's rule for its
built-in token), so the `tests` workflow does not run on them. If `main` is ever protected
with "require the tests check to pass", bot pull requests will wait for a check that
never comes. Then either exempt `bot/siemx-conversions*` from that check, or give the bot
its own token (a GitHub App or personal access token stored as a secret).

## 8. What it does not do

| Limitation | Consequence | What to do |
|---|---|---|
| It only sees what is committed | detections on someone's PC are never converted by the bot | commit them (private repository only) |
| Splunk input only | KQL / XQL / Elastic input files are not converted | run those on a laptop |
| No documentation index | an AI used by the bot gets no official doc excerpts | use rules only (`none`) for now |
| The Sunday run skips unchanged files | it rarely changes anything | planned: a real weekly docs and model recheck |
| No tests on bot pull requests | nothing re-checks the converted files there | review the pull request; the queries were validated during conversion |
| Hand fixes are not kept | a fix in `converted/` is replaced on reconversion | fix the cause (mapping, macro, detection); planned: pinned fixes |
| It never merges | queries wait until a person merges | review bot pull requests promptly |

## 9. Troubleshooting

| Problem | Likely cause | Fix |
|---|---|---|
| No bot pull request after a merge | nothing changed in the output, or the merge did not touch a trigger path | normal; check the run under Actions |
| The run is red (failed) | open the run, click the red step | see the rows below |
| Fails at "Open PR with converted queries" | the workflow permission is off | section 7: tick "Allow GitHub Actions to create and approve pull requests" |
| Fails at "Install the official KQL parser" | `tools/kql-validate` changed or npm was down | re-run the job; if it repeats, check the latest change to `tools/` |
| Many results say `LLM step failed: no AI model configured` | no AI set up for the bot | set the variable `SIEMX_PROVIDER` to `none` |
| Results show `EDIT_ME_...` | a data source is not mapped | `siemx mappings missing --write` locally, fill in, merge (GUIDE.md section 8) |
| The pull request cannot be merged: "checks pending" | branch protection requires tests | section 7, branch protection |
| The pull request closed by itself | `main` already contains the same converted files | nothing to do |
| A client run wrote to `converted/` instead of `converted/<client>/` | the client name was left empty | run again with the client name |

## 10. Questions people ask

**Does the bot change detections or mappings?** No. It only writes under `converted/`.

**Can the bot put a wrong query into production?** No. It only proposes a pull request;
a person merges it, and deploying a query to a SIEM is a separate, manual step.

**Does it send our detections anywhere?** Only to the AI provider set in section 7, and
only for detections the rules cannot convert. With `SIEMX_PROVIDER` = `none`, nothing
leaves GitHub.

**Why is the converted output in the repository at all?** So every change to a converted
query is reviewed in a pull request and has a history, and so the next run knows what is
already converted.

**Can two runs collide?** Each run starts from the latest `main` and rewrites the bot
branch, so the most recent run's result is what the pull request shows.

**How do I stop it for a while?** Actions -> convert-detections -> the "..." menu ->
**Disable workflow**. Enable it again the same way.
