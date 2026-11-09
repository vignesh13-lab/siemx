<p align="center">
  <img src="docs/assets/siemx-logo.svg" alt="siemx: SIEM detection converter" width="560">
</p>

<p align="center">
  <b>Convert security detections between Splunk, Microsoft Sentinel, Palo Alto Cortex and Elastic,<br>
  accurately, with every uncertain point flagged for a person.</b>
</p>

<p align="center">
  <img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-3776AB">
  <img alt="Tests" src="https://img.shields.io/badge/tests-1025%20passing-2EA44F">
  <img alt="AI optional" src="https://img.shields.io/badge/AI-optional-38BDF8">
  <img alt="Languages" src="https://img.shields.io/badge/SPL%20%C2%B7%20KQL%20%C2%B7%20XQL%20%C2%B7%20Elastic-0B1F33">
</p>

<p align="center">Created and maintained by <a href="https://github.com/vignesh13-lab"><b>Vignesh</b></a></p>

---

## Contents

- [What siemx does](#what-siemx-does)
- [Supported conversions](#supported-conversions)
- [How it works](#how-it-works)
- [Design principles](#design-principles)
- [Quick start](#quick-start)
- [Input files](#input-files)
- [Results and review](#results-and-review)
- [Mappings: data sources and field names](#mappings-data-sources-and-field-names)
- [AI: optional](#ai-optional)
- [Official documentation index (RAG)](#official-documentation-index-rag)
- [GitHub automation (the bot)](#github-automation-the-bot)
- [Commands](#commands)
- [Project layout](#project-layout)
- [Status and limits](#status-and-limits)
- [Contributing](#contributing)
- [Documentation](#documentation)
- [Author](#author)

---

## What siemx does

A security team's detections are saved searches written in one SIEM's language. Moving
to, or also supporting, another SIEM means rewriting every detection: with about 1,000
detections, months of analyst work and plenty of room for silent mistakes.

siemx does the rewriting. It reads one detection per file, writes the equivalent query
for each target SIEM, and gives every result a status with its reasons:

| Status | Meaning |
|---|---|
| **auto-approved** | converted by verified rules, nothing to check |
| **needs-review** | converted, with the exact points a person must confirm |
| **unsupported** | no faithful translation; the reason is stated |

It is built for **accuracy, not speed**. When something is uncertain, siemx says so
instead of guessing.

## Supported conversions

| From | To | Input folder |
|---|---|---|
| Splunk **SPL** | Sentinel **KQL**, Cortex **XQL**, Elastic **Kibana KQL** | `detections/spl/*.spl` |
| Sentinel **KQL** | SPL, Elastic | `detections/kql/*.kql` |
| Cortex **XQL** | SPL, Elastic | `detections/xql/*.xql` |
| Elastic **Kibana KQL** | SPL, KQL, XQL | `detections/elk/*.elk` |

In siemx, Elastic's Kibana Query Language is called **`elk`**, so it is never confused
with Microsoft's KQL. Sentinel and Cortex convert to each other through SPL.

## How it works

```
 detections/spl/windows/failed_logins.spl          one detection per file
                 |
                 v
   1. Mappings      Splunk source -> table / dataset / index pattern
                    Splunk field  -> the other SIEM's field name
                 |
                 v
   2. Rules         each command converted exactly, checked against official docs
                 |
                 |  no rule?  (optional)
                 v
   3. AI fallback   official doc excerpts + verified examples; told to flag, not guess
                 |
                 v
   4. Validator     KQL: Microsoft's parser · XQL / SPL: official name references ·
                    Elastic: Kibana's own grammar
                 |
                 v
   5. Status        auto-approved | needs-review | unsupported, with reasons
                 |
                 v
   6. People        review, record verdicts; the report measures real accuracy
```

Example: `source=XmlWinEventLog:Security EventCode=4625 Logon_Type=3 | stats count as failures by Account_Name, ComputerName | where failures > 10`

```
KQL:  SecurityEvent
      | where EventID == 4625 and LogonType == 3
      | where isnotempty(Account_Name) and isnotempty(Computer)
      | summarize failures = count() by Account_Name, Computer
      | where failures > 10

XQL:  dataset = xdr_data
      | filter action_evtlog_event_id = 4625 and Logon_Type = 3
      | filter Account_Name != null and agent_hostname != null
      | comp count() as failures by Account_Name, agent_hostname
      | filter failures > 10

ELK:  event.code: 4625 and winlog.event_data.LogonType: 3
```

`Account_Name` is deliberately not renamed: in Windows logon events it can mean two
different accounts, so a person chooses. Elastic gets only the filter, because Kibana KQL
cannot count; the review notes say so.

## Design principles

| siemx never | Instead |
|---|---|
| invents syntax or field names | marks the result **needs-review** with the exact reason |
| guesses a table it does not know | writes an editable `EDIT_ME_` placeholder |
| auto-approves an AI answer | AI results always need review |
| silently drops something that changes the meaning | writes a warning (e.g. "index=clienta was dropped") |
| sends data out unless you choose a cloud AI | rules only, or a local model: nothing leaves the PC |
| uses an unsourced mapping | every mapping links to the vendor documentation it came from |

## Quick start

Requirements: Windows (or any OS with Python), **Python 3.10+**, **Git**, and **Node.js**
for Microsoft's KQL parser (recommended).

```powershell
git clone <this repository's URL>
cd siemx
python -m venv .venv
.venv\Scripts\activate
pip install -e .                          # installs the `siemx` command
npm ci --prefix tools/kql-validate        # Microsoft's official KQL parser
siemx validate                            # shows which checkers are active
```

Convert, with no AI:

```powershell
siemx convert --no-ai --to kql,xql,elk    # detections/spl -> converted/kql, xql, elk
siemx status                              # counts per status
siemx review                              # what a person must check, and why
siemx report                              # converted/_report/report.md
```

A step-by-step first conversion with real output is in
[GUIDE.md, section 5](GUIDE.md#5-your-first-conversion-step-by-step).

## Input files

One query per file; the folder and extension say the language.

```
detections/spl/windows/failed_logins.spl   source=XmlWinEventLog:Security EventCode=4625 | stats count by user
detections/kql/windows/failed_logins.kql   SecurityEvent | where EventID == 4625
detections/xql/windows/failed_logins.xql   dataset = xdr_data | filter action_evtlog_event_id = 4625
detections/elk/windows/failed_logins.elk   # index: logs-system.security-*
                                           event.code: 4625
```

Key tips for Splunk detections: name the data on the first line (`source=...:Security`),
write `AND` / `OR` / `NOT` in capitals, keep `earliest=` out of the search. Every form
each command accepts, for all four languages: **[INPUT_FILES.md](INPUT_FILES.md)**.

## Results and review

```
converted/
  kql/windows/failed_logins.kql             the Sentinel query
  xql/windows/failed_logins.xql             the Cortex query
  elk/windows/failed_logins.elk             the Elastic query
  _meta/windows/failed_logins.kql.json      status, warnings, method, model, field mappings
  _report/report.md, summary.csv            coverage, review reasons, missing rules, accuracy
```

- `siemx review` lists every result that needs a person, with the reasons.
- `siemx verdict <file> --to kql --result correct|fixed|wrong --by "<name>"` records a review.
- `siemx report` measures coverage and **real accuracy** from the verdicts, and ranks the
  missing rules worth building.
- Running `convert` again only redoes what changed.

Before converting everything, run the 50-detection pilot: **[PILOT.md](PILOT.md)**.

## Mappings: data sources and field names

| File | Holds |
|---|---|
| `mappings/sources.json` | Splunk source -> Sentinel table, Cortex dataset, Elastic index pattern |
| `mappings/field_map.json` | Splunk field -> target field, with an evidence level: `exact`, `conditional`, `ambiguous` |
| `mappings/macros.json` | shared Splunk macro definitions |
| `mappings/clients/<client>/` | per-client overrides (MSSP), used with `--client <client>` |
| `mappings/SOURCES.md` | where every mapping comes from |

Windows Security events are mapped to all three targets from the vendors' documentation.
Mapping is by **sourcetype / source**, not client index, so it works for every client.
Unmapped sources become `EDIT_ME_` placeholders:

```powershell
siemx mappings missing            # which Splunk sources are not mapped yet
siemx mappings missing --write    # add them to sources.json as EDIT_ME_ entries to fill in
siemx fields import-props props.conf --stanza "XmlWinEventLog:Security" --client acme --table SecurityEvent
```

## AI: optional

siemx works fully without AI. The AI only tries what no rule converts, and its answers are
always reviewed. The model is a setting, not code:

| Setting | Rules only | Local, free (Ollama) | Paid API |
|---|---|---|---|
| `SIEMX_PROVIDER` | `none` (or `--no-ai`) | `ollama` | `anthropic`, or `openai` (Azure OpenAI, OpenAI, a gateway) |
| `SIEMX_MODEL` | | `qwen2.5-coder:7b` | e.g. `claude-sonnet-5-5` |
| Key | | none | `ANTHROPIC_API_KEY` / `SIEMX_API_KEY`, never in a file |
| Data leaves the PC | no | no | only detections that need the AI |

Every result records which model produced it, so models can be compared on the same pilot.

## Official documentation index (RAG)

For AI answers, siemx downloads the official SPL, KQL, XQL and Elastic documentation
(about 1,070 pages; the text stays local, only URLs are committed) and gives the model the
relevant excerpts, plus a translation bridge built from its own rules.

```powershell
siemx docs discover; siemx docs fetch; siemx docs build; siemx docs embed
siemx docs eval              # measure how well the right pages are found
```

## GitHub automation (the bot)

When detections or mappings change on `main`, the **convert-detections** workflow converts
them and opens a pull request **"siemx: converted detections"** on the branch
`bot/siemx-conversions`. A person reviews and merges it; the bot never merges. It can also
be run by hand for one client or folder. Full guide: **[BOT.md](BOT.md)**.

## Commands

| Command | Does |
|---|---|
| `siemx convert` | convert detections (`--to`, `--from`, `--no-ai`, `--path`, `--force`, `--client`) |
| `siemx status` / `siemx review` | counts per status / what needs a person, with reasons |
| `siemx report` | coverage, review reasons, missing rules, accuracy |
| `siemx verdict <file>` | record a review result |
| `siemx pilot-sample <folder>` | pick a fair sample for the pilot |
| `siemx mappings missing` | unmapped data sources (`--write` adds placeholders) |
| `siemx fields show` / `fields import-props` | field maps |
| `siemx validate [query]` | check one query (`--to kql\|xql\|elk\|spl`) |
| `siemx docs ...` | build and measure the documentation index |
| `siemx gold ...` | verified examples for the AI |

Every command has `--help`. Full reference: [GUIDE.md, section 17](GUIDE.md#17-command-reference).

## Project layout

```
siemx/            the tool (rules, parsers, validators, AI layer, retrieval, CLI)
detections/       input: spl/, kql/, xql/, elk/  (real detections: private repository only)
converted/        output: kql/, xql/, elk/, spl/, _meta/, _report/
mappings/         data sources, field maps, macros, per-client overrides, SOURCES.md
gold/             verified example pairs for the AI
rag/              documentation URL list (downloaded text and indexes are not committed)
tools/            Microsoft's KQL parser (Node.js)
tests/            about 1,000 tests
docs/assets/      logo
```

## Status and limits

Working today: all directions above, rules for the common Splunk commands (`search`,
`where`, `eval`, `stats`, `table`, `rename`, `dedup`, `sort`, `head`, `top`, `rex`,
`timechart`, `lookup`, `join`), Windows Security mappings, placeholders, rules-only mode,
the GitHub bot, and the review and report tools.

Not yet:

- no rules for `tstats` / data models, `transaction`, `streamstats`, `eventstats`, `bin`
- only the query is converted, not the detection's schedule, threshold or severity
- most Cortex field names (Cortex publishes no full field list for `xdr_data`)
- Elastic ES|QL (counting detections are kept as filters only)
- importing `savedsearches.conf` / YAML (export one `.spl` file per detection)
- proxy and authentication source mappings (depend on the vendors in use)
- reviewed fixes are not yet kept when a detection is converted again

Accuracy on a real detection library is measured by the pilot ([PILOT.md](PILOT.md)).

## Contributing

- Never push to `main`: use a branch and a pull request. Every pull request runs the tests.
- Run `python -m pytest -q` before pushing.
- No secrets in files: keys come from environment variables or GitHub secrets.
- Real detections and client names only in the private repository.
- New rules and mappings cite the official documentation they are based on.

## Documentation

| Document | For |
|---|---|
| [GUIDE.md](GUIDE.md) | the full user guide, written for readers with no prior knowledge |
| [INPUT_FILES.md](INPUT_FILES.md) | how to write input files, language by language |
| [BOT.md](BOT.md) | the GitHub automation and its pull requests |
| [PILOT.md](PILOT.md) | the 50-detection pilot: steps and exit criteria |
| [mappings/SOURCES.md](mappings/SOURCES.md) | the sources of every mapping |
| [CLAUDE.md](CLAUDE.md) | design notes and decisions, for maintainers |

## Author

**Vignesh** ([@vignesh13-lab](https://github.com/vignesh13-lab)): idea, design and
maintenance of siemx.
