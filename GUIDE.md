# siemx user guide

This guide assumes **no prior knowledge**. It explains what siemx is, how to install it,
how to convert your detections, how to read the results, and every command it has.
If you only have 10 minutes, read [section 1](#1-what-siemx-does-in-plain-words) and
[section 5](#5-your-first-conversion-step-by-step). How to write the input files in detail
(every language, what each rule accepts, how to rewrite the rest):
[INPUT_FILES.md](INPUT_FILES.md).

## Contents

1. [What siemx does, in plain words](#1-what-siemx-does-in-plain-words)
2. [Words you will see (glossary)](#2-words-you-will-see-glossary)
3. [How it works](#3-how-it-works)
4. [Install (one time)](#4-install-one-time)
5. [Your first conversion, step by step](#5-your-first-conversion-step-by-step)
6. [Converting your own detections](#6-converting-your-own-detections)
7. [Reading the results](#7-reading-the-results)
8. [Data sources: telling siemx where the data lives](#8-data-sources-telling-siemx-where-the-data-lives)
9. [Field names](#9-field-names)
10. [Elastic (Kibana KQL)](#10-elastic-kibana-kql)
11. [Other directions: KQL, XQL and Elastic as input](#11-other-directions-kql-xql-and-elastic-as-input)
12. [Reviewing and measuring accuracy](#12-reviewing-and-measuring-accuracy)
13. [AI: optional, and how to choose a model](#13-ai-optional-and-how-to-choose-a-model)
14. [Running it on GitHub automatically](#14-running-it-on-github-automatically)
15. [Checking a single query](#15-checking-a-single-query)
16. [Advanced: documentation index and verified examples](#16-advanced-documentation-index-and-verified-examples)
17. [Command reference](#17-command-reference)
18. [Troubleshooting](#18-troubleshooting)
19. [Questions people ask](#19-questions-people-ask)
20. [A 15-minute demo script](#20-a-15-minute-demo-script)

---

## 1. What siemx does, in plain words

A **SIEM** is the system a security team uses to search logs and raise alerts. Each SIEM
has its own search language:

| SIEM | Language | Looks like |
|---|---|---|
| Splunk | SPL | `source=XmlWinEventLog:Security EventCode=4625 \| stats count by user` |
| Microsoft Sentinel | KQL | `SecurityEvent \| where EventID == 4625 \| summarize count() by TargetUserName` |
| Palo Alto Cortex XDR / XSIAM | XQL | `dataset = xdr_data \| filter action_evtlog_event_id = 4625 \| comp count() by ...` |
| Elastic (Kibana) | Kibana KQL | `event.code: 4625 and user.name: "bob"` |

A **detection** is a saved search that finds suspicious activity, for example "more than
10 failed logins for one account". When a company moves from one SIEM to another, or
supports several, every detection has to be rewritten in the other language. With about
1,000 detections, that is months of work.

**siemx does that rewriting.** You give it detections in one language, it writes them in
the others, and it tells you, for each one, how much you can trust the result:

- **auto-approved**: converted by verified rules, nothing to check
- **needs-review**: converted, but something must be checked by a person (siemx says what)
- **unsupported**: could not be converted faithfully (siemx says why)

It is built for **accuracy, not speed**. It never quietly guesses. When something is
uncertain, it says so.

## 2. Words you will see (glossary)

| Word | Meaning |
|---|---|
| SPL / KQL / XQL / Kibana KQL | The search languages of Splunk / Sentinel / Cortex / Elastic. In siemx, Kibana KQL is called **`elk`** so it is never confused with Microsoft's KQL. |
| Detection, query | One search. In siemx: one file, e.g. `failed_logins.spl`. |
| Index, sourcetype, source | Splunk's labels for where data lives and what kind it is (`index=wineventlog`, `sourcetype=XmlWinEventLog`, `source=XmlWinEventLog:Security`). |
| Table / dataset / index pattern | The other SIEMs' equivalent: a Sentinel **table** (`SecurityEvent`), a Cortex **dataset** (`xdr_data`), an Elastic **index pattern** (`logs-system.security-*`). |
| Mapping | A line in a settings file that says "this Splunk source = that table". |
| Field | One value in an event, e.g. the user name. Each SIEM names fields differently (`Account_Name`, `TargetUserName`, `user.name`). |
| Rule | Code in siemx that converts one piece of SPL exactly, checked against the official documentation. Same input = same output, every time. |
| AI fallback (LLM) | Optional. For pieces no rule can convert, an AI model may try. Its answers are **always** reviewed. |
| Validator | A checker that confirms the output is valid syntax (for KQL, Microsoft's own parser). |
| Placeholder | `EDIT_ME_...`: a table name siemx could not know, left for you to fill in. |
| Client | For service providers (MSSP): one customer. Clients can have their own mappings. |

## 3. How it works

```
 detections/spl/windows/failed_logins.spl        (your detection, one per file)
                 |
                 v
   1. Mappings      Splunk source  -> table / dataset / index pattern
                    Splunk field   -> field name in the other SIEM
                 |
                 v
   2. Rules         each SPL command converted exactly, from the official docs
                 |
                 |  a command has no rule?
                 v
   3. AI (optional) tries the rest, using official doc excerpts; told to flag, not guess
                 |
                 v
   4. Validator     KQL: Microsoft's parser; XQL / SPL: names checked against official
                    references; Elastic: Kibana's own grammar
                 |
                 v
   5. Status        auto-approved | needs-review | unsupported, with the reasons
                 |
                 v
   6. People        review, record a verdict; the report measures real accuracy
```

### What siemx will never do

| Never | Instead |
|---|---|
| Invent syntax or field names it cannot verify | Marks the output **needs-review** with the exact reason |
| Guess a table it does not know | Writes an `EDIT_ME_` placeholder for you to fill in |
| Auto-approve an AI answer | AI results always need review |
| Silently drop something that changes the meaning | Writes a warning (e.g. "index=clienta was dropped ...") |
| Send your data anywhere unless you choose a cloud AI | Without AI, or with a local AI (Ollama), nothing leaves the PC |

## 4. Install (one time)

You need a Windows PC. Each step says how to check that it worked.

**Step 1: install the tools.**

| Tool | Why | Get it | Check (in PowerShell) |
|---|---|---|---|
| Python 3.10 or newer | siemx is written in Python | python.org (tick "Add python.exe to PATH") | `python --version` |
| Git | to download the repository | git-scm.com | `git --version` |
| Node.js (LTS) | runs Microsoft's official KQL checker (optional but recommended) | nodejs.org | `node --version` |

**Step 2: open PowerShell** (Start menu, type "PowerShell") and run, one line at a time:

```powershell
git clone <your private siemx repo URL>     # downloads the project
cd siemx                                     # go into it
python -m venv .venv                         # a private Python space for siemx
.venv\Scripts\activate                       # switch into it (the prompt starts with (.venv))
pip install -e .                             # installs the `siemx` command
npm ci --prefix tools/kql-validate           # Microsoft's KQL checker (needs Node.js)
```

**Step 3: check.**

```powershell
siemx --help             # lists all commands
siemx validate           # shows which checkers are active
```

`siemx validate` should print `"kql": "official parser (Kusto.Language)"`. If it says
"basic checks only", Node.js or step 2's last line is missing.

**Every time you open a new PowerShell window**, go to the folder and activate again:

```powershell
cd siemx
.venv\Scripts\activate
```

If activation fails with "running scripts is disabled on this system", run this once:
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, then try again.

## 5. Your first conversion, step by step

This uses four example detections, so you can see every kind of result. (They are made
up for this guide.)

**Step 1: create the detection files.** Each file holds one SPL search. Put them in
`detections/spl/windows/`:

| File | Content |
|---|---|
| `failed_logins.spl` | `source=XmlWinEventLog:Security EventCode=4625 Logon_Type=3 \| stats count as failures by Account_Name, ComputerName \| where failures > 10` |
| `elevated_process.spl` | `source=XmlWinEventLog:Security EventCode=4688 Token_Elevation_Type="*(2)" \| table _time, ComputerName, New_Process_Name, Process_Command_Line` |
| `powershell_encoded.spl` | `index=* sourcetype=wineventlog EventCode=4104 ScriptBlockText="*-enc*"` |
| `failed_login_burst.spl` | `source=XmlWinEventLog:Security EventCode=4625 \| transaction Account_Name maxspan=5m` |

**Step 2: convert** (no AI, so nothing leaves the PC):

```powershell
siemx convert --no-ai --to kql,xql,elk
```

It prints one line per result and a summary:

```
note: rules-only mode (no AI). Queries without a rule are marked unsupported ...
found 4 SPL files -> kql,xql,elk
{"file": "windows/failed_logins", "target": "kql", "status": "needs-review"}
...
{"summary": {"unsupported": 4, "needs-review": 8}}
```

**Step 3: look at the results.** They are in `converted/`:

```
converted/
  kql/windows/failed_logins.kql             the Sentinel query
  xql/windows/failed_logins.xql             the Cortex query
  elk/windows/failed_logins.elk             the Elastic query
  _meta/windows/failed_logins.kql.json      status, reasons, how it was made
```

`failed_logins` became:

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

Notice:

- `source=XmlWinEventLog:Security` became the right table everywhere (from the mappings).
- `EventCode` became `EventID`, `action_evtlog_event_id` and `event.code` (field mappings).
- `Account_Name` was **not** renamed: in Windows it can mean two different accounts, so
  siemx refuses to choose and asks you (see section 9).
- Elastic got only the filter part, because Kibana KQL cannot count (see section 10).

**Step 4: see what needs a person.**

```powershell
siemx status          # how many of each status
siemx review          # every result that needs a person, with the reasons
```

Part of the `siemx review` output:

```
needs-review  kql  detections/spl/windows/failed_logins.spl  conf=0.9  method=rules
    - KQL: field 'Account_Name' is ambiguous for SecurityEvent: one of TargetUserName, SubjectUserName ...
unsupported   kql  detections/spl/windows/failed_login_burst.spl  conf=0.0  method=rules
    - not converted: the rules cannot convert `transaction` (rules-only mode, AI is off) ...
needs-review  kql  detections/spl/windows/powershell_encoded.spl  conf=0.9  method=rules
    - KQL: no table is mapped for sourcetype=wineventlog; the query uses the placeholder EDIT_ME_wineventlog ...
```

That is the whole workflow: **convert, review, fix what is flagged**. The rest of this
guide explains each part in detail.

## 6. Converting your own detections

### Where to put detections

siemx reads **one SPL search per `.spl` file** from `detections/spl/`. Sub-folders are up
to you; one folder per data type (or per client) keeps reports readable:

```
detections/spl/
  windows/
    failed_logins.spl
    elevated_process.spl
  proxy/
    beaconing.spl
```

Rules for the files:

- One search per file. The file name becomes the output name.
- Plain text. Line breaks inside the search are fine.
- Splunk macros like `` `win_security` `` are expanded if they are defined in
  `mappings/macros.json` (section 8).
- If your detections are stored another way (Splunk `savedsearches.conf`, YAML), export
  each search to a `.spl` file first. siemx has no importer for those formats yet.
- A leading `search` and Splunk comments (```` ```...``` ````) are fine.
- Every form each command accepts, and how to rewrite the rest:
  [INPUT_FILES.md](INPUT_FILES.md).

### Converting 1,000 detections

The same command converts every file in the folder, however many there are:

```powershell
siemx convert --to kql,xql,elk
```

Running it **again** is cheap: only files that changed (or whose mappings changed) are
converted again; the rest print `"status": "skipped"`. 200 detections take a few seconds
with rules only.

### All options of `siemx convert`

| Option | What it does | Example |
|---|---|---|
| `--to` | which languages to write: `kql`, `xql`, `elk` (default `kql,xql`) | `--to kql,xql,elk` |
| `--no-ai` | rules only, never call an AI model | `--no-ai` |
| `--path` | only one sub-folder | `--path windows` |
| `--force` | convert everything again, even unchanged files | `--force` |
| `--client` | use a client's own mappings and write to `converted/<client>/` | `--client acme` |
| `--from` | the input language: `spl` (default), `kql`, `xql`, `elk` (section 11) | `--from kql --to elk` |
| `--workers` | how many conversions run at once (default 4; 1 with a local AI) | `--workers 2` |

## 7. Reading the results

### The three statuses

| Status | Meaning | What you do |
|---|---|---|
| **auto-approved** | Converted by rules only, no warnings, validator passed | Spot-check during the pilot |
| **needs-review** | A result exists, but something must be confirmed | Read the warnings, check, edit the output if needed |
| **unsupported** | No faithful translation | Convert by hand, or add a mapping / rule / AI |

### The files

| File | What it is |
|---|---|
| `converted/kql/<folder>/<name>.kql` | the Sentinel query, ready to paste |
| `converted/xql/<folder>/<name>.xql` | the Cortex query |
| `converted/elk/<folder>/<name>.elk` | the Elastic (Kibana KQL) query |
| `converted/_meta/<folder>/<name>.<lang>.json` | the details: status, warnings, method, which model, field mappings used |
| `converted/_report/report.md`, `summary.csv` | the report (section 12) |
| `converted/_reviews.jsonl` | review verdicts (section 12) |
| `converted/_cache/llm/` | saved AI answers, so the same question is not asked twice |

The important parts of a `_meta` file:

```json
{
  "src": "detections/spl/windows/elevated_process.spl",
  "target": "kql",
  "status": "needs-review",
  "method": "rules",          // rules, llm or llm-retry (AI)
  "model": null,              // which AI model, if one was used
  "warnings": ["KQL: field 'EventCode' mapped to EventID (conditional: ...); verify", "..."],
  "validator": "official parser (Kusto.Language)",
  "field_map": {"EventCode": {"to": "EventID", "level": "conditional"}}
}
```

### Common warnings and what to do

| Warning starts with | Means | What to do |
|---|---|---|
| `field 'X' mapped to Y (conditional: ...)` | renamed using a documented mapping that holds under a condition | Check the condition in the note; usually fine |
| `field 'X' is ambiguous ... one of A, B` | two possible fields; siemx did not choose | Pick the right one in the output (section 9) |
| `field(s) not in <table>` / `no field list for ...` | a field name could not be verified | Check the name exists in the target SIEM |
| `no table is mapped for ...; the query uses the placeholder EDIT_ME_...` | the data source is unknown | Fill in the mapping once (section 8) |
| `index=... was dropped` | the table comes from the sourcetype; the client index was removed | Fine, unless that index holds only part of the data |
| ``the rules cannot convert `transaction` `` | no rule for that command (and AI is off) | Convert by hand, or turn AI on (section 13) |
| ``Kibana KQL only selects events; `stats` has no equivalent`` | Elastic's search bar cannot count | Use the filter in an Elastic threshold rule, or ES\|QL (section 10) |
| `matched ... case-insensitively` / `case-sensitively` | the two SIEMs treat upper/lower case differently | Check how the values are stored |
| `validation: ...` | the checker found a syntax problem | Fix the query (the message says where) |
| `LLM step failed: ...` | the AI could not be reached | Check the AI setting (section 13); it is retried on the next run |

## 8. Data sources: telling siemx where the data lives

A Splunk search starts with *where the data is*: `index=...`, `sourcetype=...`,
`source=...`. The other SIEMs need a table, dataset or index pattern instead. The file
**`mappings/sources.json`** holds that translation. One line per data source:

```json
{
  "source=XmlWinEventLog:Security": {"kql": "SecurityEvent", "xql": "dataset = xdr_data", "elk": "logs-system.security-*"}
}
```

### What is already mapped

Windows Security events are mapped from the official documentation of all four products.
The sources are listed in [mappings/SOURCES.md](mappings/SOURCES.md).

| Splunk | Sentinel | Cortex | Elastic |
|---|---|---|---|
| `source=XmlWinEventLog:Security` (with or without `sourcetype=XmlWinEventLog`) | `SecurityEvent` | `dataset = xdr_data` | `logs-system.security-*` |
| `source=WinEventLog:Security` (with or without `sourcetype=WinEventLog`) | same | same | same |
| `sourcetype=WinEventLog:Security` (older Splunk add-on) | same | same | same |

**Deliberately not mapped:** `sourcetype=wineventlog` alone. That sourcetype holds every
Windows log (Security, System, PowerShell, ...), so the right table depends on the
channel. PowerShell event 4104, for example, is not in `SecurityEvent`.

### Map by sourcetype, not by client index (MSSP)

Client index names differ (`index=clienta_win`, `index=clientb_sec`), but the sourcetype
is the same for everyone. siemx matches on sourcetype/source and drops the index, with a
note:

| Detection starts with | Result |
|---|---|
| `index=clienta_win source=XmlWinEventLog:Security ...` | `SecurityEvent`, note: "index=clienta_win was dropped" |
| `index=clientb_sec source=XmlWinEventLog:Security ...` | `SecurityEvent` (same) |

### Sources that are not mapped yet: placeholders

An unmapped source still converts. The table becomes an **editable placeholder** that
keeps the Splunk name, and the result is needs-review:

```
SPL:  index=* sourcetype=wineventlog EventCode=4104 ScriptBlockText="*-enc*"
KQL:  EDIT_ME_wineventlog | where EventCode == 4104 and ScriptBlockText contains "-enc"
XQL:  dataset = EDIT_ME_wineventlog | filter EventCode = 4104 and ...
```

You can replace `EDIT_ME_wineventlog` in the output file. Better: set it **once** for all
detections:

```powershell
siemx mappings missing            # step 1: list unmapped sources and where they are used
siemx mappings missing --write    # step 2: add them to mappings/sources.json as EDIT_ME_ lines
```

Output of step 1:

```
   1  sourcetype=wineventlog                        -> EDIT_ME_wineventlog
        windows/powershell_encoded.spl
```

Step 3: open `mappings/sources.json`, find the `EDIT_ME_` line, and replace each value with
the real name:

```json
"sourcetype=wineventlog": {"kql": "EDIT_ME_wineventlog", "xql": "dataset = EDIT_ME_wineventlog", "elk": "EDIT_ME_wineventlog"}
                                       becomes
"sourcetype=wineventlog": {"kql": "SecurityEvent", "xql": "dataset = xdr_data", "elk": "logs-system.security-*"}
```

Step 4: run `siemx convert` again. Every detection using that source is converted again
with the real name (and its field names are mapped too).

### Macros

If detections use Splunk macros (`` `win_security` ``), define them once in
`mappings/macros.json`:

```json
{ "win_security": "source=XmlWinEventLog:Security" }
```

### Per-client mappings (optional)

Only when a client really differs (for example, an index that holds only domain
controllers). Put the same kind of files in `mappings/clients/<client>/` and convert with
`--client <client>`; output goes to `converted/<client>/`. Client lines override shared
ones.

## 9. Field names

Each SIEM names the same field differently. **`mappings/field_map.json`** holds the
translations, per table, with an **evidence level**:

| Level | Meaning | What siemx does |
|---|---|---|
| `exact` | proven for your data (for example from a client's own Splunk config) | renames silently |
| `conditional` | right under a stated condition | renames, and adds a note with the condition |
| `ambiguous` | several possible fields | does **not** rename; lists the candidates for you |

Already mapped for Windows Security (details and sources in
[mappings/SOURCES.md](mappings/SOURCES.md)):

| Splunk | Sentinel | Cortex | Elastic |
|---|---|---|---|
| `EventCode` | `EventID` | `action_evtlog_event_id` | `event.code` |
| `ComputerName` | `Computer` | `agent_hostname` | `winlog.computer_name` |
| `New_Process_Name` | `NewProcessName` | (inside a JSON column) | `process.executable` |
| `Process_Command_Line` | `CommandLine` | (inside a JSON column) | `process.command_line` |
| `Account_Name`, `user` | **ambiguous**: `TargetUserName` or `SubjectUserName` | | **ambiguous** |

Why `Account_Name` is ambiguous: in a Windows logon event there are two accounts, the one
that asked for the logon (subject) and the one that logged on (target). Splunk's classic
logs call both "Account Name". Only a person who knows the detection can choose.

Useful commands:

```powershell
siemx fields show --table SecurityEvent              # the field map for a table
siemx fields show --table xdr_data --to xql
siemx fields import-props props.conf --stanza "XmlWinEventLog:Security" --client acme --table SecurityEvent
```

The last one reads a client's own Splunk `props.conf` (from their Windows add-on) and
creates `exact` mappings for that client, which is the strongest evidence possible.

## 10. Elastic (Kibana KQL)

```powershell
siemx convert --to elk
```

Kibana KQL is the language of Kibana's search bar and of Elastic "custom query" rules.
**It only selects events.** It cannot count, calculate or pick columns. So:

| SPL detection | Elastic result | Status |
|---|---|---|
| search terms only | the full filter | needs-review |
| plus `table` / `fields` / `sort` | the filter; those stages are dropped with a note (they only choose columns) | needs-review |
| plus `stats`, `eval`, `transaction`, ... | **only the filter part** is written to the file | unsupported |

For an "unsupported" Elastic result, the file still holds the filter. Use it in an
Elastic **threshold rule** (for "count per user > 10" detections) or rewrite the counting
in ES|QL.

Things siemx always flags for Elastic:

- Elastic matches most fields **exactly and case-sensitively**; Splunk ignores case.
- `source.ip` is an IP field: Kibana fails on a wildcard like `10.*` there. Use a range
  such as `10.0.0.0/8`.
- Elastic's logon type is stored as a name (`Network`), so siemx uses the raw number field.

## 11. Other directions: KQL, XQL and Elastic as input

siemx also converts the other way. Put the input files in their own folder:

| Input | Folder | Command | Output |
|---|---|---|---|
| Sentinel KQL | `detections/kql/*.kql` | `siemx convert --from kql` | SPL |
| | | `siemx convert --from kql --to elk` | Elastic |
| Cortex XQL | `detections/xql/*.xql` | `siemx convert --from xql` | SPL |
| | | `siemx convert --from xql --to elk` | Elastic |
| Elastic | `detections/elk/*.elk` | `siemx convert --from elk` | SPL |
| | | `siemx convert --from elk --to kql,xql` | Sentinel, Cortex |

An Elastic query contains no index, so start each `.elk` file with one line telling
siemx which data it is for:

```
# index: logs-system.security-*
event.code: 4625 and not user.name: "SYSTEM"
```

Field names in the reverse direction are kept as they are unless an `exact` mapping
exists; the warning lists them so you can rename.

## 12. Reviewing and measuring accuracy

### Record what you found

After checking a result, record a **verdict**:

```powershell
siemx verdict windows/failed_logins.spl --to kql --result correct --by "Your Name"
siemx verdict windows/elevated_process.spl --to kql --result fixed --by "Your Name" --notes "_time -> TimeGenerated"
siemx verdict windows/failed_login_burst.spl --to kql --result wrong --by "Your Name" --notes "lost the 5-minute window"
```

| `--result` | Meaning |
|---|---|
| `correct` | right as generated, no edit |
| `fixed` | usable after an edit (commit the edited file) |
| `wrong` | not usable |

A verdict remembers which query it judged. If the query changes later, the verdict is
shown as stale and must be repeated.

**The best check:** run the SPL in Splunk and the new query in the other SIEM over the
same time range, and compare the results (row counts, top values).

### The report

```powershell
siemx report                                  # converted/_report/report.md and summary.csv
siemx report --mkdocs <siem-hub>/docs/reports # also a page for the SIEM Hub site
```

The report shows:

- per folder and language: how many are auto-approved / needs-review / unsupported, by rules or by AI
- the most common review reasons
- **the SPL commands no rule could convert, ranked**: the next rules worth building
- **real accuracy from the verdicts**, including how often auto-approved was really correct

### Teach siemx from your fixes

When you fixed a result, make it a verified example. The AI then sees it as a model
answer for similar detections:

```powershell
siemx gold add windows/elevated_process.spl --to kql --by "Your Name"
```

### The pilot

Before converting all detections, run a pilot of 50 (see [PILOT.md](PILOT.md)):

```powershell
siemx pilot-sample path\to\all\detections -n 50 > pilot.txt
```

This picks a fair sample (every data type and complexity). Convert those, review them,
record verdicts, and read the report. It tells you how accurate siemx is **on your
detections** before anyone relies on it.

## 13. AI: optional, and how to choose a model

**siemx works without AI.** Rules, mappings, placeholders, validators, review and report
need none. The AI only tries the pieces no rule can convert, and its answers are always
reviewed.

### Without AI (rules-only mode)

```powershell
siemx convert --no-ai
```

A query the rules cannot convert is marked unsupported with the stages that stopped it.
Those are not retried on every run, only once an AI model is turned on.

### With a free local AI (Ollama, nothing leaves the PC)

1. Install Ollama from ollama.com (it runs in the background, in the system tray).
2. Download a model once: `ollama pull qwen2.5-coder:7b`
3. In PowerShell, before converting:

```powershell
$env:SIEMX_PROVIDER = "ollama"; $env:SIEMX_MODEL = "qwen2.5-coder:7b"
siemx convert --to kql,xql
```

Local models are slow (minutes per long query) and make mistakes. siemx sends them one
at a time and always marks their answers needs-review.

### With a paid AI (later)

| Setting | Local (now) | Paid API (later) |
|---|---|---|
| `SIEMX_PROVIDER` | `ollama` | `anthropic`, or `openai` for Azure OpenAI / OpenAI / a company gateway |
| `SIEMX_MODEL` | `qwen2.5-coder:7b` | for example `claude-sonnet-5-5` |
| `SIEMX_BASE_URL` | (default) | `openai` only: the API address |
| key | none | `ANTHROPIC_API_KEY` or `SIEMX_API_KEY`, never written in a file |

`SIEMX_PROVIDER=none` is the same as `--no-ai`. `$env:...` settings last only for that
PowerShell window. Each result records which model produced it, so two models can be
compared on the same pilot. Get approval before sending detections to a cloud AI.

## 14. Running it on GitHub automatically

The repository has a workflow called **convert-detections**:

1. Someone merges a change to `detections/spl/` or `mappings/` (or starts it by hand:
   **Actions -> convert-detections -> Run workflow**, optionally with a client name and
   folder). It also runs every Sunday.
2. It converts what changed and opens a pull request **"siemx: converted detections"**
   with the new files under `converted/`.
3. A reviewer reads the pull request and merges it. The run's summary page shows the
   status counts.

The AI choice there is set under **Settings -> Secrets and variables -> Actions**:
repository **variables** `SIEMX_PROVIDER` / `SIEMX_MODEL`, and keys as **secrets**. Set
the variable `SIEMX_PROVIDER` to `none` for rules only. GitHub cannot reach Ollama on
your PC.

The workflow converts to KQL, XQL and Elastic (`--to kql,xql,elk` in
`.github/workflows/convert.yml`).

## 15. Checking a single query

```powershell
siemx validate                                                  # which checkers are active
siemx validate --to kql "SecurityEvent | where EventID = = 4625"
siemx validate --to elk 'event.code: 4625 and user.name: "bob"'
```

Example output for the broken KQL above:

```
KQL syntax: Missing expression (line 1 col 32: ` = 4625`)
```

`--to` can be `kql`, `xql`, `elk` or `spl`. It prints `no problems found` when the query
is valid.

## 16. Advanced: documentation index and verified examples

These improve AI answers. You do not need them for rules-only use.

**Official documentation index (RAG).** siemx can download the official SPL, KQL, XQL and
Elastic documentation and give the AI the relevant excerpts. For Elastic that is the Kibana
KQL reference, the Elastic Security rule types (custom query, threshold) and the ECS field
reference (what `event.code`, `source.ip`, ... mean and their types):

```powershell
siemx docs discover          # list the official pages -> rag/sources.json
siemx docs fetch             # download them -> rag/raw/ (a few minutes; not committed)
siemx docs build             # split into searchable pieces -> rag/index/
siemx docs embed             # optional vector search (needs: pip install -e ".[rag]")
siemx docs search "count distinct" --lang kql             # try a search
siemx docs retrieve "index=a | stats dc(user)" --to kql   # what the AI would be given
siemx docs eval              # measure how well the right pages are found (first line:
                             # official bridge only; then with siemx's own rule bridge)
```

**Verified examples (gold).** Checked SPL -> KQL/XQL pairs in `gold/pairs.jsonl`:

```powershell
siemx gold seed                                            # rebuild the examples the rules can verify
siemx gold add <file> --to kql --by "Your Name"            # add a reviewed fix (section 12)
siemx gold show "index=a | stats count by user" --to kql   # which examples a query would get
siemx gold check                                           # do the rules still give the verified answers?
```

## 17. Command reference

Every command accepts `--help`, for example `siemx convert --help`.

| Command | Does | Main options |
|---|---|---|
| `siemx convert` | convert detections | `--to`, `--from`, `--no-ai`, `--path`, `--force`, `--client`, `--workers` |
| `siemx status` | counts per status | `--client` |
| `siemx review` | every result that needs a person, with reasons | `--client` |
| `siemx report` | report.md + summary.csv | `--client`, `--mkdocs <folder>` |
| `siemx verdict <file>` | record a review result | `--to`, `--result correct\|fixed\|wrong`, `--by`, `--notes`, `--client` |
| `siemx pilot-sample <folder>` | pick a fair sample for the pilot | `-n 50`, `--seed 7` |
| `siemx mappings missing` | unmapped data sources | `--write`, `--client` |
| `siemx fields show` | field map for a table | `--table`, `--to kql\|xql`, `--client` |
| `siemx fields import-props <props.conf>` | exact field mappings from a client's Splunk config | `--stanza`, `--client`, `--table`, `--to` |
| `siemx validate [query]` | check one query | `--to kql\|xql\|elk\|spl` |
| `siemx docs discover\|fetch\|build\|embed` | build the documentation index | `fetch --lang`, `--limit`, `--refresh` |
| `siemx docs search\|retrieve\|eval` | explore / measure the documentation index | `--lang`, `-k`, `--to`, `--verbose`, `--ablation`, `--reverse` |
| `siemx gold seed\|add\|show\|check` | verified examples | `add --to --by --notes` |

Settings read from the environment:

| Variable | Meaning |
|---|---|
| `SIEMX_PROVIDER` | `none`, `ollama`, `anthropic` (default), `openai` |
| `SIEMX_MODEL` | the model name |
| `SIEMX_BASE_URL` | API address (`openai`) or Ollama address |
| `ANTHROPIC_API_KEY`, `SIEMX_API_KEY` | keys for paid AI |
| `SIEMX_NUM_CTX` | Ollama context size (default 16384) |
| `SIEMX_TIMEOUT` | seconds per AI request (default 600) |
| `SIEMX_CLIENT` | default for `--client` |

## 18. Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| `siemx` is not recognized | the Python space is not active | `cd siemx` then `.venv\Scripts\activate` |
| "running scripts is disabled on this system" | PowerShell policy | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` (once) |
| Every result says `skipped` | nothing changed since the last run | that is normal; use `--force` to redo all |
| `note: no AI model configured` | AI is not set, and not turned off | add `--no-ai`, or set an AI (section 13) |
| `LLM step failed: timed out` | the local AI was too slow | `$env:SIEMX_TIMEOUT = "1800"`; it is retried next run |
| `LLM step failed: prompt cut at the context limit` | the query is too long for the local AI | `$env:SIEMX_NUM_CTX = "32768"` |
| `validator: basic checks only` | Node.js or the KQL checker is missing | install Node.js, run `npm ci --prefix tools/kql-validate` |
| `EDIT_ME_...` in the output | the data source is not mapped | section 8: `siemx mappings missing --write`, then fill in |
| `input is not valid KQL` (reverse direction) | the input file has a syntax error | fix the input; the message says where |
| An `.elk` file says "names no index pattern" | the `# index:` line is missing | add `# index: <pattern>` as the first line |

## 19. Questions people ask

**Does it need every client's index names?** No. Mapping is by sourcetype/source, which
is the same for every client (section 8). Per-client mappings are only for exceptions.

**Can we use it without AI?** Yes: `siemx convert --no-ai`. Rules convert what they can;
the rest is marked unsupported with the reason, and the report ranks the missing rules
worth building.

**Can it convert all ~1,000 detections now?** Technically yes, in one command. First run
the 50-detection pilot: it measures real accuracy and shows which missing rules matter
most.

**Is our data sent anywhere?** Without AI or with Ollama: no. With a paid AI, only the
detections that need the AI are sent, as text, to that provider; get approval first.

**What if a result is wrong?** Record `siemx verdict ... --result wrong` with a note.
Wrong patterns become new rules, mappings or tests, so the same mistake is caught next time.

**Who can change the rules or mappings?** Changes go through pull requests, and every
pull request runs the test suite (about 1,000 tests). Restricting who may approve
(a `CODEOWNERS` file plus branch protection) is not set up yet for this repository.

**What does it not handle yet?** Splunk commands without rules (for example
`transaction`; the report lists them), most Cortex field names (needs the full xdr_data
field list), importing `savedsearches.conf` / YAML, Elastic's ES|QL and EQL (only
Kibana KQL), and proxy / authentication mappings (they depend on your vendors).

## 20. A 15-minute demo script

Prepare: setup done (section 4), the four example detections from section 5, `converted/`
deleted so the run starts clean.

| Min | Show | Say |
|---|---|---|
| 0-2 | Section 3 picture | "Mappings and rules first, AI only for gaps, a checker on everything, people decide." |
| 2-4 | `detections/spl/` and `mappings/sources.json` | "One file per detection. Mapping is by sourcetype, so it works for every client." |
| 4-6 | `siemx convert --no-ai --to kql,xql,elk` | "Each detection becomes a Sentinel, a Cortex and an Elastic query, with no AI and nothing leaving the PC." |
| 6-8 | `failed_logins.spl` next to its `.kql`, `.xql`, `.elk` | Walk through section 5, step 3. |
| 8-10 | `siemx review` | "It tells us exactly what to check: which user field, which table is still a placeholder." |
| 10-12 | `siemx mappings missing`, fill one `EDIT_ME_`, convert again | "Fix a data source once, and every detection using it updates." |
| 12-14 | `siemx report`, open `report.md` | "This tells us which rules to build next and, after the pilot, how accurate it really is." |
| 14-15 | Next steps | Pilot with 50 real detections (PILOT.md), then decide on AI and the rollout. |
