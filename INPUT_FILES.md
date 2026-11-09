# Writing input files for siemx

How to prepare detections so siemx converts as many as possible **by rules** (exact,
repeatable, no AI). It covers all four input languages, what each rule accepts, and how
to rewrite the forms it does not accept. For installing and running siemx, see
[GUIDE.md](GUIDE.md).

Everything here was checked against the current version (converter 23).

## Contents

1. [Rules for every file](#1-rules-for-every-file)
2. [Splunk (SPL) files](#2-splunk-spl-files)
3. [Sentinel (KQL) files](#3-sentinel-kql-files)
4. [Cortex (XQL) files](#4-cortex-xql-files)
5. [Elastic (Kibana KQL) files](#5-elastic-kibana-kql-files)
6. [Checklist before you convert](#6-checklist-before-you-convert)
7. [Testing one file](#7-testing-one-file)

---

## 1. Rules for every file

| Rule | Example |
|---|---|
| One query per file | `failed_logins.spl` holds one search |
| The extension says the language | `.spl`, `.kql`, `.xql`, `.elk` |
| The folder says the language | `detections/spl/`, `detections/kql/`, `detections/xql/`, `detections/elk/` |
| Sub-folders are free | `detections/spl/windows/`, `detections/spl/clienta/proxy/` |
| The file name becomes the output name | `detections/spl/windows/failed_logins.spl` -> `converted/kql/windows/failed_logins.kql` |
| Plain text, any line breaks | a long search can be split over lines |
| No secrets, no real client data in the public demo | real detections only in the private repository |

File names: letters, digits, `_` and `-` are safest (`failed_logins_rdp.spl`). The same
name in two folders is fine.

## 2. Splunk (SPL) files

**Folder:** `detections/spl/` · **Extension:** `.spl` · **Converts to:** Sentinel, Cortex, Elastic

### 2.1 The shape of a good file

```
source=XmlWinEventLog:Security EventCode=4625 Logon_Type=3
| stats count as failures by Account_Name, ComputerName
| where failures > 10
```

1. **First line: where the data is, then the filter.** `sourcetype=` / `source=` (and,
   optionally, `index=`) followed by `field=value` terms.
2. **Then one command per line**, each starting with `|`.

### 2.2 Where the data is (the most important part)

siemx picks the Sentinel table, Cortex dataset and Elastic index pattern from the
`sourcetype` / `source` / `index` terms, using `mappings/sources.json`.

| Write | Result |
|---|---|
| `source=XmlWinEventLog:Security ...` | mapped: `SecurityEvent`, `xdr_data`, `logs-system.security-*` |
| `index=clienta_win source=XmlWinEventLog:Security ...` | mapped; the client index is dropped with a note (fine for MSSP) |
| `sourcetype=wineventlog ...` (no source) | `EDIT_ME_wineventlog` placeholder: that sourcetype holds every Windows log |
| `index=proxy ...` (index only) | `EDIT_ME_proxy` placeholder |
| no index / sourcetype / source at all | no rule: the base search is unsupported |

Tips:

- **Name the channel.** `source=XmlWinEventLog:Security` beats `sourcetype=wineventlog`.
- **Metadata terms belong at the top level.** `(index=a OR index=b)` and `NOT index=x`
  are not converted.
- **A wildcard is allowed only in `index`** (`index=win*`), not in sourcetype or source.
- **Unknown sources are fine:** fill in the placeholder once with
  `siemx mappings missing --write` (GUIDE.md section 8).

### 2.3 The filter on the first line

| Form | Example | Converted? |
|---|---|---|
| field = value | `EventCode=4625` | yes |
| quoted value (spaces, special characters) | `Account_Name="john doe"` | yes |
| wildcard | `CommandLine="*-enc*"`, `Process=*\\cmd.exe` | yes |
| not equal | `Account_Name!=SYSTEM` | yes |
| field exists | `CommandLine=*` | yes |
| number comparison | `EventCode>4600` | yes |
| list | `EventCode IN (4624, 4625)` | yes |
| AND / OR / NOT, parentheses | `(EventCode=4624 OR EventCode=4625) NOT Account_Name=SYSTEM` | yes |
| explicit `search` at the start | `search source=... EventCode=4625` | yes (same as without it) |
| comments | ``source=... EventCode=4625 ```failed logons``` `` | yes (comments are ignored) |
| **lowercase** and / or / not | `EventCode=4625 and Logon_Type=3` | **no**: in Splunk lowercase `and` is a search word, not an operator. Write `AND`, or just a space |
| free text (no field) | `mimikatz`, `"failed password"` | no: write `CommandLine="*mimikatz*"` instead |
| time range in the search | `earliest=-24h`, `latest=now` | no: leave it out; the time range belongs to the SIEM rule's schedule |
| text comparison | `user>abc` | no |
| `CASE()`, `TERM()` | `CASE(Admin)` | no |
| `field!=*` | `user!=*` | no (it never matches in Splunk) |

Backslashes in values: write them as Splunk expects (`"*\\cmd.exe"` = one backslash).
siemx adds a note to check the value.

### 2.4 Commands after the first line

| Command | Accepted forms | Not converted (rewrite or expect review / AI) |
|---|---|---|
| `search` | `\| search field=value ...` (same terms as 2.3) | metadata terms (`index=`) in a later search |
| `where` | `=`, `==`, `!=`, `<`, `<=`, `>`, `>=`, `AND`/`OR`/`NOT`, `( )`, functions below | `like()`, `match()`, `cidrmatch()`, `isnull()`, lowercase and/or |
| `eval` | `a = <value>, b = <value>`; `+ - * /`, `.` (join text), `lower`, `upper`, `len`, `coalesce`, `if` | other functions: `strftime`, `replace`, `mvcount`, `split`, `case`, `tonumber`, ... |
| `stats` | `count`, `count(f)`, `dc(f)`, `distinct_count(f)`, `sum`, `avg`, `min`, `max`, `as name`, `by f1, f2` | `values`, `list`, `earliest`, `latest`, `first`, `last`, `estdc`, `perc*` |
| `table` / `fields` | `table a, b, c`; `fields a, b`; `fields - a, b` | wildcards (`table user*`) |
| `rename` | `rename a AS b, c AS d` | wildcards; a quoted new name with spaces (`AS "d e"`) works for Sentinel only |
| `sort` | `sort - count`, `sort 20 -a, +b` | `sort` with functions (`num()`, `str()`) |
| `head` | `head 10` | `head` with a condition |
| `dedup` | `dedup a, b` | options (`keepempty`, `consecutive`, `sortby`) |
| `top` | `top 5 user`, `top limit=5 user countfield=n showperc=f` | `by`, several fields, `useother` |
| `rex` | `rex field=cmd "user=(?<user>\w+)"`, also with `max_match=1` | no `field=` (`_raw`), `mode=sed`, other `max_match` values, PCRE-only syntax |
| `timechart` | `timechart span=1h count` (span in s/m/h, or exactly 1d) | no span, `by`, other functions |
| `lookup` | `lookup assets ip AS src OUTPUT owner AS asset_owner` | `OUTPUTNEW`, no OUTPUT list |
| `join` | `join type=left host [search ... \| stats count by host]` | no field list, `usetime`, `overwrite`, `left=`/`right=` forms |
| anything else | `transaction`, `streamstats`, `eventstats`, `tstats`, `bin`, `append`, `inputlookup`, `mvexpand`, `fillnull`, ... | no rule yet: unsupported (rules only) or AI |

How to read a "not converted" line in `siemx review`:
*"the rules cannot convert `eval`"* means that `eval` has a rule, but not for what you
wrote (here, a function it does not know). The report ranks these, so the most needed
rules are built first.

### 2.5 Macros

| Write | Result |
|---|---|
`` `win_security` EventCode=4625 `` with `"win_security": "source=XmlWinEventLog:Security"` in `mappings/macros.json` | expanded, then converted |
| a macro that is not defined | not converted (the macro name stays) |
| a macro with arguments, `` `my_macro(4625)` `` | not expanded: paste its definition into the file |

Client-specific macros go in `mappings/clients/<client>/macros.json`.

### 2.6 Before / after examples

| Instead of | Write |
|---|---|
| `index=* sourcetype=wineventlog EventCode=4688` | `source=XmlWinEventLog:Security EventCode=4688` |
| `source=... EventCode=4625 earliest=-24h` | `source=... EventCode=4625` (time range in the rule's schedule) |
| `source=... mimikatz` | `source=... CommandLine="*mimikatz*"` |
| `source=... EventCode=4625 and Logon_Type=3` | `source=... EventCode=4625 Logon_Type=3` |
| `\| stats values(host) as hosts by user` | `\| stats dc(host) as hosts by user` only if a count is what you need; otherwise keep it and review |

Never change what a detection detects just to get a conversion. If the logic needs
`transaction`, keep it: an honest "unsupported" is better than a different detection.

## 3. Sentinel (KQL) files

**Folder:** `detections/kql/` · **Extension:** `.kql` · **Converts to:** Splunk (`--from kql`), Elastic (`--from kql --to elk`)

```
// Failed network logons per account
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4625 and LogonType == 3
| summarize failures = count() by TargetUserName
| where failures > 10
```

| Rule | Detail |
|---|---|
| Start with the table name | `SecurityEvent` (or `SecurityEvent \| ...` on one line) |
| The table must be mapped | the table must appear as a `"kql"` value in `mappings/sources.json`; otherwise "no SPL source maps to ..." |
| Valid KQL only | checked with Microsoft's parser; an invalid file is reported, not converted |
| `//` comments | allowed, ignored |
| Time filter | `TimeGenerated > ago(1d)` becomes Splunk `earliest=-1d`; for Elastic, a note to set the rule's look-back |

Converted by rules: `where`, `project`, `project-away`, `project-rename`, `extend`,
`summarize` (`count`, `dcount`, `count_distinct`, `sum`, `avg`, `min`, `max`), `take` /
`limit`, `sort by` / `order by`, `top N by`, `distinct`, `count`. Conditions with `==`,
`!=`, `=~`, `!~`, `<` `>` ..., `contains`, `startswith`, `endswith` (and their `!`
forms), `in`, `!in`, `in~`, `and`, `or`, `not()`, `isempty()`, `isnotempty()`,
`isnull()`, `isnotnull()`, `tolower`, `toupper`, `strlen`, `strcat`, `iff`, `coalesce`.

Not converted: `let` statements, `union`, `search`, `has` / `has_cs`, `matches regex`,
`between`, `mv-expand`, `parse`, `join` (KQL side), datetime arithmetic other than the
leading `ago()` filter.

## 4. Cortex (XQL) files

**Folder:** `detections/xql/` · **Extension:** `.xql` · **Converts to:** Splunk (`--from xql`), Elastic (`--from xql --to elk`)

```
// Failed logons per host
config case_sensitive = true
| dataset = xdr_data
| filter action_evtlog_event_id = 4625
| comp count() as failures by agent_hostname
| filter failures > 10
```

| Rule | Detail |
|---|---|
| `config` first (optional) | `config timeframe = 24H` (becomes `earliest=-24h`), `config case_sensitive = true` |
| Then `dataset = <name>` (optional) | missing = `xdr_data`, as in Cortex. The dataset must be mapped in `sources.json` |
| `//` comments | allowed, ignored |
| `and` / `or` mixed | put parentheses: `(a = 1 and b = 2) or c = 3`. XQL does not document their precedence, so siemx refuses to guess |
| `not` | always with parentheses: `not (a = 1)` |

Converted by rules: `filter`, `alter`, `fields` (and `fields -`), `comp` (`count`,
`count_distinct`, `sum`, `avg`, `min`, `max`, with `as` and `by`), `sort`, `limit`,
`dedup`. Conditions with `=`, `!=`, `<` `>` ..., `= null`, `!= null`, `in`, `not in`,
`contains`, wildcards in `"..."` strings, `lowercase`, `uppercase`, `len`, `coalesce`,
`if`, `concat`, `add` / `subtract` / `multiply` / `divide`, `to_string`, `to_number`.

Not converted: `preset`, `datamodel`, `cold_dataset`, triple-quoted strings, `~=`
(regex), `incidr`, arrays and JSON functions, `true` / `false`, `join`, `union`, `bin`.

## 5. Elastic (Kibana KQL) files

**Folder:** `detections/elk/` · **Extension:** `.elk` · **Converts to:** Splunk (`--from elk`), Sentinel and Cortex (`--from elk --to kql,xql`)

```
# index: logs-system.security-*
event.code: 4625 and not user.name: "SYSTEM"
```

| Rule | Detail |
|---|---|
| First line `# index: <pattern>` | the index pattern the Elastic rule searches. **Required** for Sentinel / Cortex (it picks the table); recommended for Splunk |
| The pattern must be mapped | an entry in `sources.json` whose `"elk"` value is that pattern |
| Then one filter | exactly as typed in Kibana's search bar; may span several lines |
| `and` / `or` / `not` | any case. Always add parentheses when mixing `and` with `or`: Kibana and Elastic's other entry points group them differently |
| No pipes | Kibana KQL has no pipes; `\|` in an unquoted value is reported |

Converted by rules: `field: value`, `field: "quoted value"`, wildcards (`field: *cmd*`),
`field: *` (exists), value lists `field: (a or b)`, ranges `field > 10` with numbers,
`and`, `or`, `not`, parentheses, escaped characters (`\(`, `\:`, `\*`).

Not converted: free text without a field (`mimikatz`), nested queries `field: { ... }`,
date ranges (`@timestamp > "2026-01-01"`), `null`, wildcards in field names
(`process.*: x`), an escaped literal `*` (Splunk has no literal star).

Escaping (Kibana's own rules): outside quotes, put `\` before `\ ( ) : < > " * { }`;
inside quotes, only before `"` and `\`. A Windows path: `process.executable: *\\cmd.exe`.

## 6. Checklist before you convert

- [ ] One query per file, the right folder and extension
- [ ] SPL: the first line names the data (`source=...:Security`, not only `index=*`)
- [ ] SPL: `AND` / `OR` / `NOT` in capitals; no `earliest=` / `latest=` in the search
- [ ] SPL: macros defined in `mappings/macros.json`, or pasted in
- [ ] KQL: starts with a mapped table; no `let` or `union`
- [ ] XQL: `config` first, then `dataset`; parentheses around mixed `and` / `or`
- [ ] Elastic: first line `# index: <pattern>`, and that pattern mapped
- [ ] `siemx mappings missing` shows no surprises (or the placeholders are filled in)

## 7. Testing one file

Put the file in its own folder and convert only that folder:

```powershell
siemx convert --no-ai --to kql,xql,elk --path test
siemx review
```

For a single query, check its syntax directly:

```powershell
siemx validate --to kql "SecurityEvent | where EventID == 4625"
siemx validate --to elk 'event.code: 4625 and user.name: "bob"'
```

A file that should convert but does not: `siemx review` gives the exact reason, and
`converted/_meta/<folder>/<name>.<lang>.json` has the details.
