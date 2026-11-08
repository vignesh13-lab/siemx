# Where the mappings come from

Every entry in `sources.json` and `field_map.json` is based on the official documentation
or the vendor's own code listed here (checked 2026-11-08). Shared entries are never `exact`:
`exact` is for a client's own configuration (`siemx fields import-props`).

## Windows Security event log

| Product | Name | Source |
|---|---|---|
| Splunk | `sourcetype=XmlWinEventLog source=XmlWinEventLog:Security` (add-on 11.0.3) | [research.splunk.com data source](https://research.splunk.com/sources/1bbc004e-a75e-4d94-a619-c5aaf5d11ed5) |
| Splunk | classic: `sourcetype=WinEventLog source=WinEventLog:Security`; before add-on 5.0: `sourcetype=WinEventLog:Security` | [add-on 5.0.1 source types](https://docs.splunk.com/Documentation/WindowsAddOn/5.0.1/User/SourcetypesandCIMdatamodelinfo), [Splunk answer on the 5.0 change](https://community.splunk.com/t5/Splunk-Enterprise-Security/Seeing-both-WinEventLogs-and-XmlWinEventlogs/m-p/514195) |
| Sentinel | `SecurityEvent` | [table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent) |
| Cortex | `dataset = xdr_data` (XDR Collector; also `microsoft_windows_raw`) | [Query Windows Event Log records](https://cortex-docs.paloaltonetworks.com/cortex-xdr-3.x/cortex-xdr-3.x-documentation/data-management/xdr-collectors/add-an-xdr-collector-profile-for-windows/query-windows-event-log-records.md) |
| Elastic | `logs-system.security-*` (System integration, data stream `system.security`) | [manifest](https://github.com/elastic/integrations/blob/main/packages/system/data_stream/security/manifest.yml), [sample event](https://github.com/elastic/integrations/blob/main/packages/system/data_stream/security/sample_event.json) |

**Not mapped on purpose:** `sourcetype=WinEventLog` or `XmlWinEventLog` without a `source`.
Those sourcetypes hold every classic/XML channel (Security, System, PowerShell, ...), so the
table depends on the channel. Detections that use them get an `EDIT_ME_wineventlog`
placeholder table: set it once in `sources.json` (`siemx mappings missing --write` adds the
entry), or add `source=...:Security` to the detection.

## Field names

| Splunk (classic) | Sentinel `SecurityEvent` | Cortex `xdr_data` | Elastic `logs-system.security-*` |
|---|---|---|---|
| `EventCode` | `EventID` | `action_evtlog_event_id` | `event.code` |
| `ComputerName` | `Computer` | `agent_hostname` | `winlog.computer_name` |
| `host` | `Computer` (conditional) | `agent_hostname` (conditional) | `host.name` (conditional) |
| `Source_Network_Address`, `src_ip` | `IpAddress` | in `action_evtlog_data_fields` | `source.ip` (type ip) |
| `Logon_Type` | `LogonType` | in `action_evtlog_data_fields` | `winlog.event_data.LogonType` (number; `winlog.logon.type` has the name) |
| `New_Process_Name` | `NewProcessName` | in `action_evtlog_data_fields` | `process.executable` (4688) |
| `Creator_Process_Name` | `ParentProcessName` | in `action_evtlog_data_fields` | `process.parent.executable` (4688) |
| `Process_Command_Line` | `CommandLine` | in `action_evtlog_data_fields` | `process.command_line` (4688) |
| `Token_Elevation_Type` | `TokenElevationType` | in `action_evtlog_data_fields` | `winlog.event_data.TokenElevationType` (raw `%%1937`) |
| `Account_Name`, `user` | ambiguous: Target/SubjectUserName | in `action_evtlog_data_fields` | ambiguous: `user.name`, `user.target.name`, ... |

Sources: SecurityEvent and the per-event pages listed in `field_map.json`; Cortex: the page
above (`action_evtlog_event_id` is the Windows EventID, `event_id` is internal, EventData is
a JSON string in `action_evtlog_data_fields`); Elastic:
[ingest pipeline standard.yml](https://github.com/elastic/integrations/blob/main/packages/system/data_stream/security/elasticsearch/ingest_pipeline/standard.yml)
(scripts "Rename Common Auth Fields", "Process Event 4688", "Set Logon Type",
"Copy Subject User from Event Data", "Copy Target User"); ECS field types:
[ECS reference](https://www.elastic.co/docs/reference/ecs).

## Still open (need your environment)

- **Proxy and authentication sources:** they depend on the vendor (Zscaler, Blue Coat,
  Entra ID, ...). Tell me the vendors and I will add them the same way.
- **Cortex field list for `xdr_data`:** only the event-log fields above are documented
  here, so other XQL field names stay "not verified".
- **Splunk XML field names** (`TargetUserName` style, add-on 6.0+): the add-on's extraction
  list is not published in a form I could verify; detections using classic names
  (`Account_Name`) are covered.
