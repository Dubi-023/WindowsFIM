# SPEI-FIM OneClick

SPEI-FIM OneClick is a Windows-native file integrity monitoring package for Windows 11 workstations.

It does not use a third-party FIM product. Detection is performed by an internally controlled PowerShell mechanism using Windows-native hashing, Windows auditing, Windows Event Log, and Task Scheduler. SPEI-FIM writes JSONL logs locally; the approved Filebeat component ships those logs to the existing Linux EFK stack.

## One-click local install

Ask the local operator to extract the package and double-click:

```text
INSTALL-AS-ADMIN.bat
```

The batch wrapper requests Administrator privileges and runs the PowerShell installer.

## Manual install command

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Deploy-SPEIFIM.ps1
```

## One-click local uninstall

Ask the local operator to double-click:

```text
UNINSTALL-AS-ADMIN.bat
```

The default uninstall removes the scheduled task and `C:\Program Files\SPEI-FIM`, but preserves `C:\ProgramData\SPEI-FIM` as audit evidence.

For full local cleanup:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Uninstall-SPEIFIM.ps1 -PurgeData -RemoveSacl -RemoveEventSource
```

`-DisableAuditPolicy` is intentionally not part of the default full cleanup because Windows File System auditing may be used by other controls on the endpoint.

## HQ package command

After creating `config\deployment.local.json`, build the package with:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Prepare-SPEIFIM-Package.ps1
```

## Modes after installation

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\SPEI-FIM\SPEI-FIM.ps1" -Mode ValidateConfig
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\SPEI-FIM\SPEI-FIM.ps1" -Mode CreateBaseline -ChangeTicket CHG-0001
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\SPEI-FIM\SPEI-FIM.ps1" -Mode Scan
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\SPEI-FIM\SPEI-FIM.ps1" -Mode SendTestAlert
```

In the default `filebeat` mode, `SendTestAlert` writes a local JSONL test event. Filebeat is responsible for forwarding it to EFK.

## One-click local verification

After installation, run:

```bat
VERIFY-AS-ADMIN.bat
```

The verification helper checks the installed scanner, configuration, baseline file and hash, scheduled task, manual scan, test alert, and JSONL log parsing. Any `FAIL` result means the workstation should not be treated as successfully installed.

## Filebeat input

Use this template on the Windows endpoint or in your managed Filebeat policy:

```text
efk\filebeat-windows-spei-fim.example.yml
```

## Log format and EFK forwarding

SPEI-FIM always writes newline-delimited JSON locally:

```text
C:\ProgramData\SPEI-FIM\Logs\fim-YYYY-MM-DD.jsonl
```

Each line is one event. Filebeat parses it with the `ndjson` parser and forwards structured fields to EFK.

Example event:

```json
{"event_id":9101,"event_type":"fim.file_modified","event_time":"2026-05-22T12:00:00+08:00","hostname":"WIN11-001","asset_id":"SPEI-WKS-001","environment":"production","source":"SPEI-FIM","severity":"high","path":"C:\\Windows\\System32\\drivers\\etc\\hosts","change_type":"hash_changed"}
```

For a central rsyslog/syslog collector, set `efk.mode` to `syslog` in `config\deployment.local.json`. SPEI-FIM will keep local JSONL evidence and forward RFC5424 syslog messages with the JSON event as the message body.

```json
"efk": {
  "enabled": true,
  "mode": "syslog",
  "syslogHost": "<EFK_SYSLOG_IP>",
  "syslogPort": 5140,
  "syslogProtocol": "tcp",
  "syslogFacility": "local0",
  "syslogAppName": "SPEI-FIM",
  "syslogFraming": "newline"
}
```

For the current EFK collector, use TCP syslog on port `5140`. The repo also includes `config\deployment.syslog-tcp.example.json` as a ready template; copy it to `config\deployment.local.json` and replace `EFK_SYSLOG_IP_CHANGE_ME`.

## Default scope

The default critical file register is intentionally narrow for the first Windows workstation pilot:

- `hosts`
- Windows Scheduled Tasks
- Machine-wide Startup folder
- SPEI-FIM program files
- SPEI-FIM config files

Database manager monitoring is not enabled in the core template. Use `config\critical-files-register-db-placeholders.example.json` only as a starting point after confirming the actual database product and instance paths.

## Stability controls

The scanner is non-blocking and read-only. It includes these controls to reduce operational impact:

- One scan instance at a time.
- Bounded directory traversal with `maxDepth` and `maxFilesPerItem`.
- Optional `maxFileSizeMB` to avoid hashing large database/data files.
- `excludePatterns` for high-churn paths.
- Per-file hash/ACL failures are logged as findings instead of stopping the whole scan.
- Windows Security Log correlation is read once per scan, not once per finding.
- Filebeat is granted read-only access to SPEI-FIM logs when its service account is known.
- Local log retention is enforced on each scanner run. The default keeps at least 180 days and applies a 1024 MB safety cap to old local log files.

## Compliance mapping

- Formal FIM procedure: documented separately, this package enforces the technical mechanism.
- Monitoring at least every 24 hours: default scheduled scan is every 12 hours.
- OS and DB manager critical paths: configured in `critical-files-register.json`.
- Alerting: events are written locally and forwarded to EFK.
- Log protection and retention: local logs are ACL protected and retained locally for at least 180 days by default; central retention must also be enforced on EFK for at least 180 days.
- Review evidence: baseline, local JSONL logs, Windows Event Log, and EFK records provide evidence.
