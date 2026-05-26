# SPEI-FIM Local Operator Guide

This package is designed for local operators who only need to run one installer.

## What the operator does

1. Extract the package to a local folder.
2. Edit `config\deployment.local.json`.
3. Double-click `INSTALL-AS-ADMIN.bat`.
4. Double-click `VERIFY-AS-ADMIN.bat`.

If the batch wrapper is blocked, right-click Windows PowerShell, select `Run as administrator`, and run:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Deploy-SPEIFIM.ps1
```

The installer creates:

- `C:\Program Files\SPEI-FIM`
- `C:\ProgramData\SPEI-FIM\Config`
- `C:\ProgramData\SPEI-FIM\Baseline`
- `C:\ProgramData\SPEI-FIM\Logs`
- `C:\ProgramData\SPEI-FIM\Queue` for HTTP fallback mode
- `C:\ProgramData\SPEI-FIM\EFK` with the Filebeat input example
- Scheduled task: `\SPEI-FIM\SPEI-FIM-Scan`
- Windows Event Log source: `SPEI-FIM`

The scheduled task runs every 12 hours while the workstation is available. It also runs at startup and user logon, with missed-scan recovery enabled, so a workstation that was powered off overnight performs a catch-up scan when it is next used.

The verification script must show `Summary: 0 failure(s)`. If any line shows `FAIL`, the workstation is not considered successfully installed.

On non-English Windows builds, SPEI-FIM uses well-known Windows SIDs instead of localized group names when protecting folders. If an older package left `C:\Program Files\SPEI-FIM` inaccessible, re-running `INSTALL-AS-ADMIN.bat` from the latest package repairs the ACL before reinstalling.

## Minimum fields to change

In `config\deployment.local.json`:

- `assetId`
- `initialChangeTicket`

Use `assetId = "AUTO-COMPUTERNAME"` when the package should automatically use the Windows hostname as the asset ID.

Keep `logRetentionDaysLocal` at `180` or higher for SPEI evidence retention. `logMaxSizeMB` defaults to `1024` as a local disk safety cap for old log files.

Default log shipping mode is `efk.mode = "filebeat"`. In this mode SPEI-FIM writes JSONL logs to:

```text
C:\ProgramData\SPEI-FIM\Logs\fim-*.jsonl
```

Filebeat must be configured separately by the EFK owner to harvest that path.

Important: Filebeat needs access to the Windows endpoint log file. The normal deployment is Filebeat running on the Windows endpoint and shipping to the Linux EFK server. A Filebeat instance running only on Linux cannot read `C:\ProgramData\SPEI-FIM\Logs\fim-*.jsonl` unless a separate approved file-sharing mechanism is provided.

The local log format is JSONL/NDJSON: one JSON object per line. Do not configure syslog parsing for the local file; configure Filebeat `ndjson` parsing.

If the EFK team provides a central rsyslog/syslog collector, set this before deployment:

```json
"mode": "syslog",
"syslogHost": "<EFK_SYSLOG_IP>",
"syslogPort": 5140,
"syslogProtocol": "udp"
```

In syslog mode, SPEI-FIM still writes the local JSONL file and also sends RFC5424 syslog messages with the JSON event body.

For UDP syslog deployment, local operators can copy `config\deployment.syslog-udp.example.json` to `config\deployment.local.json` and replace `EFK_SYSLOG_IP_CHANGE_ME`.

If Filebeat runs under a custom service account, set this before deployment:

```json
"filebeatReadPrincipal": "DOMAIN\\svc-filebeat"
```

If the field is empty, the installer tries to detect the Filebeat service account and grant read-only access to `C:\ProgramData\SPEI-FIM\Logs`.

If a production critical file register already exists, set:

```json
"criticalFilesRegisterPath": "C:\\Path\\To\\critical-files-register.json"
```

Otherwise the installer uses the example register and disables database paths by default.

## Manual checks

Run a one-time scan:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\SPEI-FIM\SPEI-FIM.ps1" -Mode Scan
```

Write a test event for Filebeat pickup:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\SPEI-FIM\SPEI-FIM.ps1" -Mode SendTestAlert
```

Validate configuration:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\SPEI-FIM\SPEI-FIM.ps1" -Mode ValidateConfig
```

## Uninstall

For normal uninstall, double-click:

```text
UNINSTALL-AS-ADMIN.bat
```

Normal uninstall removes:

- Scheduled task `\SPEI-FIM\SPEI-FIM-Scan`
- `C:\Program Files\SPEI-FIM`

Normal uninstall preserves:

- `C:\ProgramData\SPEI-FIM\Logs`
- `C:\ProgramData\SPEI-FIM\Baseline`
- `C:\ProgramData\SPEI-FIM\Config`
- Windows Event Log source `SPEI-FIM`
- Windows audit policy and SACL rules

For full cleanup, run as Administrator:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Uninstall-SPEIFIM.ps1 -PurgeData -RemoveSacl -RemoveEventSource
```

Use `-DisableAuditPolicy` only if the endpoint does not need File System auditing for any other control.

## Production hardening

Before formal production use:

- Sign all PowerShell scripts with the Participant code-signing certificate.
- Change `executionPolicyForTask` from `Bypass` to `AllSigned`.
- Replace the example critical files register with the formally approved and signed register.
- Deploy the Filebeat input from `efk\filebeat-windows-spei-fim.example.yml`.
- Keep monitored paths narrow. Do not enable whole-drive scans or database data/log directories.
- Use `maxDepth`, `maxFilesPerItem`, `maxFileSizeMB`, and `excludePatterns` in the critical files register.
- For the first workstation pilot, keep the default core register. Add database manager paths only after confirming the actual DB product and instance layout.
- Confirm EFK retention is at least 180 days.
- Confirm EFK alerts notify the designated personnel.

## Stability notes

SPEI-FIM is monitoring-only. It does not block file writes or stop processes. The main operational risks are excessive scan scope and excessive Windows audit volume. For production rollout, test scan duration, CPU, disk queue, Security Log growth, and Filebeat backlog on a pilot workstation first.

## HQ package preparation

HQ should prepare `config\deployment.local.json` before sending the package to local operators:

```powershell
copy .\config\deployment.example.json .\config\deployment.local.json
notepad .\config\deployment.local.json
powershell.exe -ExecutionPolicy Bypass -File .\Prepare-SPEIFIM-Package.ps1
```

Send the generated `SPEI-FIM-OneClick.zip` to the local operator.
