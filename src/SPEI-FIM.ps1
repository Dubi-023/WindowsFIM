<# 
SPEI-FIM main entry point.

Supported modes:
  ValidateConfig
  CreateBaseline
  Scan
  SendTestAlert
  ExportEvidence
#>

[CmdletBinding()]
param(
    [ValidateSet("ValidateConfig", "CreateBaseline", "Scan", "SendTestAlert", "ExportEvidence")]
    [string]$Mode = "Scan",

    [string]$ProgramDataRoot = "C:\ProgramData\SPEI-FIM",
    [string]$ChangeTicket = "UNSPECIFIED",
    [datetime]$From = (Get-Date).AddDays(-30),
    [datetime]$To = (Get-Date)
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

$ConfigRoot = Join-Path $ProgramDataRoot "Config"
$BaselineRoot = Join-Path $ProgramDataRoot "Baseline"
$LogsRoot = Join-Path $ProgramDataRoot "Logs"
$QueueRoot = Join-Path $ProgramDataRoot "Queue"
$EvidenceRoot = Join-Path $ProgramDataRoot "Evidence"
$RunRoot = Join-Path $ProgramDataRoot "Run"
$SettingsPath = Join-Path $ConfigRoot "fim-settings.json"
$RegisterPath = Join-Path $ConfigRoot "critical-files-register.json"
$BaselinePath = Join-Path $BaselineRoot "baseline-current.json"
$BaselineHashPath = Join-Path $BaselineRoot "baseline-current.sha256"
$script:FimMutex = $null
$script:LastHashError = $null
$script:LastWalkLimitHit = $false
$script:LogRetentionChecked = $false

function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Read-JsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "JSON file not found: $Path"
    }
    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
}

function ConvertTo-JsonText {
    param([Parameter(Mandatory = $true)]$Object)
    return ($Object | ConvertTo-Json -Depth 16 -Compress)
}

function Get-StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Text)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally {
        $sha.Dispose()
    }
}

function Get-FileSha256OrNull {
    param(
        [string]$Path,
        [bool]$Enabled,
        [int64]$FileSize = 0,
        [int]$MaxFileSizeMB = 0
    )
    $script:LastHashError = $null
    if (-not $Enabled) { return $null }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    if ($MaxFileSizeMB -gt 0 -and $FileSize -gt ([int64]$MaxFileSizeMB * 1MB)) {
        $script:LastHashError = "hash_skipped_max_file_size_exceeded"
        return $null
    }
    try {
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    } catch {
        $script:LastHashError = $_.Exception.Message
        return $null
    }
}

function Get-AclState {
    param([string]$Path)
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $sddl = $acl.Sddl
        return [ordered]@{
            owner = [string]$acl.Owner
            aclSddl = [string]$sddl
            aclHash = (Get-StringSha256 -Text $sddl)
            aclError = $null
        }
    } catch {
        return [ordered]@{
            owner = $null
            aclSddl = $null
            aclHash = $null
            aclError = $_.Exception.Message
        }
    }
}

function New-FimErrorDetail {
    param([object]$ErrorRecord)

    $parts = New-Object "System.Collections.Generic.List[string]"
    if ($ErrorRecord -and $ErrorRecord.Exception) {
        $parts.Add(($ErrorRecord.Exception.GetType().FullName + ": " + $ErrorRecord.Exception.Message))
    }
    if ($ErrorRecord -and $ErrorRecord.InvocationInfo -and $ErrorRecord.InvocationInfo.PositionMessage) {
        $parts.Add([string]$ErrorRecord.InvocationInfo.PositionMessage)
    }
    if ($ErrorRecord -and $ErrorRecord.ScriptStackTrace) {
        $parts.Add([string]$ErrorRecord.ScriptStackTrace)
    }
    return ($parts -join [Environment]::NewLine)
}

function Write-FimDiagnosticError {
    param([string]$Context, [object]$ErrorRecord)

    try {
        Ensure-Directory $LogsRoot
        $path = Join-Path $LogsRoot ("fim-error-" + (Get-Date -Format "yyyy-MM-dd") + ".log")
        $message = @(
            "[$((Get-Date).ToString('o'))] $Context"
            (New-FimErrorDetail -ErrorRecord $ErrorRecord)
            ""
        ) -join [Environment]::NewLine
        Add-Content -LiteralPath $path -Value $message -Encoding UTF8
    } catch {
        return
    }
}

function Expand-FimPath {
    param([string]$Path)
    return [Environment]::ExpandEnvironmentVariables($Path)
}

function Test-FimExcludedPath {
    param([string]$Path, [array]$ExcludePatterns)
    if (-not $ExcludePatterns) { return $false }
    foreach ($pattern in $ExcludePatterns) {
        if ([string]::IsNullOrWhiteSpace([string]$pattern)) { continue }
        if ($Path -like [string]$pattern) { return $true }
    }
    return $false
}

function Get-ChildFileSafe {
    param(
        [string]$Path,
        [bool]$Recursive,
        [int]$MaxDepth,
        [int]$MaxFiles,
        [array]$ExcludePatterns
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return @()
    }

    $script:LastWalkLimitHit = $false
    $results = New-Object "System.Collections.Generic.List[object]"
    $queue = New-Object System.Collections.Queue
    $queue.Enqueue([pscustomobject]@{ Path = $Path; Depth = 0 })

    while ($queue.Count -gt 0) {
        $node = $queue.Dequeue()
        if (Test-FimExcludedPath -Path ([string]$node.Path) -ExcludePatterns $ExcludePatterns) { continue }

        foreach ($file in (Get-ChildItem -LiteralPath ([string]$node.Path) -File -Force -ErrorAction SilentlyContinue)) {
            if (Test-FimExcludedPath -Path $file.FullName -ExcludePatterns $ExcludePatterns) { continue }
            $results.Add($file)
            if ($MaxFiles -gt 0 -and $results.Count -ge $MaxFiles) {
                $script:LastWalkLimitHit = $true
                return $results.ToArray()
            }
        }

        if (-not $Recursive) { continue }
        if ($MaxDepth -gt 0 -and [int]$node.Depth -ge $MaxDepth) { continue }

        foreach ($dir in (Get-ChildItem -LiteralPath ([string]$node.Path) -Directory -Force -ErrorAction SilentlyContinue)) {
            if (Test-FimExcludedPath -Path $dir.FullName -ExcludePatterns $ExcludePatterns) { continue }
            $queue.Enqueue([pscustomobject]@{ Path = $dir.FullName; Depth = ([int]$node.Depth + 1) })
        }
    }

    return $results.ToArray()
}

function Get-FimInventory {
    param([object]$Register)

    $entries = New-Object "System.Collections.Generic.List[object]"

    foreach ($item in $Register.items) {
        if ($item.enabled -eq $false) { continue }

        $expanded = Expand-FimPath -Path ([string]$item.path)
        $itemType = [string]$item.type
        $hashEnabled = [bool]$item.hash
        $aclEnabled = [bool]$item.acl
        $recursive = [bool]$item.recursive
        $maxDepth = 0
        if ($item.PSObject.Properties.Name -contains "maxDepth") {
            $maxDepth = [int]$item.maxDepth
        }
        $maxFiles = 10000
        if ($item.PSObject.Properties.Name -contains "maxFilesPerItem") {
            $maxFiles = [int]$item.maxFilesPerItem
        }
        $maxFileSizeMB = 0
        if ($item.PSObject.Properties.Name -contains "maxFileSizeMB") {
            $maxFileSizeMB = [int]$item.maxFileSizeMB
        }
        $excludePatterns = @()
        if ($item.PSObject.Properties.Name -contains "excludePatterns") {
            $excludePatterns = @($item.excludePatterns)
        }

        if ($itemType -eq "file") {
            if (-not (Test-Path -LiteralPath $expanded -PathType Leaf)) {
                $entries.Add([ordered]@{
                    id = [string]$item.id
                    configuredPath = [string]$item.path
                    path = $expanded
                    type = "file"
                    exists = $false
                    severity = [string]$item.severity
                    category = [string]$item.category
                    sha256 = $null
                    size = $null
                    creationTimeUtc = $null
                    lastWriteTimeUtc = $null
                    owner = $null
                    aclHash = $null
                    hashError = $null
                    aclError = $null
                })
                continue
            }

            $file = Get-Item -LiteralPath $expanded -Force
            $aclState = $null
            if ($aclEnabled) { $aclState = Get-AclState -Path $file.FullName }
            $hash = Get-FileSha256OrNull -Path $file.FullName -Enabled $hashEnabled -FileSize ([int64]$file.Length) -MaxFileSizeMB $maxFileSizeMB
            $owner = $null
            $aclHash = $null
            $aclError = $null
            if ($null -ne $aclState) {
                $owner = $aclState.owner
                $aclHash = $aclState.aclHash
                $aclError = $aclState.aclError
            }
            $entries.Add([ordered]@{
                id = [string]$item.id
                configuredPath = [string]$item.path
                path = [string]$file.FullName
                type = "file"
                exists = $true
                severity = [string]$item.severity
                category = [string]$item.category
                sha256 = $hash
                size = [int64]$file.Length
                creationTimeUtc = $file.CreationTimeUtc.ToString("o")
                lastWriteTimeUtc = $file.LastWriteTimeUtc.ToString("o")
                owner = $owner
                aclHash = $aclHash
                hashError = $script:LastHashError
                aclError = $aclError
            })
            continue
        }

        if ($itemType -eq "directory") {
            if (-not (Test-Path -LiteralPath $expanded -PathType Container)) {
                $entries.Add([ordered]@{
                    id = [string]$item.id
                    configuredPath = [string]$item.path
                    path = $expanded
                    type = "directory"
                    exists = $false
                    severity = [string]$item.severity
                    category = [string]$item.category
                    sha256 = $null
                    size = $null
                    creationTimeUtc = $null
                    lastWriteTimeUtc = $null
                    owner = $null
                    aclHash = $null
                    hashError = $null
                    aclError = $null
                })
                continue
            }

            $dirAcl = $null
            if ($aclEnabled) { $dirAcl = Get-AclState -Path $expanded }
            $dir = Get-Item -LiteralPath $expanded -Force
            $dirOwner = $null
            $dirAclHash = $null
            $dirAclError = $null
            if ($null -ne $dirAcl) {
                $dirOwner = $dirAcl.owner
                $dirAclHash = $dirAcl.aclHash
                $dirAclError = $dirAcl.aclError
            }
            $dirEntry = [ordered]@{
                id = [string]$item.id
                configuredPath = [string]$item.path
                path = [string]$dir.FullName
                type = "directory"
                exists = $true
                severity = [string]$item.severity
                category = [string]$item.category
                sha256 = $null
                size = $null
                creationTimeUtc = $dir.CreationTimeUtc.ToString("o")
                lastWriteTimeUtc = $dir.LastWriteTimeUtc.ToString("o")
                owner = $dirOwner
                aclHash = $dirAclHash
                hashError = $null
                aclError = $dirAclError
                scanLimitHit = $false
            }
            $entries.Add($dirEntry)

            $childFiles = Get-ChildFileSafe -Path $expanded -Recursive $recursive -MaxDepth $maxDepth -MaxFiles $maxFiles -ExcludePatterns $excludePatterns
            $dirEntry["scanLimitHit"] = $script:LastWalkLimitHit

            foreach ($file in $childFiles) {
                $aclState = $null
                if ($aclEnabled) { $aclState = Get-AclState -Path $file.FullName }
                $hash = Get-FileSha256OrNull -Path $file.FullName -Enabled $hashEnabled -FileSize ([int64]$file.Length) -MaxFileSizeMB $maxFileSizeMB
                $owner = $null
                $aclHash = $null
                $aclError = $null
                if ($null -ne $aclState) {
                    $owner = $aclState.owner
                    $aclHash = $aclState.aclHash
                    $aclError = $aclState.aclError
                }
                $entries.Add([ordered]@{
                    id = [string]$item.id
                    configuredPath = [string]$item.path
                    path = [string]$file.FullName
                    type = "file"
                    exists = $true
                    severity = [string]$item.severity
                    category = [string]$item.category
                    sha256 = $hash
                    size = [int64]$file.Length
                    creationTimeUtc = $file.CreationTimeUtc.ToString("o")
                    lastWriteTimeUtc = $file.LastWriteTimeUtc.ToString("o")
                    owner = $owner
                    aclHash = $aclHash
                    hashError = $script:LastHashError
                    aclError = $aclError
                })
            }
        }
    }

    return $entries.ToArray()
}

function New-FimEvent {
    param(
        [object]$Settings,
        [int]$EventId,
        [string]$EventType,
        [string]$Severity,
        [hashtable]$Data
    )

    $payload = [ordered]@{
        event_id = $EventId
        event_type = $EventType
        event_time = (Get-Date).ToString("o")
        hostname = $env:COMPUTERNAME
        asset_id = [string]$Settings.assetId
        environment = [string]$Settings.environment
        source = "SPEI-FIM"
        severity = $Severity
    }

    foreach ($key in $Data.Keys) {
        $payload[$key] = $Data[$key]
    }

    return $payload
}

function Write-FimLocalLog {
    param([object]$Event)
    Ensure-Directory $LogsRoot
    $logFile = Join-Path $LogsRoot ("fim-" + (Get-Date -Format "yyyy-MM-dd") + ".jsonl")
    Add-Content -LiteralPath $logFile -Value (ConvertTo-JsonText -Object $Event) -Encoding UTF8
}

function Invoke-FimLocalLogRetention {
    param([object]$Settings)

    if ($script:LogRetentionChecked) { return }
    $script:LogRetentionChecked = $true

    try {
        Ensure-Directory $LogsRoot
        $retentionDays = 180
        if ($Settings -and ($Settings.PSObject.Properties.Name -contains "logRetentionDaysLocal")) {
            $retentionDays = [int]$Settings.logRetentionDaysLocal
        }
        if ($retentionDays -lt 180) {
            $retentionDays = 180
        }

        $maxSizeMB = 1024
        if ($Settings -and ($Settings.PSObject.Properties.Name -contains "logMaxSizeMB")) {
            $maxSizeMB = [int]$Settings.logMaxSizeMB
        }

        $cutoff = (Get-Date).AddDays(-1 * $retentionDays)
        $files = @(Get-ChildItem -LiteralPath $LogsRoot -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "fim-*.jsonl" -or $_.Name -like "fim-error-*.log" })

        foreach ($file in $files) {
            if ($file.LastWriteTime -lt $cutoff) {
                Remove-Item -LiteralPath $file.FullName -Force -ErrorAction SilentlyContinue
            }
        }

        if ($maxSizeMB -le 0) { return }

        $maxBytes = [int64]$maxSizeMB * 1MB
        $todayJson = "fim-" + (Get-Date -Format "yyyy-MM-dd") + ".jsonl"
        $remaining = @(Get-ChildItem -LiteralPath $LogsRoot -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "fim-*.jsonl" -or $_.Name -like "fim-error-*.log" } |
            Sort-Object LastWriteTimeUtc)
        $totalBytes = [int64]0
        foreach ($file in $remaining) {
            $totalBytes += [int64]$file.Length
        }

        foreach ($file in $remaining) {
            if ($totalBytes -le $maxBytes) { break }
            if ($file.Name -eq $todayJson) { continue }
            $size = [int64]$file.Length
            Remove-Item -LiteralPath $file.FullName -Force -ErrorAction SilentlyContinue
            $totalBytes -= $size
        }
    } catch {
        return
    }
}

function Write-FimWindowsEvent {
    param([object]$Settings, [object]$Event)
    $source = [string]$Settings.eventSource
    $logName = [string]$Settings.eventLogName
    $message = ConvertTo-JsonText -Object $Event
    try {
        Write-EventLog -LogName $logName -Source $source -EventId ([int]$Event.event_id) -EntryType Information -Message $message
    } catch {
        Write-FimLocalLog -Event (New-FimEvent -Settings $Settings -EventId 9401 -EventType "fim.eventlog_write_failed" -Severity "medium" -Data @{
            error = $_.Exception.Message
            original_event_id = $Event.event_id
        })
    }
}

function Get-ProtectedToken {
    param([string]$TokenFile)
    if ([string]::IsNullOrWhiteSpace($TokenFile)) { return $null }
    if (-not (Test-Path -LiteralPath $TokenFile)) { return $null }
    $encrypted = Get-Content -LiteralPath $TokenFile -Raw
    if ([string]::IsNullOrWhiteSpace($encrypted)) { return $null }
    $secure = $encrypted | ConvertTo-SecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
}

function Get-SyslogFacilityCode {
    param([string]$Facility)
    switch ([string]$Facility) {
        "kern" { return 0 }
        "user" { return 1 }
        "mail" { return 2 }
        "daemon" { return 3 }
        "auth" { return 4 }
        "syslog" { return 5 }
        "lpr" { return 6 }
        "news" { return 7 }
        "uucp" { return 8 }
        "cron" { return 9 }
        "authpriv" { return 10 }
        "ftp" { return 11 }
        "local0" { return 16 }
        "local1" { return 17 }
        "local2" { return 18 }
        "local3" { return 19 }
        "local4" { return 20 }
        "local5" { return 21 }
        "local6" { return 22 }
        "local7" { return 23 }
        default { return 16 }
    }
}

function Get-SyslogSeverityCode {
    param([string]$Severity)
    switch ([string]$Severity) {
        "critical" { return 2 }
        "high" { return 3 }
        "medium" { return 4 }
        "low" { return 6 }
        default { return 5 }
    }
}

function ConvertTo-SyslogToken {
    param([string]$Value, [int]$MaxLength = 32)
    if ([string]::IsNullOrWhiteSpace($Value)) { return "-" }
    $token = ([string]$Value) -replace "[^A-Za-z0-9_.-]", "_"
    if ($token.Length -gt $MaxLength) {
        return $token.Substring(0, $MaxLength)
    }
    return $token
}

function ConvertTo-FimSyslogMessage {
    param([object]$Settings, [object]$Event)

    $facility = "local0"
    if ($Settings.efk.PSObject.Properties.Name -contains "syslogFacility") {
        $facility = [string]$Settings.efk.syslogFacility
    }
    $appName = "SPEI-FIM"
    if ($Settings.efk.PSObject.Properties.Name -contains "syslogAppName") {
        $appName = [string]$Settings.efk.syslogAppName
    }

    $priority = ((Get-SyslogFacilityCode -Facility $facility) * 8) + (Get-SyslogSeverityCode -Severity ([string]$Event.severity))
    $timestamp = [string]$Event.event_time
    if ([string]::IsNullOrWhiteSpace($timestamp)) {
        $timestamp = (Get-Date).ToString("o")
    }
    $hostname = ConvertTo-SyslogToken -Value $env:COMPUTERNAME -MaxLength 255
    $app = ConvertTo-SyslogToken -Value $appName -MaxLength 48
    $messageId = ConvertTo-SyslogToken -Value ([string]$Event.event_type) -MaxLength 32
    $json = ConvertTo-JsonText -Object $Event

    return ("<{0}>1 {1} {2} {3} - {4} - {5}" -f $priority, $timestamp, $hostname, $app, $messageId, $json)
}

function Send-FimSyslogUdp {
    param([string]$TargetHost, [int]$Port, [string]$Message)

    $udp = New-Object System.Net.Sockets.UdpClient
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Message)
        [void]$udp.Send($bytes, $bytes.Length, $TargetHost, $Port)
        return $true
    } finally {
        $udp.Close()
    }
}

function Send-FimSyslogTcp {
    param(
        [string]$TargetHost,
        [int]$Port,
        [string]$Message,
        [int]$TimeoutSeconds,
        [string]$Framing
    )

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($TargetHost, $Port, $null, $null)
        $timeoutMs = [Math]::Max(1, $TimeoutSeconds) * 1000
        if (-not $async.AsyncWaitHandle.WaitOne($timeoutMs, $false)) {
            $client.Close()
            throw "Syslog TCP connect timeout to ${TargetHost}:$Port"
        }
        $client.EndConnect($async)
        $stream = $client.GetStream()
        $payload = $Message + "`n"
        if ($Framing -eq "octet-counted") {
            $messageBytes = [Text.Encoding]::UTF8.GetBytes($Message)
            $payload = ([string]$messageBytes.Length) + " " + $Message
        }
        $bytes = [Text.Encoding]::UTF8.GetBytes($payload)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
        return $true
    } finally {
        $client.Close()
    }
}

function Send-FimEventToSyslog {
    param([object]$Settings, [object]$Event)

    $hostName = ""
    if ($Settings.efk.PSObject.Properties.Name -contains "syslogHost") {
        $hostName = [string]$Settings.efk.syslogHost
    }
    if ([string]::IsNullOrWhiteSpace($hostName)) {
        return $false
    }

    $port = 5140
    if ($Settings.efk.PSObject.Properties.Name -contains "syslogPort") {
        $port = [int]$Settings.efk.syslogPort
    }
    $protocol = "tcp"
    if ($Settings.efk.PSObject.Properties.Name -contains "syslogProtocol") {
        $protocol = ([string]$Settings.efk.syslogProtocol).ToLowerInvariant()
    }
    $framing = "newline"
    if ($Settings.efk.PSObject.Properties.Name -contains "syslogFraming") {
        $framing = ([string]$Settings.efk.syslogFraming).ToLowerInvariant()
    }
    $timeoutSeconds = 15
    if ($Settings.efk.PSObject.Properties.Name -contains "timeoutSeconds") {
        $timeoutSeconds = [int]$Settings.efk.timeoutSeconds
    }

    $message = ConvertTo-FimSyslogMessage -Settings $Settings -Event $Event
    try {
        if ($protocol -eq "tcp") {
            return (Send-FimSyslogTcp -TargetHost $hostName -Port $port -Message $message -TimeoutSeconds $timeoutSeconds -Framing $framing)
        }
        return (Send-FimSyslogUdp -TargetHost $hostName -Port $port -Message $message)
    } catch {
        return $false
    }
}

function Send-FimEventToEfk {
    param(
        [object]$Settings,
        [object]$Event,
        [bool]$QueueOnFailure = $true
    )

    if (-not [bool]$Settings.efk.enabled) { return $true }
    $mode = "filebeat"
    if ($Settings.efk.PSObject.Properties.Name -contains "mode") {
        $mode = [string]$Settings.efk.mode
    }
    if ($mode -eq "filebeat") { return $true }
    if ($mode -eq "syslog") { return (Send-FimEventToSyslog -Settings $Settings -Event $Event) }
    if ($mode -ne "http") { return $true }

    $headers = @{
        "Content-Type" = "application/json"
        "X-SPEI-FIM-Source" = $env:COMPUTERNAME
    }
    $token = Get-ProtectedToken -TokenFile ([string]$Settings.efk.tokenFile)
    if (-not [string]::IsNullOrWhiteSpace($token)) {
        $headers["Authorization"] = "Bearer $token"
    }

    $body = ConvertTo-JsonText -Object $Event

    try {
        Invoke-RestMethod -Method Post -Uri ([string]$Settings.efk.endpoint) -Headers $headers -ContentType "application/json" -Body $body -TimeoutSec ([int]$Settings.efk.timeoutSeconds) | Out-Null
        return $true
    } catch {
        if ($QueueOnFailure) {
            Ensure-Directory $QueueRoot
            $queueFile = Join-Path $QueueRoot ((Get-Date -Format "yyyyMMddHHmmssfff") + "-" + [guid]::NewGuid().ToString("n") + ".json")
            Set-Content -LiteralPath $queueFile -Value $body -Encoding UTF8
        }
        return $false
    }
}

function Flush-FimQueue {
    param([object]$Settings)
    if (-not [bool]$Settings.efk.enabled) { return }
    $mode = "filebeat"
    if ($Settings.efk.PSObject.Properties.Name -contains "mode") {
        $mode = [string]$Settings.efk.mode
    }
    if ($mode -ne "http") { return }
    if (-not (Test-Path -LiteralPath $QueueRoot)) { return }

    foreach ($file in (Get-ChildItem -LiteralPath $QueueRoot -Filter "*.json" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc)) {
        try {
            $event = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
            if (Send-FimEventToEfk -Settings $Settings -Event $event -QueueOnFailure $false) {
                Remove-Item -LiteralPath $file.FullName -Force
            }
        } catch {
            return
        }
    }
}

function Publish-FimEvent {
    param([object]$Settings, [object]$Event)
    Invoke-FimLocalLogRetention -Settings $Settings
    Write-FimLocalLog -Event $Event
    Write-FimWindowsEvent -Settings $Settings -Event $Event
    [void](Send-FimEventToEfk -Settings $Settings -Event $Event)
}

function Save-Baseline {
    param([object]$Settings, [object]$Register, [array]$Entries, [string]$Ticket)

    Ensure-Directory $BaselineRoot
    $baseline = [ordered]@{
        baselineId = "BL-" + (Get-Date -Format "yyyyMMdd-HHmmss")
        createdAt = (Get-Date).ToString("o")
        createdBy = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        hostname = $env:COMPUTERNAME
        assetId = [string]$Settings.assetId
        changeTicket = $Ticket
        registerVersion = [string]$Register.version
        entries = $Entries
    }

    $json = ($baseline | ConvertTo-Json -Depth 16)
    Set-Content -LiteralPath $BaselinePath -Value $json -Encoding UTF8
    $hash = (Get-FileHash -LiteralPath $BaselinePath -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath $BaselineHashPath -Value $hash -Encoding ASCII

    return $baseline
}

function Test-BaselineIntegrity {
    if (-not (Test-Path -LiteralPath $BaselinePath)) { throw "Baseline not found: $BaselinePath" }
    if (-not (Test-Path -LiteralPath $BaselineHashPath)) { throw "Baseline hash manifest not found: $BaselineHashPath" }
    $expected = (Get-Content -LiteralPath $BaselineHashPath -Raw).Trim().ToLowerInvariant()
    $actual = (Get-FileHash -LiteralPath $BaselinePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($expected -ne $actual) {
        throw "Baseline integrity check failed. Expected $expected but got $actual."
    }
}

function Compare-FimInventory {
    param([array]$BaselineEntries, [array]$CurrentEntries)

    $findings = New-Object "System.Collections.Generic.List[object]"
    $baseByPath = @{}
    $curByPath = @{}

    foreach ($entry in $BaselineEntries) { $baseByPath[[string]$entry.path.ToLowerInvariant()] = $entry }
    foreach ($entry in $CurrentEntries) { $curByPath[[string]$entry.path.ToLowerInvariant()] = $entry }

    foreach ($key in $baseByPath.Keys) {
        $old = $baseByPath[$key]
        if (-not $curByPath.ContainsKey($key)) {
            $findings.Add([ordered]@{
                eventId = 9102
                eventType = "fim.file_deleted"
                changeType = "deleted"
                path = [string]$old.path
                severity = [string]$old.severity
                category = [string]$old.category
                old = $old
                current = $null
            })
            continue
        }

        $cur = $curByPath[$key]
        if ($old.exists -eq $true -and $cur.exists -eq $false) {
            $findings.Add([ordered]@{
                eventId = 9102
                eventType = "fim.file_deleted"
                changeType = "missing"
                path = [string]$old.path
                severity = [string]$old.severity
                category = [string]$old.category
                old = $old
                current = $cur
            })
            continue
        }

        $curScanLimitHit = $false
        if ($cur.PSObject.Properties.Name -contains "scanLimitHit") {
            $curScanLimitHit = [bool]$cur.scanLimitHit
        }
        if ($curScanLimitHit) {
            $findings.Add([ordered]@{
                eventId = 9404
                eventType = "fim.scan_limit_hit"
                changeType = "scan_limit_hit"
                path = [string]$cur.path
                severity = [string]$cur.severity
                category = [string]$cur.category
                old = $old
                current = $cur
            })
        }

        if ($old.sha256 -and $cur.sha256 -and ([string]$old.sha256 -ne [string]$cur.sha256)) {
            $findings.Add([ordered]@{
                eventId = 9101
                eventType = "fim.file_modified"
                changeType = "hash_changed"
                path = [string]$cur.path
                severity = [string]$cur.severity
                category = [string]$cur.category
                old = $old
                current = $cur
            })
        }

        if ($old.sha256 -and (-not $cur.sha256) -and $cur.hashError) {
            $findings.Add([ordered]@{
                eventId = 9402
                eventType = "fim.file_hash_failed"
                changeType = "hash_failed"
                path = [string]$cur.path
                severity = [string]$cur.severity
                category = [string]$cur.category
                old = $old
                current = $cur
            })
        }

        if ($old.aclHash -and $cur.aclHash -and ([string]$old.aclHash -ne [string]$cur.aclHash)) {
            $findings.Add([ordered]@{
                eventId = 9104
                eventType = "fim.acl_changed"
                changeType = "acl_changed"
                path = [string]$cur.path
                severity = [string]$cur.severity
                category = [string]$cur.category
                old = $old
                current = $cur
            })
        }

        if ($old.aclHash -and (-not $cur.aclHash) -and $cur.aclError) {
            $findings.Add([ordered]@{
                eventId = 9403
                eventType = "fim.acl_read_failed"
                changeType = "acl_read_failed"
                path = [string]$cur.path
                severity = [string]$cur.severity
                category = [string]$cur.category
                old = $old
                current = $cur
            })
        }

        if ($old.owner -and $cur.owner -and ([string]$old.owner -ne [string]$cur.owner)) {
            $findings.Add([ordered]@{
                eventId = 9104
                eventType = "fim.owner_changed"
                changeType = "owner_changed"
                path = [string]$cur.path
                severity = [string]$cur.severity
                category = [string]$cur.category
                old = $old
                current = $cur
            })
        }
    }

    foreach ($key in $curByPath.Keys) {
        if (-not $baseByPath.ContainsKey($key)) {
            $cur = $curByPath[$key]
            $findings.Add([ordered]@{
                eventId = 9103
                eventType = "fim.file_added"
                changeType = "added"
                path = [string]$cur.path
                severity = [string]$cur.severity
                category = [string]$cur.category
                old = $null
                current = $cur
            })
        }
    }

    return $findings.ToArray()
}

function Get-EventDataMap {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Record)
    $xml = [xml]$Record.ToXml()
    $map = @{}
    foreach ($data in $xml.Event.EventData.Data) {
        if ($data.Name) {
            $map[[string]$data.Name] = [string]$data."#text"
        }
    }
    return $map
}

function New-AuditCorrelationIndex {
    param([int]$LookbackMinutes)

    $start = (Get-Date).AddMinutes(-1 * $LookbackMinutes)
    $ids = @(4663, 4670, 4660)
    $index = @{}
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = "Security"; Id = $ids; StartTime = $start } -ErrorAction Stop
    } catch {
        return $index
    }

    foreach ($event in $events) {
        try {
            $map = Get-EventDataMap -Record $event
            $objectName = $null
            if ($map.ContainsKey("ObjectName")) { $objectName = $map["ObjectName"] }
            if ($objectName) {
                $user = $null
                if ($map.ContainsKey("SubjectDomainName") -and $map.ContainsKey("SubjectUserName")) {
                    $user = $map["SubjectDomainName"] + "\" + $map["SubjectUserName"]
                }
                $key = $objectName.ToLowerInvariant()
                if (-not $index.ContainsKey($key)) {
                    $processName = $null
                    $processId = $null
                    $accessMask = $null
                    $accesses = $null
                    if ($map.ContainsKey("ProcessName")) { $processName = $map["ProcessName"] }
                    if ($map.ContainsKey("ProcessId")) { $processId = $map["ProcessId"] }
                    if ($map.ContainsKey("AccessMask")) { $accessMask = $map["AccessMask"] }
                    if ($map.ContainsKey("Accesses")) { $accesses = $map["Accesses"] }
                    $index[$key] = [ordered]@{
                        windows_event_id = $event.Id
                        windows_event_time = $event.TimeCreated.ToString("o")
                        user = $user
                        process_name = $processName
                        process_id = $processId
                        object_name = $objectName
                        access_mask = $accessMask
                        accesses = $accesses
                    }
                }
            }
        } catch {
            continue
        }
    }

    return $index
}

function Find-AuditCorrelation {
    param([string]$Path, [hashtable]$Index)
    if (-not $Index) { return $null }
    $key = $Path.ToLowerInvariant()
    if ($Index.ContainsKey($key)) {
        return $Index[$key]
    }
    return $null
}

function Invoke-ValidateConfig {
    $settings = Read-JsonFile -Path $SettingsPath
    $register = Read-JsonFile -Path $RegisterPath
    if (-not $register.items -or $register.items.Count -eq 0) {
        throw "critical-files-register.json contains no items."
    }
    return [ordered]@{
        settings = $SettingsPath
        register = $RegisterPath
        items = $register.items.Count
        assetId = [string]$settings.assetId
    }
}

function Invoke-CreateBaseline {
    param([string]$Ticket)
    try {
        $settings = Read-JsonFile -Path $SettingsPath
        $register = Read-JsonFile -Path $RegisterPath
        $entries = @(Get-FimInventory -Register $register)
        $baseline = Save-Baseline -Settings $settings -Register $register -Entries $entries -Ticket $Ticket
        $event = New-FimEvent -Settings $settings -EventId 9200 -EventType "fim.baseline_created" -Severity "medium" -Data @{
            baseline_id = $baseline.baselineId
            change_ticket = $Ticket
            entry_count = $entries.Count
        }
        Publish-FimEvent -Settings $settings -Event $event
        return $baseline
    } catch {
        Write-FimDiagnosticError -Context "CreateBaseline failed" -ErrorRecord $_
        throw ("CreateBaseline internal failure: " + (New-FimErrorDetail -ErrorRecord $_))
    }
}

function Enter-FimScanLock {
    param([object]$Settings)

    Ensure-Directory $RunRoot
    $script:FimMutex = New-Object System.Threading.Mutex -ArgumentList $false, "Local\SPEI-FIM-Scan"
    $acquired = $script:FimMutex.WaitOne(0)
    if (-not $acquired) {
        return [ordered]@{
            acquired = $false
            reason = "another_scan_is_running"
            lock_path = (Join-Path $RunRoot "scan.lock")
        }
    }

    $lockPath = Join-Path $RunRoot "scan.lock"
    $lock = [ordered]@{
        pid = $PID
        hostname = $env:COMPUTERNAME
        started_at = (Get-Date).ToString("o")
        asset_id = [string]$Settings.assetId
    }
    ($lock | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $lockPath -Encoding UTF8

    return [ordered]@{
        acquired = $true
        reason = $null
        lock_path = $lockPath
    }
}

function Exit-FimScanLock {
    param([object]$Lock)
    try {
        if ($Lock -and $Lock.lock_path -and (Test-Path -LiteralPath ([string]$Lock.lock_path))) {
            Remove-Item -LiteralPath ([string]$Lock.lock_path) -Force -ErrorAction SilentlyContinue
        }
    } catch {
    }

    try {
        if ($script:FimMutex) {
            $script:FimMutex.ReleaseMutex()
            $script:FimMutex.Dispose()
            $script:FimMutex = $null
        }
    } catch {
    }
}

function Invoke-Scan {
    $settings = Read-JsonFile -Path $SettingsPath
    $register = Read-JsonFile -Path $RegisterPath

    $scanLock = Enter-FimScanLock -Settings $settings
    if (-not $scanLock.acquired) {
        $skipped = New-FimEvent -Settings $settings -EventId 9002 -EventType "fim.scan_skipped_existing_run" -Severity "medium" -Data @{
            reason = [string]$scanLock.reason
            lock_path = [string]$scanLock.lock_path
        }
        Publish-FimEvent -Settings $settings -Event $skipped
        return @()
    }

    Flush-FimQueue -Settings $settings

    $startEvent = New-FimEvent -Settings $settings -EventId 9000 -EventType "fim.scan_started" -Severity "low" -Data @{
        register_version = [string]$register.version
    }
    Publish-FimEvent -Settings $settings -Event $startEvent

    try {
        Test-BaselineIntegrity
        $baseline = Read-JsonFile -Path $BaselinePath
        $current = @(Get-FimInventory -Register $register)
        $findings = @(Compare-FimInventory -BaselineEntries @($baseline.entries) -CurrentEntries $current)
        $correlationIndex = New-AuditCorrelationIndex -LookbackMinutes ([int]$settings.auditCorrelationLookbackMinutes)

        foreach ($finding in $findings) {
            $correlation = Find-AuditCorrelation -Path ([string]$finding.path) -Index $correlationIndex
            $data = @{
                path = [string]$finding.path
                change_type = [string]$finding.changeType
                category = [string]$finding.category
                old = $finding.old
                current = $finding.current
                audit_correlation = $correlation
                authorization_status = "unknown"
                change_ticket = $null
            }
            $event = New-FimEvent -Settings $settings -EventId ([int]$finding.eventId) -EventType ([string]$finding.eventType) -Severity ([string]$finding.severity) -Data $data
            Publish-FimEvent -Settings $settings -Event $event
        }

        $completeEvent = New-FimEvent -Settings $settings -EventId 9001 -EventType "fim.scan_completed" -Severity "low" -Data @{
            finding_count = $findings.Count
            baseline_id = [string]$baseline.baselineId
        }
        Publish-FimEvent -Settings $settings -Event $completeEvent
        return $findings
    } catch {
        $failure = New-FimEvent -Settings $settings -EventId 9401 -EventType "fim.scan_failed" -Severity "high" -Data @{
            error = $_.Exception.Message
        }
        Publish-FimEvent -Settings $settings -Event $failure
        throw
    } finally {
        Exit-FimScanLock -Lock $scanLock
    }
}

function Invoke-SendTestAlert {
    $settings = Read-JsonFile -Path $SettingsPath
    $event = New-FimEvent -Settings $settings -EventId 9301 -EventType "fim.test_alert" -Severity "low" -Data @{
        message = "SPEI-FIM test alert from $env:COMPUTERNAME"
    }
    Publish-FimEvent -Settings $settings -Event $event
    return $event
}

function Invoke-ExportEvidence {
    $settings = Read-JsonFile -Path $SettingsPath
    Ensure-Directory $EvidenceRoot
    $outFile = Join-Path $EvidenceRoot ("fim-evidence-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".jsonl")
    $files = Get-ChildItem -LiteralPath $LogsRoot -Filter "fim-*.jsonl" -File -ErrorAction SilentlyContinue
    foreach ($file in $files) {
        foreach ($line in (Get-Content -LiteralPath $file.FullName)) {
            try {
                $event = $line | ConvertFrom-Json
                $t = [datetime]$event.event_time
                if ($t -ge $From -and $t -le $To) {
                    Add-Content -LiteralPath $outFile -Value $line -Encoding UTF8
                }
            } catch {
                continue
            }
        }
    }
    $summary = New-FimEvent -Settings $settings -EventId 9601 -EventType "fim.evidence_exported" -Severity "low" -Data @{
        from = $From.ToString("o")
        to = $To.ToString("o")
        output = $outFile
    }
    Publish-FimEvent -Settings $settings -Event $summary
    return $outFile
}

Ensure-Directory $ConfigRoot
Ensure-Directory $BaselineRoot
Ensure-Directory $LogsRoot
Ensure-Directory $QueueRoot
Ensure-Directory $EvidenceRoot
Ensure-Directory $RunRoot

switch ($Mode) {
    "ValidateConfig" {
        Invoke-ValidateConfig | ConvertTo-Json -Depth 6
    }
    "CreateBaseline" {
        Invoke-CreateBaseline -Ticket $ChangeTicket | ConvertTo-Json -Depth 12
    }
    "Scan" {
        Invoke-Scan | ConvertTo-Json -Depth 12
    }
    "SendTestAlert" {
        Invoke-SendTestAlert | ConvertTo-Json -Depth 8
    }
    "ExportEvidence" {
        Invoke-ExportEvidence
    }
}
