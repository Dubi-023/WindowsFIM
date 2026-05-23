<#
SPEI-FIM local verification helper.

Run from an Administrator PowerShell window, or double-click VERIFY-AS-ADMIN.bat.
#>

[CmdletBinding()]
param(
    [string]$InstallRoot = "C:\Program Files\SPEI-FIM",
    [string]$ProgramDataRoot = "C:\ProgramData\SPEI-FIM",
    [switch]$SkipScan,
    [switch]$SkipTestAlert
)

Set-StrictMode -Version 2.0

$script:FailureCount = 0
$script:WarningCount = 0

function Write-Check {
    param(
        [ValidateSet("PASS", "WARN", "FAIL")]
        [string]$Status,
        [string]$Name,
        [string]$Details = ""
    )

    $color = "White"
    if ($Status -eq "PASS") { $color = "Green" }
    if ($Status -eq "WARN") {
        $color = "Yellow"
        $script:WarningCount++
    }
    if ($Status -eq "FAIL") {
        $color = "Red"
        $script:FailureCount++
    }

    if ([string]::IsNullOrWhiteSpace($Details)) {
        Write-Host ("[{0}] {1}" -f $Status, $Name) -ForegroundColor $color
    } else {
        Write-Host ("[{0}] {1} - {2}" -f $Status, $Name, $Details) -ForegroundColor $color
    }
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-FimMode {
    param(
        [string]$ScriptPath,
        [string]$Mode,
        [string[]]$ExtraArguments = @()
    )

    $arguments = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $ScriptPath, "-Mode", $Mode) + $ExtraArguments
    $output = & powershell.exe @arguments 2>&1
    return [pscustomobject]@{
        ExitCode = $LASTEXITCODE
        Output = ($output -join [Environment]::NewLine)
    }
}

function Test-JsonLog {
    param(
        [string]$Path,
        [string[]]$ExpectedEventTypes
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Write-Check -Status "FAIL" -Name "JSONL log file" -Details "Missing $Path"
        return
    }

    Write-Check -Status "PASS" -Name "JSONL log file" -Details $Path
    $events = @()
    $parseErrors = 0
    foreach ($line in (Get-Content -LiteralPath $Path -Tail 200 -ErrorAction SilentlyContinue)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try {
            $events += ($line | ConvertFrom-Json)
        } catch {
            $parseErrors++
        }
    }

    if ($parseErrors -gt 0) {
        Write-Check -Status "FAIL" -Name "JSONL parse" -Details "$parseErrors invalid line(s) in last 200 lines"
    } else {
        Write-Check -Status "PASS" -Name "JSONL parse" -Details "Last 200 lines parsed"
    }

    foreach ($eventType in $ExpectedEventTypes) {
        $match = $events | Where-Object { $_.event_type -eq $eventType } | Select-Object -First 1
        if ($null -eq $match) {
            Write-Check -Status "FAIL" -Name "Expected event $eventType" -Details "Not found in recent log lines"
        } else {
            Write-Check -Status "PASS" -Name "Expected event $eventType" -Details "Found"
        }
    }
}

$installedScript = Join-Path $InstallRoot "SPEI-FIM.ps1"
$configRoot = Join-Path $ProgramDataRoot "Config"
$baselineRoot = Join-Path $ProgramDataRoot "Baseline"
$logsRoot = Join-Path $ProgramDataRoot "Logs"
$registerPath = Join-Path $configRoot "critical-files-register.json"
$settingsPath = Join-Path $configRoot "fim-settings.json"
$baselinePath = Join-Path $baselineRoot "baseline-current.json"
$baselineHashPath = Join-Path $baselineRoot "baseline-current.sha256"
$todayLog = Join-Path $logsRoot ("fim-" + (Get-Date -Format "yyyy-MM-dd") + ".jsonl")

Write-Host ""
Write-Host "SPEI-FIM verification"
Write-Host "====================="

if (Test-IsAdministrator) {
    Write-Check -Status "PASS" -Name "Administrator PowerShell"
} else {
    Write-Check -Status "FAIL" -Name "Administrator PowerShell" -Details "Run VERIFY-AS-ADMIN.bat or start PowerShell as Administrator"
}

if (Test-Path -LiteralPath $installedScript -PathType Leaf) {
    Write-Check -Status "PASS" -Name "Installed scanner" -Details $installedScript
} else {
    Write-Check -Status "FAIL" -Name "Installed scanner" -Details "Missing $installedScript"
}

foreach ($item in @(
    @{ Name = "Settings file"; Path = $settingsPath },
    @{ Name = "Critical files register"; Path = $registerPath },
    @{ Name = "Baseline file"; Path = $baselinePath },
    @{ Name = "Baseline hash file"; Path = $baselineHashPath }
)) {
    if (Test-Path -LiteralPath ([string]$item.Path) -PathType Leaf) {
        Write-Check -Status "PASS" -Name ([string]$item.Name) -Details ([string]$item.Path)
    } else {
        Write-Check -Status "FAIL" -Name ([string]$item.Name) -Details ("Missing " + [string]$item.Path)
    }
}

if ((Test-Path -LiteralPath $baselinePath -PathType Leaf) -and (Test-Path -LiteralPath $baselineHashPath -PathType Leaf)) {
    try {
        $expected = (Get-Content -LiteralPath $baselineHashPath -Raw).Trim().ToLowerInvariant()
        $actual = (Get-FileHash -LiteralPath $baselinePath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($expected -eq $actual) {
            Write-Check -Status "PASS" -Name "Baseline integrity" -Details $actual
        } else {
            Write-Check -Status "FAIL" -Name "Baseline integrity" -Details "Expected $expected but got $actual"
        }
    } catch {
        Write-Check -Status "FAIL" -Name "Baseline integrity" -Details $_.Exception.Message
    }
}

try {
    $task = Get-ScheduledTask -TaskPath "\SPEI-FIM\" -TaskName "SPEI-FIM-Scan" -ErrorAction Stop
    Write-Check -Status "PASS" -Name "Scheduled task" -Details ("\SPEI-FIM\SPEI-FIM-Scan state=" + $task.State)
} catch {
    Write-Check -Status "FAIL" -Name "Scheduled task" -Details "Missing \SPEI-FIM\SPEI-FIM-Scan"
}

if (Test-Path -LiteralPath $installedScript -PathType Leaf) {
    $validate = Invoke-FimMode -ScriptPath $installedScript -Mode "ValidateConfig"
    if ($validate.ExitCode -eq 0) {
        Write-Check -Status "PASS" -Name "ValidateConfig"
    } else {
        Write-Check -Status "FAIL" -Name "ValidateConfig" -Details $validate.Output
    }

    if (-not $SkipScan) {
        $scan = Invoke-FimMode -ScriptPath $installedScript -Mode "Scan"
        if ($scan.ExitCode -eq 0) {
            Write-Check -Status "PASS" -Name "Manual scan"
        } else {
            Write-Check -Status "FAIL" -Name "Manual scan" -Details $scan.Output
        }
    }

    if (-not $SkipTestAlert) {
        $testAlert = Invoke-FimMode -ScriptPath $installedScript -Mode "SendTestAlert"
        if ($testAlert.ExitCode -eq 0) {
            Write-Check -Status "PASS" -Name "Test alert"
        } else {
            Write-Check -Status "FAIL" -Name "Test alert" -Details $testAlert.Output
        }
    }
}

$expectedEvents = @()
if (-not $SkipScan) { $expectedEvents += "fim.scan_completed" }
if (-not $SkipTestAlert) { $expectedEvents += "fim.test_alert" }
Test-JsonLog -Path $todayLog -ExpectedEventTypes $expectedEvents

Write-Host ""
Write-Host ("Summary: {0} failure(s), {1} warning(s)" -f $script:FailureCount, $script:WarningCount)
if ($script:FailureCount -gt 0) {
    exit 1
}
exit 0
