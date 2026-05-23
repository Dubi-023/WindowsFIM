<# 
One-click installer for SPEI-FIM.

Run from an elevated Windows PowerShell console:
  powershell.exe -ExecutionPolicy Bypass -File .\Deploy-SPEIFIM.ps1

This installer intentionally uses only Windows-native capabilities.
#>

[CmdletBinding()]
param(
    [string]$DeploymentConfig = "",
    [switch]$SkipBaseline,
    [switch]$SkipAuditPolicy,
    [switch]$SkipSacl,
    [switch]$SkipConnectivityTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

function Get-ScriptRoot {
    if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        return $PSScriptRoot
    }
    if ($MyInvocation.MyCommand.Path) {
        return Split-Path -Parent $MyInvocation.MyCommand.Path
    }
    return (Get-Location).Path
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Read-JsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Required JSON file not found: $Path"
    }
    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
}

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Protect-Path {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$ReadOnlyForAdmins
    )
    if (-not (Test-Path -LiteralPath $Path)) { return }

    & icacls.exe $Path /inheritance:r | Out-Null
    & icacls.exe $Path /grant:r "SYSTEM:(OI)(CI)(F)" | Out-Null
    & icacls.exe $Path /grant:r "Administrators:(OI)(CI)(F)" | Out-Null
    if ($ReadOnlyForAdmins) {
        & icacls.exe $Path /grant:r "Users:(OI)(CI)(RX)" | Out-Null
    }
}

function Grant-FilebeatReadAccess {
    param(
        [string]$ProgramDataRoot,
        [string]$LogsRoot,
        [string]$Principal
    )

    if ([string]::IsNullOrWhiteSpace($Principal)) { return }
    if ($Principal -eq "LocalSystem") { $Principal = "SYSTEM" }

    & icacls.exe $ProgramDataRoot /grant:r "${Principal}:(RX)" | Out-Null
    & icacls.exe $LogsRoot /grant:r "${Principal}:(OI)(CI)(RX)" | Out-Null
}

function Resolve-FilebeatReadPrincipal {
    param([object]$Deployment)

    if (($Deployment.efk.PSObject.Properties.Name -contains "filebeatReadPrincipal") -and $Deployment.efk.filebeatReadPrincipal) {
        return [string]$Deployment.efk.filebeatReadPrincipal
    }

    $serviceName = "filebeat"
    if (($Deployment.efk.PSObject.Properties.Name -contains "filebeatServiceName") -and $Deployment.efk.filebeatServiceName) {
        $serviceName = [string]$Deployment.efk.filebeatServiceName
    }

    try {
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop
        if ($service -and $service.StartName) {
            return [string]$service.StartName
        }
    } catch {
        return ""
    }

    return ""
}

function Register-FimEventSource {
    param([string]$Source)
    if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
        New-EventLog -LogName Application -Source $Source
    }
}

function Write-InstallerEvent {
    param(
        [string]$Message,
        [int]$EventId = 9000,
        [string]$EntryType = "Information"
    )
    try {
        Write-EventLog -LogName Application -Source "SPEI-FIM" -EventId $EventId -EntryType $EntryType -Message $Message
    } catch {
        Write-Host $Message
    }
}

function Convert-PlainTokenToProtectedFile {
    param(
        [string]$PlainToken,
        [string]$TokenFile
    )
    if ([string]::IsNullOrWhiteSpace($PlainToken)) { return }
    $secure = ConvertTo-SecureString -String $PlainToken -AsPlainText -Force
    $encrypted = $secure | ConvertFrom-SecureString
    Set-Content -LiteralPath $TokenFile -Value $encrypted -Encoding ASCII
    & icacls.exe $TokenFile /inheritance:r | Out-Null
    & icacls.exe $TokenFile /grant:r "SYSTEM:(F)" | Out-Null
    & icacls.exe $TokenFile /grant:r "Administrators:(F)" | Out-Null
}

function Clear-PlainTokenInDeploymentConfig {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $json = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($json.efk -and $json.efk.authTokenPlainText) {
        $json.efk.authTokenPlainText = ""
        ($json | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $Path -Encoding UTF8
    }
}

function Initialize-DefaultDeploymentConfig {
    param(
        [string]$ExamplePath,
        [string]$TargetPath
    )

    Copy-Item -LiteralPath $ExamplePath -Destination $TargetPath -Force
    $json = Get-Content -LiteralPath $TargetPath -Raw | ConvertFrom-Json
    $json.assetId = $env:COMPUTERNAME
    $json.initialChangeTicket = "PILOT-LOCAL"
    ($json | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath $TargetPath -Encoding UTF8
}

function New-SettingsFile {
    param(
        [object]$Deployment,
        [string]$SettingsPath,
        [string]$TokenFile
    )

    $efkMode = "filebeat"
    if (($Deployment.efk.PSObject.Properties.Name -contains "mode") -and $Deployment.efk.mode) {
        $efkMode = [string]$Deployment.efk.mode
    }
    $filebeatServiceName = "filebeat"
    if (($Deployment.efk.PSObject.Properties.Name -contains "filebeatServiceName") -and $Deployment.efk.filebeatServiceName) {
        $filebeatServiceName = [string]$Deployment.efk.filebeatServiceName
    }
    $efkEndpoint = ""
    if (($Deployment.efk.PSObject.Properties.Name -contains "endpoint") -and $Deployment.efk.endpoint) {
        $efkEndpoint = [string]$Deployment.efk.endpoint
    }
    $efkTimeoutSeconds = 15
    if (($Deployment.efk.PSObject.Properties.Name -contains "timeoutSeconds") -and $Deployment.efk.timeoutSeconds) {
        $efkTimeoutSeconds = [int]$Deployment.efk.timeoutSeconds
    }
    $efkTlsSkipCertificateCheck = $false
    if ($Deployment.efk.PSObject.Properties.Name -contains "tlsSkipCertificateCheck") {
        $efkTlsSkipCertificateCheck = [bool]$Deployment.efk.tlsSkipCertificateCheck
    }

    $settings = [ordered]@{
        toolName = "SPEI-FIM"
        eventSource = "SPEI-FIM"
        eventLogName = "Application"
        assetId = $Deployment.assetId
        environment = $Deployment.environment
        scanIntervalHours = [int]$Deployment.scanIntervalHours
        programDataRoot = "C:\ProgramData\SPEI-FIM"
        logRetentionDaysLocal = [int]$Deployment.logRetentionDaysLocal
        auditCorrelationLookbackMinutes = [int]$Deployment.auditCorrelationLookbackMinutes
        efk = [ordered]@{
            enabled = [bool]$Deployment.efk.enabled
            mode = $efkMode
            localJsonLogPath = "C:\ProgramData\SPEI-FIM\Logs\fim-*.jsonl"
            filebeatServiceName = $filebeatServiceName
            endpoint = $efkEndpoint
            tokenFile = $TokenFile
            timeoutSeconds = $efkTimeoutSeconds
            tlsSkipCertificateCheck = $efkTlsSkipCertificateCheck
        }
    }

    ($settings | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $SettingsPath -Encoding UTF8
}

function Enable-FimAuditPolicy {
    param(
        [bool]$EnableFileSystem,
        [bool]$EnableHandleManipulation,
        [bool]$EnableProcessCreation
    )
    if ($EnableFileSystem) {
        & auditpol.exe /set /subcategory:"File System" /success:enable /failure:enable | Out-Null
    }
    if ($EnableHandleManipulation) {
        & auditpol.exe /set /subcategory:"Handle Manipulation" /success:enable /failure:enable | Out-Null
    }
    if ($EnableProcessCreation) {
        & auditpol.exe /set /subcategory:"Process Creation" /success:enable /failure:disable | Out-Null
    }
}

function Add-FileSystemSacl {
    param([string]$Path, [bool]$Recursive)

    $expanded = [Environment]::ExpandEnvironmentVariables($Path)
    if (-not (Test-Path -LiteralPath $expanded)) {
        Write-Warning "SACL target not found, skipping: $expanded"
        return
    }

    $acl = Get-Acl -LiteralPath $expanded
    $rights = [System.Security.AccessControl.FileSystemRights]"CreateFiles,CreateDirectories,WriteData,AppendData,WriteExtendedAttributes,WriteAttributes,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership"
    $auditFlags = [System.Security.AccessControl.AuditFlags]"Success,Failure"

    if ((Get-Item -LiteralPath $expanded).PSIsContainer -and $Recursive) {
        $inherit = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
        $propagation = [System.Security.AccessControl.PropagationFlags]"None"
    } else {
        $inherit = [System.Security.AccessControl.InheritanceFlags]"None"
        $propagation = [System.Security.AccessControl.PropagationFlags]"None"
    }

    $everyone = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
    $rule = New-Object System.Security.AccessControl.FileSystemAuditRule($everyone, $rights, $inherit, $propagation, $auditFlags)
    $acl.AddAuditRule($rule)
    Set-Acl -LiteralPath $expanded -AclObject $acl
}

function Register-FimScheduledTask {
    param(
        [string]$ScriptPath,
        [int]$IntervalHours,
        [string]$ExecutionPolicyForTask
    )

    $taskName = "SPEI-FIM-Scan"
    $taskPath = "\SPEI-FIM\"
    $escapedScript = '"' + $ScriptPath + '"'
    $tr = "powershell.exe -NoProfile -ExecutionPolicy $ExecutionPolicyForTask -File $escapedScript -Mode Scan"

    & schtasks.exe /Create /TN "$taskPath$taskName" /SC HOURLY /MO $IntervalHours /RU SYSTEM /RL HIGHEST /F /TR $tr | Out-Null
}

function Test-FilebeatService {
    param([string]$ServiceName)
    if ([string]::IsNullOrWhiteSpace($ServiceName)) { $ServiceName = "filebeat" }
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        Write-Warning "Filebeat service '$ServiceName' was not found. SPEI-FIM will still write JSONL logs locally, but EFK ingestion requires Filebeat to harvest C:\ProgramData\SPEI-FIM\Logs\fim-*.jsonl."
        return
    }
    Write-Host "Filebeat service detected: $ServiceName ($($service.Status))"
}

$ScriptRoot = Get-ScriptRoot
if ([string]::IsNullOrWhiteSpace($DeploymentConfig)) {
    $DeploymentConfig = Join-Path $ScriptRoot "config\deployment.local.json"
}

if (-not (Test-IsAdministrator)) {
    throw "This installer must be run as Administrator."
}

$exampleConfig = Join-Path $ScriptRoot "config\deployment.example.json"
if (-not (Test-Path -LiteralPath $DeploymentConfig)) {
    Initialize-DefaultDeploymentConfig -ExamplePath $exampleConfig -TargetPath $DeploymentConfig
    Write-Host "Created default deployment config: $DeploymentConfig"
    Write-Host "Default assetId: $env:COMPUTERNAME"
    Write-Host "Default initialChangeTicket: PILOT-LOCAL"
}

$deployment = Read-JsonFile -Path $DeploymentConfig

$programFilesRoot = "C:\Program Files\SPEI-FIM"
$programDataRoot = "C:\ProgramData\SPEI-FIM"
$configRoot = Join-Path $programDataRoot "Config"
$baselineRoot = Join-Path $programDataRoot "Baseline"
$logsRoot = Join-Path $programDataRoot "Logs"
$queueRoot = Join-Path $programDataRoot "Queue"
$evidenceRoot = Join-Path $programDataRoot "Evidence"
$efkRoot = Join-Path $programDataRoot "EFK"
$tokenFile = Join-Path $configRoot "efk-token.protected"
$settingsPath = Join-Path $configRoot "fim-settings.json"
$registerPath = Join-Path $configRoot "critical-files-register.json"

Register-FimEventSource -Source "SPEI-FIM"

Ensure-Directory $programFilesRoot
Ensure-Directory $programDataRoot
Ensure-Directory $configRoot
Ensure-Directory $baselineRoot
Ensure-Directory $logsRoot
Ensure-Directory $queueRoot
Ensure-Directory $evidenceRoot
Ensure-Directory $efkRoot

Copy-Item -LiteralPath (Join-Path $ScriptRoot "src\SPEI-FIM.ps1") -Destination (Join-Path $programFilesRoot "SPEI-FIM.ps1") -Force
Copy-Item -LiteralPath (Join-Path $ScriptRoot "src\modules") -Destination $programFilesRoot -Recurse -Force
Copy-Item -LiteralPath (Join-Path $ScriptRoot "efk\*") -Destination $efkRoot -Force

New-SettingsFile -Deployment $deployment -SettingsPath $settingsPath -TokenFile $tokenFile
$efkMode = "filebeat"
if ($deployment.efk.PSObject.Properties.Name -contains "mode") {
    $efkMode = [string]$deployment.efk.mode
}
if ($efkMode -eq "http") {
    Convert-PlainTokenToProtectedFile -PlainToken ([string]$deployment.efk.authTokenPlainText) -TokenFile $tokenFile
}
$clearPlaintextToken = $true
if ($deployment.PSObject.Properties.Name -contains "clearPlaintextTokenAfterInstall") {
    $clearPlaintextToken = [bool]$deployment.clearPlaintextTokenAfterInstall
}
if ($clearPlaintextToken) {
    Clear-PlainTokenInDeploymentConfig -Path $DeploymentConfig
}

if ($deployment.criticalFilesRegisterPath -and (Test-Path -LiteralPath $deployment.criticalFilesRegisterPath)) {
    Copy-Item -LiteralPath $deployment.criticalFilesRegisterPath -Destination $registerPath -Force
} else {
    Copy-Item -LiteralPath (Join-Path $ScriptRoot "config\critical-files-register.example.json") -Destination $registerPath -Force
}

Protect-Path -Path $programFilesRoot
Protect-Path -Path $programDataRoot

if (-not $SkipAuditPolicy) {
    $enableFileSystem = $true
    $enableHandleManipulation = $false
    $enableProcessCreation = $false
    if ($deployment.PSObject.Properties.Name -contains "auditPolicy") {
        if ($deployment.auditPolicy.PSObject.Properties.Name -contains "enableFileSystem") {
            $enableFileSystem = [bool]$deployment.auditPolicy.enableFileSystem
        }
        if ($deployment.auditPolicy.PSObject.Properties.Name -contains "enableHandleManipulation") {
            $enableHandleManipulation = [bool]$deployment.auditPolicy.enableHandleManipulation
        }
        if ($deployment.auditPolicy.PSObject.Properties.Name -contains "enableProcessCreation") {
            $enableProcessCreation = [bool]$deployment.auditPolicy.enableProcessCreation
        }
    }
    Enable-FimAuditPolicy -EnableFileSystem $enableFileSystem -EnableHandleManipulation $enableHandleManipulation -EnableProcessCreation $enableProcessCreation
}

if (-not $SkipSacl) {
    $register = Read-JsonFile -Path $registerPath
    foreach ($item in $register.items) {
        if ($item.enabled -eq $false) { continue }
        if ($item.auditCorrelation -eq $true) {
            Add-FileSystemSacl -Path ([string]$item.path) -Recursive ([bool]$item.recursive)
        }
    }
}

$installedScript = Join-Path $programFilesRoot "SPEI-FIM.ps1"
$executionPolicyForTask = "Bypass"
if ($deployment.executionPolicyForTask) {
    $executionPolicyForTask = [string]$deployment.executionPolicyForTask
}
Register-FimScheduledTask -ScriptPath $installedScript -IntervalHours ([int]$deployment.scanIntervalHours) -ExecutionPolicyForTask $executionPolicyForTask

$filebeatPrincipal = Resolve-FilebeatReadPrincipal -Deployment $deployment
Grant-FilebeatReadAccess -ProgramDataRoot $programDataRoot -LogsRoot $logsRoot -Principal $filebeatPrincipal

if (-not $SkipBaseline) {
    & powershell.exe -NoProfile -ExecutionPolicy $executionPolicyForTask -File $installedScript -Mode CreateBaseline -ChangeTicket ([string]$deployment.initialChangeTicket)
}

if (-not $SkipConnectivityTest) {
    & powershell.exe -NoProfile -ExecutionPolicy $executionPolicyForTask -File $installedScript -Mode SendTestAlert
    if ($efkMode -eq "filebeat") {
        Test-FilebeatService -ServiceName ([string]$deployment.efk.filebeatServiceName)
    }
}

Write-InstallerEvent -EventId 9000 -Message "SPEI-FIM deployment completed on $env:COMPUTERNAME."

Write-Host ""
Write-Host "SPEI-FIM deployment completed."
Write-Host "Installed path: $programFilesRoot"
Write-Host "Config path:    $configRoot"
Write-Host "Task name:      \SPEI-FIM\SPEI-FIM-Scan"
Write-Host ""
Write-Host "Run a manual scan with:"
Write-Host "  powershell.exe -NoProfile -ExecutionPolicy $executionPolicyForTask -File `"$installedScript`" -Mode Scan"
