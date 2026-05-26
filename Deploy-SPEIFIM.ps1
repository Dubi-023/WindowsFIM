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
    $principal = New-Object Security.Principal.WindowsPrincipal -ArgumentList $identity
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
    try {
        if (Test-Path -LiteralPath $Path -ErrorAction Stop) { return }
    } catch {
        Write-Warning "Cannot query directory before ACL repair: $Path. $($_.Exception.Message)"
        return
    }
    New-Item -Path $Path -ItemType Directory -Force | Out-Null
}

function Invoke-Icacls {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    & icacls.exe $Path @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "icacls.exe failed for $Path with exit code $LASTEXITCODE. Arguments: $($Arguments -join ' ')"
    }
}

function Resolve-IcaclsPrincipal {
    param([string]$Principal)

    if ([string]::IsNullOrWhiteSpace($Principal)) { return "" }
    switch -Regex ($Principal) {
        "^(LocalSystem|SYSTEM|NT AUTHORITY\\SYSTEM)$" { return "*S-1-5-18" }
        "^Administrators$" { return "*S-1-5-32-544" }
        "^Users$" { return "*S-1-5-32-545" }
        default { return $Principal }
    }
}

function Protect-Path {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$ReadOnlyForAdmins
    )
    if (-not (Test-Path -LiteralPath $Path)) { return }

    Invoke-Icacls -Path $Path -Arguments @("/inheritance:r")
    Invoke-Icacls -Path $Path -Arguments @("/grant:r", "*S-1-5-18:(OI)(CI)(F)")
    Invoke-Icacls -Path $Path -Arguments @("/grant:r", "*S-1-5-32-544:(OI)(CI)(F)")
    if ($ReadOnlyForAdmins) {
        Invoke-Icacls -Path $Path -Arguments @("/grant:r", "*S-1-5-32-545:(OI)(CI)(RX)")
    }
}

function Repair-ProtectedPathAccess {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        Invoke-Icacls -Path $Path -Arguments @("/grant:r", "*S-1-5-18:(OI)(CI)(F)")
        Invoke-Icacls -Path $Path -Arguments @("/grant:r", "*S-1-5-32-544:(OI)(CI)(F)")
    } catch {
        Write-Warning "ACL repair failed for $Path before install copy: $($_.Exception.Message)"
    }
}

function Grant-FilebeatReadAccess {
    param(
        [string]$ProgramDataRoot,
        [string]$LogsRoot,
        [string]$Principal
    )

    if ([string]::IsNullOrWhiteSpace($Principal)) { return }
    $resolvedPrincipal = Resolve-IcaclsPrincipal -Principal $Principal

    Invoke-Icacls -Path $ProgramDataRoot -Arguments @("/grant:r", "${resolvedPrincipal}:(RX)")
    Invoke-Icacls -Path $LogsRoot -Arguments @("/grant:r", "${resolvedPrincipal}:(OI)(CI)(RX)")
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
    Invoke-Icacls -Path $TokenFile -Arguments @("/inheritance:r")
    Invoke-Icacls -Path $TokenFile -Arguments @("/grant:r", "*S-1-5-18:(F)")
    Invoke-Icacls -Path $TokenFile -Arguments @("/grant:r", "*S-1-5-32-544:(F)")
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

function Resolve-AssetId {
    param([string]$AssetId)

    if ([string]::IsNullOrWhiteSpace($AssetId)) {
        return $env:COMPUTERNAME
    }
    if ($AssetId -eq "AUTO" -or $AssetId -eq "AUTO-COMPUTERNAME") {
        return $env:COMPUTERNAME
    }
    return $AssetId
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
    $syslogHost = ""
    if (($Deployment.efk.PSObject.Properties.Name -contains "syslogHost") -and $Deployment.efk.syslogHost) {
        $syslogHost = [string]$Deployment.efk.syslogHost
    }
    $syslogPort = 5140
    if (($Deployment.efk.PSObject.Properties.Name -contains "syslogPort") -and $Deployment.efk.syslogPort) {
        $syslogPort = [int]$Deployment.efk.syslogPort
    }
    $syslogProtocol = "udp"
    if (($Deployment.efk.PSObject.Properties.Name -contains "syslogProtocol") -and $Deployment.efk.syslogProtocol) {
        $syslogProtocol = [string]$Deployment.efk.syslogProtocol
    }
    $syslogFacility = "local0"
    if (($Deployment.efk.PSObject.Properties.Name -contains "syslogFacility") -and $Deployment.efk.syslogFacility) {
        $syslogFacility = [string]$Deployment.efk.syslogFacility
    }
    $syslogAppName = "SPEI-FIM"
    if (($Deployment.efk.PSObject.Properties.Name -contains "syslogAppName") -and $Deployment.efk.syslogAppName) {
        $syslogAppName = [string]$Deployment.efk.syslogAppName
    }
    $syslogFraming = "newline"
    if (($Deployment.efk.PSObject.Properties.Name -contains "syslogFraming") -and $Deployment.efk.syslogFraming) {
        $syslogFraming = [string]$Deployment.efk.syslogFraming
    }
    $efkTimeoutSeconds = 15
    if (($Deployment.efk.PSObject.Properties.Name -contains "timeoutSeconds") -and $Deployment.efk.timeoutSeconds) {
        $efkTimeoutSeconds = [int]$Deployment.efk.timeoutSeconds
    }
    $efkTlsSkipCertificateCheck = $false
    if ($Deployment.efk.PSObject.Properties.Name -contains "tlsSkipCertificateCheck") {
        $efkTlsSkipCertificateCheck = [bool]$Deployment.efk.tlsSkipCertificateCheck
    }
    $logMaxSizeMB = 1024
    if ($Deployment.PSObject.Properties.Name -contains "logMaxSizeMB") {
        $logMaxSizeMB = [int]$Deployment.logMaxSizeMB
    }

    $settings = [ordered]@{
        toolName = "SPEI-FIM"
        eventSource = "SPEI-FIM"
        eventLogName = "Application"
        assetId = (Resolve-AssetId -AssetId ([string]$Deployment.assetId))
        environment = $Deployment.environment
        scanIntervalHours = [int]$Deployment.scanIntervalHours
        programDataRoot = "C:\ProgramData\SPEI-FIM"
        logRetentionDaysLocal = [int]$Deployment.logRetentionDaysLocal
        logMaxSizeMB = $logMaxSizeMB
        auditCorrelationLookbackMinutes = [int]$Deployment.auditCorrelationLookbackMinutes
        efk = [ordered]@{
            enabled = [bool]$Deployment.efk.enabled
            mode = $efkMode
            localJsonLogPath = "C:\ProgramData\SPEI-FIM\Logs\fim-*.jsonl"
            filebeatServiceName = $filebeatServiceName
            endpoint = $efkEndpoint
            syslogHost = $syslogHost
            syslogPort = $syslogPort
            syslogProtocol = $syslogProtocol
            syslogFacility = $syslogFacility
            syslogAppName = $syslogAppName
            syslogFraming = $syslogFraming
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

    function Set-AuditSubcategory {
        param(
            [string]$SubcategoryGuid,
            [string]$Name,
            [string]$Success,
            [string]$Failure
        )

        & auditpol.exe /set "/subcategory:$SubcategoryGuid" "/success:$Success" "/failure:$Failure" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "auditpol failed for $Name ($SubcategoryGuid) with exit code $LASTEXITCODE. FIM will still scan files, but Security Log correlation may be incomplete."
        }
    }

    if ($EnableFileSystem) {
        Set-AuditSubcategory -SubcategoryGuid "{0CCE921D-69AE-11D9-BED3-505054503030}" -Name "File System" -Success "enable" -Failure "enable"
    }
    if ($EnableHandleManipulation) {
        Set-AuditSubcategory -SubcategoryGuid "{0CCE9223-69AE-11D9-BED3-505054503030}" -Name "Handle Manipulation" -Success "enable" -Failure "enable"
    }
    if ($EnableProcessCreation) {
        Set-AuditSubcategory -SubcategoryGuid "{0CCE922B-69AE-11D9-BED3-505054503030}" -Name "Process Creation" -Success "enable" -Failure "disable"
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

    $everyone = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList "S-1-1-0"
    $rule = New-Object System.Security.AccessControl.FileSystemAuditRule -ArgumentList $everyone, $rights, $inherit, $propagation, $auditFlags
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
    $argument = "-NoProfile -ExecutionPolicy $ExecutionPolicyForTask -File `"$ScriptPath`" -Mode Scan"

    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $argument
        $periodicTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours $IntervalHours) -RepetitionDuration (New-TimeSpan -Days 3650)
        $startupTrigger = New-ScheduledTaskTrigger -AtStartup -RandomDelay (New-TimeSpan -Minutes 5)
        $logonTrigger = New-ScheduledTaskTrigger -AtLogOn -RandomDelay (New-TimeSpan -Minutes 5)
        $triggers = @($periodicTrigger, $startupTrigger, $logonTrigger)
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -StartWhenAvailable
        Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force | Out-Null
        return
    } catch {
        Write-Warning "Register-ScheduledTask failed, falling back to schtasks.exe: $($_.Exception.Message)"
    }

    $quotedScript = '\"' + $ScriptPath + '\"'
    $taskRun = "powershell.exe -NoProfile -ExecutionPolicy $ExecutionPolicyForTask -File $quotedScript -Mode Scan"
    & schtasks.exe /Create /TN "$taskPath$taskName" /SC HOURLY /MO $IntervalHours /RU SYSTEM /RL HIGHEST /F /TR $taskRun | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to register scheduled task $taskPath$taskName. schtasks.exe exit code: $LASTEXITCODE"
    }
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

function Invoke-CheckedPowerShell {
    param(
        [string]$ExecutionPolicyForTask,
        [string]$ScriptPath,
        [string[]]$ScriptArguments,
        [string]$Description
    )

    & powershell.exe -NoProfile -ExecutionPolicy $ExecutionPolicyForTask -File $ScriptPath @ScriptArguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
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

Repair-ProtectedPathAccess -Path $programFilesRoot
Repair-ProtectedPathAccess -Path $programDataRoot

Ensure-Directory $programFilesRoot
Ensure-Directory $programDataRoot
Ensure-Directory $configRoot
Ensure-Directory $baselineRoot
Ensure-Directory $logsRoot
Ensure-Directory $queueRoot
Ensure-Directory $evidenceRoot
Ensure-Directory $efkRoot

Copy-Item -LiteralPath (Join-Path $ScriptRoot "src\SPEI-FIM.ps1") -Destination (Join-Path $programFilesRoot "SPEI-FIM.ps1") -Force

$modulesSource = Join-Path $ScriptRoot "src\modules"
$modulesDestination = Join-Path $programFilesRoot "modules"
Ensure-Directory $modulesDestination
if (Test-Path -LiteralPath $modulesSource) {
    foreach ($item in (Get-ChildItem -LiteralPath $modulesSource -Force -ErrorAction SilentlyContinue)) {
        Copy-Item -LiteralPath $item.FullName -Destination $modulesDestination -Recurse -Force
    }
}

$efkSource = Join-Path $ScriptRoot "efk"
if (Test-Path -LiteralPath $efkSource) {
    foreach ($item in (Get-ChildItem -LiteralPath $efkSource -Force -ErrorAction SilentlyContinue)) {
        Copy-Item -LiteralPath $item.FullName -Destination $efkRoot -Recurse -Force
    }
}

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
    Invoke-CheckedPowerShell -ExecutionPolicyForTask $executionPolicyForTask -ScriptPath $installedScript -ScriptArguments @("-Mode", "CreateBaseline", "-ChangeTicket", ([string]$deployment.initialChangeTicket)) -Description "CreateBaseline"
}

if (-not $SkipConnectivityTest) {
    Invoke-CheckedPowerShell -ExecutionPolicyForTask $executionPolicyForTask -ScriptPath $installedScript -ScriptArguments @("-Mode", "SendTestAlert") -Description "SendTestAlert"
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
