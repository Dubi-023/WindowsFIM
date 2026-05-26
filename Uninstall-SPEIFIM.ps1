<# 
Uninstaller for SPEI-FIM.

Default behavior preserves audit evidence under C:\ProgramData\SPEI-FIM.

Safe default:
  powershell.exe -ExecutionPolicy Bypass -File .\Uninstall-SPEIFIM.ps1

Full cleanup, including local data and optional SACL cleanup:
  powershell.exe -ExecutionPolicy Bypass -File .\Uninstall-SPEIFIM.ps1 -PurgeData -RemoveSacl -RemoveEventSource
#>

[CmdletBinding()]
param(
    [string]$ProgramFilesRoot = "C:\Program Files\SPEI-FIM",
    [string]$ProgramDataRoot = "C:\ProgramData\SPEI-FIM",
    [switch]$PurgeData,
    [switch]$RemoveSacl,
    [switch]$RemoveEventSource,
    [switch]$DisableAuditPolicy,
    [switch]$Force
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal -ArgumentList $identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Directory {
    param([string]$Path)
    try {
        if (Test-Path -LiteralPath $Path -ErrorAction Stop) { return }
    } catch {
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

function Repair-ProtectedPathAccess {
    param([string]$Path)

    try {
        Invoke-Icacls -Path $Path -Arguments @("/setowner", "*S-1-5-32-544", "/T", "/C")
        Invoke-Icacls -Path $Path -Arguments @("/grant:r", "*S-1-5-18:(OI)(CI)(F)", "*S-1-5-32-544:(OI)(CI)(F)", "/T", "/C")
    } catch {
        Write-UninstallMessage "WARNING: Failed to repair ACL on $Path : $($_.Exception.Message)"
    }
}

function Write-UninstallMessage {
    param([string]$Message)
    $line = "$(Get-Date -Format o) $Message"
    Write-Host $Message
    try {
        if (-not $PurgeData) {
            $logRoot = Join-Path $ProgramDataRoot "Logs"
            Ensure-Directory $logRoot
            Add-Content -LiteralPath (Join-Path $logRoot "uninstall.log") -Value $line -Encoding UTF8
        }
    } catch {
    }
}

function Remove-FimScheduledTask {
    $taskName = "SPEI-FIM-Scan"
    $taskPath = "\SPEI-FIM\"

    try {
        $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
        if ($null -ne $task) {
            Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false
            Write-UninstallMessage "Removed scheduled task: $taskPath$taskName"
            return
        }
    } catch {
        Write-UninstallMessage "Register-ScheduledTask cleanup failed, falling back to schtasks.exe: $($_.Exception.Message)"
    }

    & schtasks.exe /Query /TN "$taskPath$taskName" *> $null
    if ($LASTEXITCODE -eq 0) {
        & schtasks.exe /Delete /TN "$taskPath$taskName" /F | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-UninstallMessage "Removed scheduled task with schtasks.exe: $taskPath$taskName"
        } else {
            Write-UninstallMessage "WARNING: Failed to remove scheduled task with schtasks.exe. Exit code: $LASTEXITCODE"
        }
    } else {
        Write-UninstallMessage "Scheduled task not found: $taskPath$taskName"
    }
}

function Read-JsonFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
}

function Remove-FileSystemSacl {
    param([object]$Register)
    if ($null -eq $Register -or -not $Register.items) {
        Write-UninstallMessage "No critical file register found for SACL cleanup."
        return
    }

    $rights = [System.Security.AccessControl.FileSystemRights]"CreateFiles,CreateDirectories,WriteData,AppendData,WriteExtendedAttributes,WriteAttributes,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership"
    $auditFlags = [System.Security.AccessControl.AuditFlags]"Success,Failure"
    $everyone = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList "S-1-1-0"

    foreach ($item in $Register.items) {
        if ($item.enabled -eq $false) { continue }
        if ($item.auditCorrelation -ne $true) { continue }

        $path = [Environment]::ExpandEnvironmentVariables([string]$item.path)
        if (-not (Test-Path -LiteralPath $path)) {
            Write-UninstallMessage "SACL target not found, skipping: $path"
            continue
        }

        try {
            if ((Get-Item -LiteralPath $path).PSIsContainer -and [bool]$item.recursive) {
                $inherit = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
            } else {
                $inherit = [System.Security.AccessControl.InheritanceFlags]"None"
            }
            $propagation = [System.Security.AccessControl.PropagationFlags]"None"
            $rule = New-Object System.Security.AccessControl.FileSystemAuditRule -ArgumentList $everyone, $rights, $inherit, $propagation, $auditFlags
            $acl = Get-Acl -LiteralPath $path
            [void]$acl.RemoveAuditRule($rule)
            Set-Acl -LiteralPath $path -AclObject $acl
            Write-UninstallMessage "Removed SPEI-FIM SACL rule from: $path"
        } catch {
            Write-UninstallMessage "WARNING: Failed to remove SACL from $path : $($_.Exception.Message)"
        }
    }
}

function Remove-FimProgramFiles {
    Repair-ProtectedPathAccess -Path $ProgramFilesRoot
    if (Test-Path -LiteralPath $ProgramFilesRoot -ErrorAction SilentlyContinue) {
        Remove-Item -LiteralPath $ProgramFilesRoot -Recurse -Force
        Write-UninstallMessage "Removed program files: $ProgramFilesRoot"
    } else {
        Write-UninstallMessage "Program files path not found: $ProgramFilesRoot"
    }
}

function Remove-FimProgramData {
    Repair-ProtectedPathAccess -Path $ProgramDataRoot
    if (Test-Path -LiteralPath $ProgramDataRoot -ErrorAction SilentlyContinue) {
        Remove-Item -LiteralPath $ProgramDataRoot -Recurse -Force
        Write-Host "Removed program data: $ProgramDataRoot"
    } else {
        Write-Host "Program data path not found: $ProgramDataRoot"
    }
}

function Remove-FimEventSource {
    try {
        if ([System.Diagnostics.EventLog]::SourceExists("SPEI-FIM")) {
            Remove-EventLog -Source "SPEI-FIM"
            Write-UninstallMessage "Removed Windows Event Log source: SPEI-FIM"
        } else {
            Write-UninstallMessage "Windows Event Log source not found: SPEI-FIM"
        }
    } catch {
        Write-UninstallMessage "WARNING: Failed to remove Windows Event Log source: $($_.Exception.Message)"
    }
}

function Disable-FimAuditPolicy {
    Write-UninstallMessage "WARNING: Disabling Windows audit policy may affect other controls."
    & auditpol.exe /set /subcategory:"File System" /success:disable /failure:disable | Out-Null
    Write-UninstallMessage "Disabled File System audit policy."
}

if (-not (Test-IsAdministrator)) {
    throw "This uninstaller must be run as Administrator."
}

Write-UninstallMessage "Starting SPEI-FIM uninstall."
Write-UninstallMessage "PurgeData=$PurgeData RemoveSacl=$RemoveSacl RemoveEventSource=$RemoveEventSource DisableAuditPolicy=$DisableAuditPolicy"

$registerPath = Join-Path $ProgramDataRoot "Config\critical-files-register.json"
$register = Read-JsonFile -Path $registerPath

Remove-FimScheduledTask

if ($RemoveSacl) {
    Remove-FileSystemSacl -Register $register
} else {
    Write-UninstallMessage "SACL cleanup skipped. Use -RemoveSacl for full cleanup."
}

Remove-FimProgramFiles

if ($RemoveEventSource) {
    Remove-FimEventSource
} else {
    Write-UninstallMessage "Windows Event Log source preserved. Use -RemoveEventSource for full cleanup."
}

if ($DisableAuditPolicy) {
    Disable-FimAuditPolicy
} else {
    Write-UninstallMessage "Windows audit policy preserved. Use -DisableAuditPolicy only if this endpoint does not need File System auditing for other controls."
}

if ($PurgeData) {
    Remove-FimProgramData
} else {
    Write-UninstallMessage "Program data preserved for evidence: $ProgramDataRoot"
    Write-UninstallMessage "Use -PurgeData to remove logs, baseline, config, queue, and evidence."
}

Write-Host ""
Write-Host "SPEI-FIM uninstall completed."
Write-Host "Default uninstall preserves evidence under: $ProgramDataRoot"
