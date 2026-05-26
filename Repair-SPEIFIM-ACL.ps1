<#
Repair SPEI-FIM folder ACLs left by an older package.

Run from an elevated Windows PowerShell console:
  powershell.exe -ExecutionPolicy Bypass -File .\Repair-SPEIFIM-ACL.ps1
#>

[CmdletBinding()]
param(
    [string]$ProgramFilesRoot = "C:\Program Files\SPEI-FIM",
    [string]$ProgramDataRoot = "C:\ProgramData\SPEI-FIM"
)

Set-StrictMode -Version 2.0

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal -ArgumentList $identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-Icacls {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    & icacls.exe $Path @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "icacls.exe failed for $Path with exit code $LASTEXITCODE. Arguments: $($Arguments -join ' ')"
    }
}

function Repair-PathAcl {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) {
        Write-Host "Path not found, skipping: $Path"
        return
    }

    Write-Host "Repairing ACL: $Path"
    Invoke-Icacls -Path $Path -Arguments @("/setowner", "*S-1-5-32-544", "/T", "/C")
    Invoke-Icacls -Path $Path -Arguments @("/grant:r", "*S-1-5-18:(OI)(CI)(F)", "*S-1-5-32-544:(OI)(CI)(F)", "/T", "/C")
}

if (-not (Test-IsAdministrator)) {
    throw "This ACL repair script must be run as Administrator."
}

Repair-PathAcl -Path $ProgramFilesRoot
Repair-PathAcl -Path $ProgramDataRoot

Write-Host ""
Write-Host "SPEI-FIM ACL repair completed. Re-run INSTALL-AS-ADMIN.bat from the latest package."
