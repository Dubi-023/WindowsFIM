<# 
HQ packaging helper.

Create config\deployment.local.json first, then run:
  powershell.exe -ExecutionPolicy Bypass -File .\Prepare-SPEIFIM-Package.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ""
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

$ScriptRoot = Get-ScriptRoot
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $ScriptRoot "SPEI-FIM-OneClick.zip"
}

$localConfig = Join-Path $ScriptRoot "config\deployment.local.json"
if (-not (Test-Path -LiteralPath $localConfig)) {
    throw "Missing config\deployment.local.json. Copy deployment.example.json, edit it, then run again."
}

$configText = Get-Content -LiteralPath $localConfig -Raw
foreach ($bad in @("CHANGE-ME", "CHG-CHANGE-ME")) {
    if ($configText -match [regex]::Escape($bad)) {
        throw "deployment.local.json still contains placeholder value: $bad"
    }
}

if (Test-Path -LiteralPath $OutputPath) {
    Remove-Item -LiteralPath $OutputPath -Force
}

$items = @(
    "Deploy-SPEIFIM.ps1",
    "INSTALL-AS-ADMIN.bat",
    "Uninstall-SPEIFIM.ps1",
    "UNINSTALL-AS-ADMIN.bat",
    "README.md",
    "TEST_PLAN.txt",
    "src",
    "config",
    "efk",
    "docs"
) | ForEach-Object { Join-Path $ScriptRoot $_ }

Compress-Archive -Path $items -DestinationPath $OutputPath -Force
Write-Host "Created package: $OutputPath"
