@echo off
setlocal

net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Requesting Administrator privileges...
  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Repair-SPEIFIM-ACL.ps1"
set RESULT=%errorlevel%
echo.
if %RESULT% neq 0 (
  echo SPEI-FIM ACL repair failed with exit code %RESULT%.
) else (
  echo SPEI-FIM ACL repair completed.
)
pause
exit /b %RESULT%
