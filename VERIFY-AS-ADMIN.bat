@echo off
setlocal

net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Requesting Administrator privileges...
  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Verify-SPEIFIM.ps1"
set RESULT=%errorlevel%
echo.
if %RESULT% neq 0 (
  echo SPEI-FIM verification failed with exit code %RESULT%.
) else (
  echo SPEI-FIM verification passed.
)
pause
exit /b %RESULT%
