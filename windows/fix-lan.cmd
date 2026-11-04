@echo off
rem One-click entry for pin-lan.ps1.
rem   fix-lan.cmd               -> apply the /32 routes, then show status
rem   fix-lan.cmd status        -> read-only overview (no admin needed)
rem   fix-lan.cmd apply         -> only write the routes
rem   fix-lan.cmd remove        -> delete the routes this tool installed
rem   fix-lan.cmd watch         -> keep repairing every 10 seconds
rem   fix-lan.cmd install       -> apply now + register a logon task
rem   fix-lan.cmd uninstall     -> remove the logon task
rem The script re-launches itself through UAC when the action needs it.
setlocal EnableExtensions
set "HERE=%~dp0"
set "PS1=%HERE%pin-lan.ps1"

if not exist "%PS1%" (
  echo [x] pin-lan.ps1 not found next to this script:
  echo     %PS1%
  pause
  exit /b 1
)

set "ACTION=%~1"
if "%ACTION%"=="" set "ACTION=apply"

net session >nul 2>&1
if errorlevel 1 (
  if /i "%ACTION%"=="status" goto run
  echo [!] Administrator rights are required for "%ACTION%".
  echo [!] Requesting elevation through UAC...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -ArgumentList '%ACTION%' -Verb RunAs"
  exit /b
)

:run
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -Action "%ACTION%"
set "RC=%ERRORLEVEL%"

if /i "%ACTION%"=="apply" (
  echo.
  echo --- current state -------------------------------------------------
  powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -Action status
)

echo.
if "%RC%"=="0" (
  echo Done.
) else (
  echo Failed with exit code %RC%.
)
if /i "%ACTION%"=="watch" exit /b %RC%
echo Press any key to close this window.
pause >nul
exit /b %RC%