@echo off
rem NOVA by Roni - S-187 round A 2026-11-01 - Signed: Claude Sonnet 5.5 (thread "המשך")
rem Double-click: installs (or updates) the NOVA-Share background service on this PC, then shows a 6-digit pairing code for the TV.
rem One time only. Needs administrator rights: if this window is not elevated, it starts itself again as administrator (Windows asks once).
rem Keep this file next to nova_share_service.ps1. After the install the service lives in C:\ProgramData\NOVA-Share, so both files can be deleted.
net session >nul 2>&1
if %errorlevel% neq 0 (
  powershell -NoProfile -Command "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c','\"%~f0\"' -Verb RunAs"
  exit /b
)
set S=%~dp0nova_share_service.ps1
if not exist "%S%" set S=%~dp0tools\nova_share_service.ps1
if not exist "%S%" (
  echo nova_share_service.ps1 was not found next to this file.
  pause
  exit /b 1
)
start "" powershell -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%S%" -Action Setup
