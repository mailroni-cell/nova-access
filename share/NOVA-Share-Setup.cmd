@echo off
rem NOVA by Roni - S-191c 2026-11-01 - Signed: Claude Sonnet 5.5 (thread "המשך")
rem ONE FILE install of the NOVA-Share background service. Double-click it (or run it from Win+R, see README.md next to it on GitHub).
rem Windows asks once whether to run as administrator: press Yes. A 6-digit code appears; type it on the TV.
rem If nova_share_service.ps1 is next to this file it is used; otherwise it is downloaded from GitHub (nova-access/share) to the temp folder
rem and deleted again when the setup window closes. After the install the service lives in C:\ProgramData\NOVA-Share.
title NOVA-Share setup
net session >nul 2>&1
if %errorlevel% neq 0 (
  powershell -NoProfile -Command "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c','\"%~f0\"' -Verb RunAs"
  exit /b
)
set S=%~dp0nova_share_service.ps1
if not exist "%S%" set S=%~dp0tools\nova_share_service.ps1
set DL=0
if not exist "%S%" (
  set S=%TEMP%\nova_share_service.ps1
  set DL=1
  echo Downloading the NOVA-Share service from GitHub...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -UseBasicParsing -Uri 'https://raw.githubusercontent.com/mailroni-cell/nova-access/main/share/nova_share_service.ps1' -OutFile \"$env:TEMP\nova_share_service.ps1\"; if ((Get-Item \"$env:TEMP\nova_share_service.ps1\").Length -lt 20000) { throw 'file too small' } } catch { Write-Host $_.Exception.Message; exit 1 }"
  if errorlevel 1 (
    echo.
    echo The download failed. Check the internet connection and run this file again.
    pause
    exit /b 1
  )
)
echo Installing... keep this window open until the code window appears and you close it.
powershell -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%S%" -Action Setup
if "%DL%"=="1" del /f /q "%TEMP%\nova_share_service.ps1" >nul 2>&1
