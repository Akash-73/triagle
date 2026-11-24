@echo off
title Triagle detection test
rem Double-click to run the detection test that sits beside this file.
rem It only reads information and runs two harmless PowerShell commands (both run Get-Date).
rem Nothing on this machine is changed, installed or deleted, and nothing is downloaded.
rem Keep this file and recon_chain.ps1 in the same folder.

if not exist "%~dp0recon_chain.ps1" (
  echo recon_chain.ps1 is not in this folder. Put it next to this file and run it again.
  echo.
  pause
  exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0recon_chain.ps1"
echo.
pause
