@echo off
rem Double-click to connect in the background, or run:
rem   vpn start ^| stop ^| status ^| login ^| install ^| uninstall  [-Config file.ovpn]
rem Keep this file next to start-ovpn.ps1 (and ovpn.exe).
setlocal
set "mode=%~1"
if "%mode%"=="" set "mode=start"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-ovpn.ps1" -%mode% %2 %3
