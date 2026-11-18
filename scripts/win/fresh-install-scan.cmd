@echo off
rem Scans a freshly installed Windows with Warden and counts what it flags.
rem Right-click this file and choose "Run as administrator".
rem It expects warden.exe and rules.wrb next to it; see fresh-install-scan.ps1.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0fresh-install-scan.ps1" %*
set "WARDEN_SCAN_CODE=%ERRORLEVEL%"
echo.
pause
exit /b %WARDEN_SCAN_CODE%
