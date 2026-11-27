@echo off
rem Lists what this machine's own logs say it was doing: Microsoft Defender's
rem scans and updates, Windows Update, starts and sleep. Times and event
rem numbers only. It reads, and changes nothing. See machine-events.ps1.
rem Double-click this file, or run it from a terminal. Add -Days 30 for more.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0machine-events.ps1" %*
set "WARDEN_EVENTS_CODE=%ERRORLEVEL%"
if not defined WARDEN_NO_PAUSE (
    echo.
    pause
)
exit /b %WARDEN_EVENTS_CODE%
