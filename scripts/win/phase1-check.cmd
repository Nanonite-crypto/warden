@echo off
rem Phase 1 acceptance check for Warden. Double-click this file, or run it from a terminal.
rem It builds Warden, checks EICAR detection, runs the tests and measures scan speed.
rem Set WARDEN_NO_PAUSE=1 to skip the "press any key" at the end.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0phase1-check.ps1" %*
set "WARDEN_CHECK_CODE=%ERRORLEVEL%"
if not defined WARDEN_NO_PAUSE (
    echo.
    pause
)
exit /b %WARDEN_CHECK_CODE%
