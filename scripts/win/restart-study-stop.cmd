@echo off
rem Ends a restart study that is under way: removes its task and whatever a
rem round left on the machine. Right-click this file and choose "Run as
rem administrator". See restart-study.ps1.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0restart-study.ps1" -Stop
set "WARDEN_KIT_CODE=%ERRORLEVEL%"
echo.
pause
exit /b %WARDEN_KIT_CODE%
