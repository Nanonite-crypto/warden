@echo off
rem Shows that Warden removes what starts a quarantined file, and puts it back.
rem Three runs, with a restart of Windows after the first and the second.
rem Right-click this file and choose "Run as administrator".
rem It expects warden.exe and warden-dummy.exe next to it; see autostart-remedy.ps1.
rem Only for a virtual machine made for the purpose: it registers a service and tasks.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0autostart-remedy.ps1" %*
set "WARDEN_KIT_CODE=%ERRORLEVEL%"
echo.
pause
exit /b %WARDEN_KIT_CODE%
