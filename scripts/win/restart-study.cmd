@echo off
rem Restarts this machine about forty times, with something else done before
rem each restart, to see whether a restart stumbles over something that
rem Warden does. Right-click this file and choose "Run as administrator".
rem It expects warden.exe, warden-dummy.exe and autostart-remedy.ps1 next to
rem it; see restart-study.ps1.
rem Only for a virtual machine made for the purpose: it restarts the machine
rem by itself, again and again, and registers a task, a service and more.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0restart-study.ps1" %*
set "WARDEN_KIT_CODE=%ERRORLEVEL%"
echo.
pause
exit /b %WARDEN_KIT_CODE%
