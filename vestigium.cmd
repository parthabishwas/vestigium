@echo off
rem vestigium.cmd - Vestigium entry point for cmd.exe and Explorer.
rem
rem Runs vestigium.ps1 through Windows PowerShell with a process-scoped
rem execution-policy bypass, so the kit runs from removable media or an
rem extracted archive without changing the machine policy. All arguments are
rem passed through unchanged:
rem
rem   vestigium.cmd -CaseId IR-2026-014 -TargetUser john.doe
rem   vestigium.cmd verify output\WS01_20260911_101500.zip
rem   vestigium.cmd help
rem
rem Set CT_NOPAUSE=1 to suppress the end-of-run pause entirely.
setlocal DisableDelayedExpansion
set "CT_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%CT_PS%" set "CT_PS=powershell.exe"

"%CT_PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0vestigium.ps1" %*
set "CT_RC=%ERRORLEVEL%"

rem Pause only when started by double-clicking in Explorer: no arguments, and
rem a cmd /c command line that names this very file. Remote shells, EDR
rem consoles and schedulers never match, so they cannot hang here. Delayed
rem expansion keeps characters such as ) or & in the kit path harmless.
if not "%~1"=="" goto :finish
if defined CT_NOPAUSE goto :finish
set "CT_SELF=%~f0"
setlocal EnableDelayedExpansion
set "CT_LINE=!CMDCMDLINE!"
if /i not "!CT_LINE:%CT_SELF%=!"=="!CT_LINE!" pause
endlocal

:finish
exit /b %CT_RC%
