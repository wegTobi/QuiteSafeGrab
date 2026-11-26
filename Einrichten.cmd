@echo off
rem Einrichtung und Updates von Quite Safe Grab (Doppelklick). Kann jederzeit erneut gestartet werden.
title Quite Safe Grab - Einrichtung
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup.ps1" %*
echo.
if errorlevel 1 echo Die Einrichtung wurde mit einem Fehler beendet (siehe oben).
pause
