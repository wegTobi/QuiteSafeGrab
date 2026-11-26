@echo off
rem Einrichtung und Updates von Quite Safe Grab (Doppelklick). Kann jederzeit erneut gestartet werden.
rem Alles steht in EINEM Klammerblock: cmd liest ihn vollstaendig, bevor er laeuft. So stoert es nicht,
rem wenn ein Update diese Datei waehrend der Einrichtung ersetzt.
(
  title Quite Safe Grab - Einrichtung
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup.ps1" %*
  echo.
  if errorlevel 1 echo Die Einrichtung wurde mit einem Fehler beendet ^(siehe oben^).
  pause
  exit /b
)
