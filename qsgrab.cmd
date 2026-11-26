@echo off
setlocal
set "HERE=%~dp0"
set "PY=%HERE%python\python.exe"
if not exist "%PY%" (
  echo Noch nicht eingerichtet. Zuerst in PowerShell ausfuehren:
  echo   powershell -ExecutionPolicy Bypass -File .\setup.ps1
  echo Siehe README.md.
  set "RC=1"
  goto :done
)
if not exist "%HERE%config.toml" (
  echo config.toml fehlt. setup.ps1 erneut ausfuehren ^(legt sie aus config.default.toml an^).
  set "RC=1"
  goto :done
)
if /i "%~1"=="firewall" (
  "%PY%" -I "%HERE%fw.py" %2 %3 %4
) else if /i "%~1"=="ui" (
  "%PY%" -I "%HERE%ui.py" %2 %3
) else (
  "%PY%" -I "%HERE%grab.py" %*
)
set "RC=%ERRORLEVEL%"
:done
echo.
if not "%RC%"=="0" echo Fehlercode: %RC%
rem Fenster nur bei Doppelklick offen halten (cmd /c), nicht in einer bestehenden Eingabeaufforderung.
echo %CMDCMDLINE% | find /i "/c" >nul && pause
exit /b %RC%
