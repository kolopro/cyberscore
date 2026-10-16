@echo off
setlocal EnableExtensions EnableDelayedExpansion
title CyberScore v0.1
cd /d "%~dp0"

REM ---------------------------------------------------------------------------
REM  Security Scanner v0.1 - double-click launcher (Windows)
REM  Asks for a website, runs a passive scan, builds a PDF report and opens it.
REM ---------------------------------------------------------------------------

REM --- Find Python (prefer the 'py' launcher, fall back to 'python') ----------
set "PYEXE="
where py >nul 2>&1 && set "PYEXE=py -3"
if not defined PYEXE (
  where python >nul 2>&1 && set "PYEXE=python"
)
if not defined PYEXE (
  echo.
  echo   Python was not found on this computer.
  echo   Please install Python 3 from https://www.python.org/downloads/
  echo   and tick "Add python.exe to PATH" during setup, then run this again.
  echo.
  start "" "https://www.python.org/downloads/"
  pause
  exit /b 1
)

REM --- First run: install dependencies once -----------------------------------
if not exist ".deps_installed" (
  echo Installing dependencies ^(first run only^)...
  %PYEXE% -m pip install --quiet --disable-pip-version-check -r requirements.txt
  if errorlevel 1 (
    echo.
    echo   Could not install dependencies. Check your internet connection and try again.
    echo.
    pause
    exit /b 1
  )
  echo done> ".deps_installed"
)

:ask
echo.
echo ========================================
echo       CyberScore  -  Security Scan
echo ========================================
set "TARGET="
set /p "TARGET=Enter a website to scan (e.g. example.com):  "
if not defined TARGET (
  echo No website entered.
  goto :end
)

echo.
echo Scanning %TARGET% ...  (this takes a few seconds)
echo.
%PYEXE% main.py "%TARGET%" --open
echo.
echo The PDF report was saved in this folder and opened automatically.

:end
echo.
pause
endlocal
