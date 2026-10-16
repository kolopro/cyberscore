@echo off
setlocal EnableExtensions
title CyberScore - Web
cd /d "%~dp0"

REM ---------------------------------------------------------------------------
REM  Starts the Security Scanner web app and opens it in your browser.
REM  Keep this window open while you use the site. Close it (or Ctrl+C) to stop.
REM ---------------------------------------------------------------------------

set "PYEXE="
where py >nul 2>&1 && set "PYEXE=py -3"
if not defined PYEXE ( where python >nul 2>&1 && set "PYEXE=python" )
if not defined PYEXE (
  echo Python 3 was not found. Install it from https://www.python.org/downloads/
  echo and tick "Add python.exe to PATH", then run this again.
  start "" "https://www.python.org/downloads/"
  pause
  exit /b 1
)

if not exist ".deps_installed" (
  echo Installing dependencies ^(first run only^)...
  %PYEXE% -m pip install --quiet --disable-pip-version-check -r requirements.txt
  if errorlevel 1 ( echo Dependency install failed. & pause & exit /b 1 )
  echo done> ".deps_installed"
)

echo Starting the web app... your browser will open at http://127.0.0.1:8000
%PYEXE% run_web.py

pause
endlocal
