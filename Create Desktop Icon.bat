@echo off
setlocal
cd /d "%~dp0"

REM ---------------------------------------------------------------------------
REM  Creates a "Security Scanner" shortcut on your Desktop, with the app icon.
REM  Double-click this once; afterwards launch the scanner from the Desktop.
REM ---------------------------------------------------------------------------

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ws = New-Object -ComObject WScript.Shell;" ^
  "$desktop = [Environment]::GetFolderPath('Desktop');" ^
  "$lnk = $ws.CreateShortcut((Join-Path $desktop 'CyberScore.lnk'));" ^
  "$lnk.TargetPath = (Join-Path '%~dp0' 'Security Scanner.bat');" ^
  "$lnk.WorkingDirectory = '%~dp0';" ^
  "$lnk.IconLocation = (Join-Path '%~dp0' 'scanner.ico');" ^
  "$lnk.Description = 'CyberScore - passive website security scanner';" ^
  "$lnk.Save();" ^
  "Write-Host 'Desktop shortcut created: CyberScore';"

if errorlevel 1 (
  echo.
  echo Could not create the shortcut automatically.
  echo You can still run the scanner by double-clicking "Security Scanner.bat" here.
)
echo.
pause
endlocal
