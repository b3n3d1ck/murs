@echo off
REM MURS launcher for Windows CMD.
setlocal
cd /d "%~dp0"

where python >nul 2>&1
if errorlevel 1 (
  echo error: python not found. Install Python 3.10+ and add it to PATH.
  exit /b 1
)

python -c "import reportlab" >nul 2>&1
if errorlevel 1 (
  echo note: reportlab not installed - PDF output will be skipped.
  echo       install it with: python -m pip install -r requirements.txt
)

where php >nul 2>&1
if errorlevel 1 (
  echo note: php CLI not found - the local lab ^(--lab^) will be unavailable.
)

python -m murs %*
