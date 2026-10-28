@echo off
setlocal
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
  echo [1/3] Creating local Python environment...
  py -3 -m venv .venv
  if errorlevel 1 (echo Python 3 was not found. Install Python 3.11 or newer from python.org and tick Add Python to PATH.& pause & exit /b 1)
)
if not exist .venv\cnv_deps_installed.flag (
  echo [2/3] Installing required packages. Internet is needed for this first run.
  .venv\Scripts\python.exe -m pip install --upgrade pip
  .venv\Scripts\python.exe -m pip install -r requirements.txt
  if errorlevel 1 (echo Dependency installation failed. Check internet and rerun this file.& pause & exit /b 1)
  echo installed>.venv\cnv_deps_installed.flag
)
echo [3/3] Starting Cryptic Nexus Vault...
.venv\Scripts\python.exe app.py
pause
