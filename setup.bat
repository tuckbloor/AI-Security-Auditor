@echo off
setlocal EnableExtensions
cd /d "%~dp0"
if errorlevel 1 (
  echo ERROR: Cannot open the AI Security Auditor folder.
  exit /b 1
)

rem Virtual environments are machine-specific and are CREATED on this Windows PC.
if not exist ".venv\Scripts\python.exe" (
  echo [1/2] Creating the Python virtual environment in %CD%\.venv ...
  py -3.14 -m venv ".venv" >nul 2>&1
  if not exist ".venv\Scripts\python.exe" py -3 -m venv ".venv" >nul 2>&1
  if not exist ".venv\Scripts\python.exe" python -m venv ".venv" >nul 2>&1
  if not exist ".venv\Scripts\python.exe" (
    echo ERROR: Python virtual environment could not be created.
    echo Install Python 3.14 for Windows, with the py launcher, then try again.
    echo Diagnostic command: py --list
    exit /b 1
  )
)

rem Only install dependencies once per packaged release.
if not exist ".venv\.security-auditor-v0.4.5-ready" (
  echo [2/2] Installing application and test dependencies...
  ".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r "requirements-dev.txt"
  if errorlevel 1 (
    echo ERROR: Package installation failed. Check your internet connection and pip output.
    exit /b 1
  )
  ".venv\Scripts\python.exe" -c "import streamlit, requests, pytest"
  if errorlevel 1 (
    echo ERROR: Some required Python packages are missing.
    exit /b 1
  )
  type nul > ".venv\.security-auditor-v0.4.5-ready"
)

echo [OK] AI Security Auditor environment is ready.
exit /b 0
