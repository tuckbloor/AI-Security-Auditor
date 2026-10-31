@echo off
setlocal EnableExtensions
cd /d "%~dp0"
call "%~dp0setup.bat"
if errorlevel 1 (
  echo ERROR: Application cannot start because setup failed.
  exit /b 1
)
echo.
echo Checking Python source syntax...
"%~dp0.venv\Scripts\python.exe" -m py_compile "%~dp0app.py" "%~dp0ai_engine.py" "%~dp0auditor.py" "%~dp0folder_picker.py" "%~dp0folder_dialog_worker.py" "%~dp0ollama_client.py" "%~dp0reviewed_edits.py" "%~dp0findings_view.py"
if errorlevel 1 (
  echo ERROR: Python syntax validation failed. Streamlit was not launched.
  exit /b 1
)
echo.
echo Opening AI Security Auditor v0.4.4 at http://127.0.0.1:8501
"%~dp0.venv\Scripts\python.exe" -m streamlit run "%~dp0app.py" --server.address 127.0.0.1
exit /b %ERRORLEVEL%
