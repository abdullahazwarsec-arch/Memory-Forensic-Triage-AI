@echo off
cd /d "%~dp0"
echo ========================================================
echo Launching Memory Forensics AI Triage Dashboard...
echo ========================================================
echo.

if not exist "venv\Scripts\streamlit.exe" (
    echo [ERROR] Virtual environment not found in .\venv!
    echo Please make sure the virtual environment is installed.
    pause
    exit /b 1
)

echo Starting Streamlit server...
".\venv\Scripts\streamlit.exe" run app.py
pause
