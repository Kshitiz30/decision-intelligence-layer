@echo off
set PY_PATH=C:\Users\kshit\AppData\Local\Programs\Python\Python313\python.exe

echo.
echo ========================================
echo  DIL - Deterministic Integrity Layer
echo  Starting Server...
echo ========================================
echo.

REM Install dependencies
echo.
echo Installing dependencies (using absolute path)...
"%PY_PATH%" -m pip install -r requirements.txt

REM Start the server
echo.
echo ========================================
echo  Server Starting on http://localhost:8000
echo  Dashboard: http://localhost:8000
echo  API Docs: http://localhost:8000/docs
echo  Press CTRL+C to stop
echo ========================================
echo.

"%PY_PATH%" dil_main.py
