@echo off
REM =====================================================
REM Start FastAPI backend (auto-install dependencies if missing)
REM Usage: scripts\launch\run_backend.cmd [--reload]
REM URL:   http://127.0.0.1:8000/docs
REM =====================================================
setlocal

cd /d "%~dp0..\.."
set "ROOT=%CD%"

REM --- Locate Python (prefer D:\python3.10, fallback PATH) ---
set "PY=python"
if exist "D:\python3.10\python.exe" set "PY=D:\python3.10\python.exe"

REM --- Dependency check + auto install ---
set "PYTHONPATH=%ROOT%\.deps;%ROOT%\backend"
if exist "%ROOT%\.deps" goto :deps_ready
"%PY%" -c "import fastapi, uvicorn" >nul 2>&1
if not errorlevel 1 (
    echo [OK] Python dependencies available (system site-packages)
    set "PYTHONPATH=%ROOT%\backend"
    goto :deps_ready
)
echo [INFO] Python dependencies missing; installing to .deps (first run may take a while)...
"%PY%" -m pip install --disable-pip-version-check -r "%ROOT%\backend\requirements.txt" --target "%ROOT%\.deps"
if errorlevel 1 (
    echo [ERROR] Python dependency install failed.
    echo        Run manually: %PY% -m pip install -r backend\requirements.txt
    pause
    exit /b 1
)
set "PYTHONPATH=%ROOT%\.deps;%ROOT%\backend"
echo [OK] Python dependencies installed to .deps

:deps_ready
cd backend
%PY% -m uvicorn app.main:app --host 127.0.0.1 --port 8000 %*
exit /b %errorlevel%
