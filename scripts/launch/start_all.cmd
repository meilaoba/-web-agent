@echo off
setlocal enabledelayedexpansion

REM =====================================================
REM AI-Driven Web Code Security Audit System - Start All Services
REM
REM Starts:
REM   1. Dependency check (Python / Node / frontend node_modules)
REM   2. Knowledge base init (build chunks + vector ingest; skippable)
REM   3. Backend  FastAPI  -> http://127.0.0.1:8000  (API docs /docs)
REM   4. Frontend Vite     -> http://localhost:5173
REM
REM Usage:
REM   scripts\start_all.cmd                 # full start (auto install deps/kb on first run)
REM   scripts\start_all.cmd --skip-kb-init  # skip knowledge base init
REM   scripts\start_all.cmd --dry-run       # print steps only, do not start services
REM
REM Stop: close the corresponding service window.
REM =====================================================

cd /d "%~dp0..\.."
set "ROOT=%CD%"
set "SKIP_KB=0"
set "DRY_RUN=0"

for %%a in (%*) do (
    if /i "%%a"=="--skip-kb-init" set "SKIP_KB=1"
    if /i "%%a"=="--dry-run" set "DRY_RUN=1"
)

echo ============================================================
echo   AI Code Security Audit System - one-click start
echo   Project root: %ROOT%
echo ============================================================
echo.

REM ---------- 1. Locate Python ----------
set "PY=python"
where python >nul 2>nul
if not errorlevel 1 goto :py_found
if exist "D:\python3.10\python.exe" (
    set "PY=D:\python3.10\python.exe"
    goto :py_found
)
echo [ERROR] Python not found. Please install Python 3.10+ and retry.
pause
exit /b 1

:py_found
"%PY%" --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not runnable: %PY%
    pause
    exit /b 1
)
echo [OK] Python: %PY%

REM ---------- 2. Locate Node / npm ----------
where node >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Node.js not found. Please install Node 18+ and retry.
    pause
    exit /b 1
)
where npm >nul 2>nul
if errorlevel 1 (
    echo [ERROR] npm not found. Please check the Node.js installation.
    pause
    exit /b 1
)
set "NODE_VER=?"
set "NPM_VER=?"
for /f "delims=" %%v in ('node --version 2^>nul') do set "NODE_VER=%%v"
for /f "delims=" %%v in ('npm --version 2^>nul') do set "NPM_VER=%%v"
echo [OK] Node: %NODE_VER% ^(npm %NPM_VER%^)

REM ---------- 3. Python dependency check + auto install ----------
set "PYTHONPATH=%ROOT%\.deps;%ROOT%\backend"
if exist "%ROOT%\.deps" goto :deps_ready
"%PY%" -c "import fastapi, chromadb, bandit, sqlalchemy" >nul 2>&1
if not errorlevel 1 (
    echo [OK] Python dependencies available (system site-packages)
    set "PYTHONPATH=%ROOT%\backend"
    goto :deps_ready
)
echo [INFO] Python dependencies missing; installing to .deps (first run may take a while)...
if "!DRY_RUN!"=="1" (
    echo        [DRY-RUN] pip install -r backend\requirements.txt --target .deps
    set "PYTHONPATH=%ROOT%\.deps;%ROOT%\backend"
    goto :deps_ready
)
"%PY%" -m pip install --disable-pip-version-check -r "%ROOT%\backend\requirements.txt" --target "%ROOT%\.deps"
if errorlevel 1 (
    echo [ERROR] Python dependency install failed.
    echo        Run manually: %PY% -m pip install -r backend\requirements.txt
    pause
    exit /b 1
)
echo [OK] Python dependencies installed to .deps

:deps_ready
REM ---------- 4. Frontend dependency check ----------
REM Check key package vite (not just node_modules dir) to avoid stale-dir false positive
if exist "%ROOT%\frontend\node_modules\vite" (
    echo [OK] Frontend dependencies installed
    goto :fe_done
)
echo [INFO] Frontend dependencies missing or incomplete; running npm install (first run may take a while)...
if "!DRY_RUN!"=="1" (
    echo        [DRY-RUN] npm install in frontend dir
    goto :fe_done
)
pushd "%ROOT%\frontend"
call npm install --no-audit --no-fund
popd
if errorlevel 1 (
    echo [ERROR] npm install failed. Please run npm install in the frontend folder.
    pause
    exit /b 1
)
echo [OK] Frontend dependencies installed

:fe_done
REM ---------- 5. MySQL hint (if .env sets DB_TYPE=mysql) ----------
if not exist "%ROOT%\.env" goto :mysql_done
findstr /i "DB_TYPE=mysql" "%ROOT%\.env" >nul 2>nul
if errorlevel 1 goto :mysql_done
echo [INFO] .env uses DB_TYPE=mysql. Make sure MySQL is running:
echo        (local: net start MYSQL80 ; docker: docker compose up -d mysql)

:mysql_done
REM ---------- 6. Knowledge base init (first run only) ----------
if "!SKIP_KB!"=="1" (
    echo [INFO] Knowledge base init skipped (--skip-kb-init)
    goto :kb_done
)
if exist "%ROOT%\backend\data\chroma" (
    echo [OK] Knowledge base already exists (backend\data\chroma); skipped.
    echo        To rebuild: scripts\data_pipeline\init_knowledge.cmd
    goto :kb_done
)
echo [INFO] Knowledge base missing; building chunks and ingesting vectors...
if "!DRY_RUN!"=="1" (
    echo        [DRY-RUN] scripts\data_pipeline\init_knowledge.cmd
    goto :kb_done
)
call "%ROOT%\scripts\data_pipeline\init_knowledge.cmd"
if errorlevel 1 (
    echo [ERROR] Knowledge base init failed (services still start; run scripts\data_pipeline\init_knowledge.cmd later)
) else (
    echo [OK] Knowledge base initialized
)

:kb_done
REM ---------- 7. Start backend (separate window) ----------
echo.
echo [INFO] Starting backend  http://127.0.0.1:8000 ...
if "!DRY_RUN!"=="1" (
    echo        [DRY-RUN] start "AI-Audit-Backend" cmd /k call "%ROOT%\scripts\launch\run_backend.cmd"
    goto :be_done
)
start "AI-Audit-Backend" cmd /k call "%ROOT%\scripts\launch\run_backend.cmd"

:be_done
REM ---------- 8. Start frontend (separate window) ----------
echo [INFO] Starting frontend http://localhost:5173 ...
if "!DRY_RUN!"=="1" (
    echo        [DRY-RUN] start "AI-Audit-Frontend" cmd /k call "%ROOT%\frontend\run_dev.cmd"
    goto :end
)
start "AI-Audit-Frontend" cmd /k call "%ROOT%\frontend\run_dev.cmd"

:end
echo.
echo ============================================================
echo   All services started:
echo.
echo     Frontend:  http://localhost:5173
echo     Backend:   http://127.0.0.1:8000
echo     API docs:  http://127.0.0.1:8000/docs
echo.
echo   Close the service windows to stop each service.
echo   Press any key to close this window (services keep running)...
echo ============================================================
pause >nul
endlocal
