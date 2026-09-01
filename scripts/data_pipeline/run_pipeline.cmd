@echo off
REM =====================================================
REM Run knowledge base pipeline (raw -> processed)
REM Usage: scripts\run_pipeline.cmd [--chunk-size 1000 ...]
REM =====================================================
setlocal

cd /d "%~dp0..\.."
set "ROOT=%CD%"

set "PY=python"
if exist "D:\python3.10\python.exe" set "PY=D:\python3.10\python.exe"

if exist "%ROOT%\.deps" set "PYTHONPATH=%ROOT%\.deps"

%PY% scripts\data_pipeline\build_knowledge_base.py %*
exit /b %errorlevel%
