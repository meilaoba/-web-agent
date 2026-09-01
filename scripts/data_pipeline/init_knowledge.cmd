@echo off
REM =====================================================
REM Init knowledge base: build chunks + ingest vectors
REM Usage: scripts\init_knowledge.cmd
REM =====================================================
setlocal

cd /d "%~dp0..\.."
set "ROOT=%CD%"

set "PY=python"
if exist "D:\python3.10\python.exe" set "PY=D:\python3.10\python.exe"

if exist "%ROOT%\.deps" set "PYTHONPATH=%ROOT%\.deps"

echo == Step 1/2: build knowledge base (raw -^> processed) ==
%PY% scripts\data_pipeline\build_knowledge_base.py
if errorlevel 1 exit /b 1

echo == Step 2/2: embed and ingest into ChromaDB ==
%PY% scripts\data_pipeline\ingest_knowledge.py
exit /b %errorlevel%
