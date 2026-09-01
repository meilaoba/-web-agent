@echo off
REM =====================================================
REM Run all tests
REM Usage: scripts\run_tests.cmd [-v]
REM =====================================================
setlocal

cd /d "%~dp0..\.."
set "ROOT=%CD%"

set "PY=python"
if exist "D:\python3.10\python.exe" set "PY=D:\python3.10\python.exe"

set "PYTHONPATH=%ROOT%\.deps;%ROOT%\backend"

%PY% -m pytest backend\tests %*
exit /b %errorlevel%
