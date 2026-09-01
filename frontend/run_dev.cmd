@echo off
REM =====================================================
REM Frontend dev server launcher (used by start_all.cmd)
REM Usage: frontend\run_dev.cmd
REM URL:   http://localhost:5173
REM =====================================================
chcp 65001 >nul
cd /d "%~dp0"
echo Starting frontend dev server: http://localhost:5173
call npm run dev
