@echo off
setlocal

set "PROJECT_DIR=%~dp0"
set "FRONTEND_DIR=%PROJECT_DIR%frontend"

cd /d "%FRONTEND_DIR%"

if not exist node_modules (
  call npm.cmd install
  if errorlevel 1 exit /b 1
)

start "" "http://localhost:5173/immersive/console"
call npm.cmd run dev -- --host 127.0.0.1
