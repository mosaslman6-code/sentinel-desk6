@echo off
chcp 65001 >nul
title SentinelDesk
cd /d "%~dp0"
echo Starting SentinelDesk...
if exist notification-config.bat call notification-config.bat
where py >nul 2>nul
if %errorlevel%==0 (
  py server.py
) else (
  where python >nul 2>nul
  if %errorlevel%==0 (
    python server.py
  ) else (
    echo.
    echo Python was not found. Install it from https://www.python.org/downloads/
    echo IMPORTANT: tick "Add Python to PATH" during installation, then run this file again.
  )
)
echo.
pause
