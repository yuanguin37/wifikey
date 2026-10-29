@echo off
chcp 65001 >nul
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
    py -m wifikey gui
) else (
    python -m wifikey gui
)
if errorlevel 1 pause
