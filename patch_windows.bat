@echo off
chcp 65001 >nul
title Google Antigravity One-Click Patcher
cd /d "%~dp0"

echo ==================================================
echo        Google Antigravity One-Click Patcher
echo               Telegram: @s1lentov1
echo ==================================================
echo.

if exist "bin\agy_patcher.exe" (
    "bin\agy_patcher.exe" patch -A
) else if exist "agy_patcher.exe" (
    "agy_patcher.exe" patch -A
) else (
    python agy_patcher.py patch -A
)

echo.
echo ==================================================
echo Нажмите любую клавишу, чтобы закрыть окно...
pause >nul
