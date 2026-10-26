@echo off
setlocal
cd /d "%~dp0"
echo [*] Building agy_patcher for Windows...
python build.py
if %ERRORLEVEL% neq 0 (
    echo [!] Build failed!
    exit /b %ERRORLEVEL%
)
echo [OK] Done! Binaries are in bin\
