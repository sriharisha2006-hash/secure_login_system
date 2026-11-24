@echo off
setlocal enabledelayedexpansion

echo ===================================================
echo     Secure Login System - Launching Application
echo ===================================================

:: Look for Python
set "PYTHON_CMD="
if exist "%LOCALAPPDATA%\Python\bin\python.exe" (
    set "PYTHON_CMD=%LOCALAPPDATA%\Python\bin\python.exe"
) else (
    where python >nul 2>&1
    if !errorlevel! equ 0 (
        set "PYTHON_CMD=python"
    ) else (
        where py >nul 2>&1
        if !errorlevel! equ 0 (
            set "PYTHON_CMD=py"
        )
    )
)

if "%PYTHON_CMD%"=="" (
    echo [ERROR] Python was not found in PATH or standard location.
    echo Please install Python 3.9+ or specify python path.
    pause
    exit /b 1
)

echo Using Python: %PYTHON_CMD%
"%PYTHON_CMD%" app.py
pause
