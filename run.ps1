# PowerShell Launch Script for Secure Login System
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "    Secure Login System - Launching Application" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan

$pythonExe = $null

if (Test-Path "$env:LOCALAPPDATA\Python\bin\python.exe") {
    $pythonExe = "$env:LOCALAPPDATA\Python\bin\python.exe"
} else {
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd) {
        $pythonExe = "python"
    } else {
        $cmdPy = Get-Command py -ErrorAction SilentlyContinue
        if ($cmdPy) {
            $pythonExe = "py"
        }
    }
}

if (-not $pythonExe) {
    Write-Host "[ERROR] Python was not found on your system." -ForegroundColor Red
    pause
    exit 1
}

Write-Host "Using Python: $pythonExe" -ForegroundColor Green
& $pythonExe app.py
