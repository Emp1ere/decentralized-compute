@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo Phase 0: Fabric testnet setup
echo.

set "BASH="
if exist "C:\Program Files\Git\bin\bash.exe" set "BASH=C:\Program Files\Git\bin\bash.exe"
if exist "C:\Program Files (x86)\Git\bin\bash.exe" set "BASH=C:\Program Files (x86)\Git\bin\bash.exe"
if "%BASH%"=="" (
    where bash >nul 2>nul
    if %ERRORLEVEL% equ 0 set "BASH=bash"
)
if "%BASH%"=="" (
    echo ERROR: bash not found.
    echo Install Git for Windows: https://git-scm.com/download/win
    echo Git includes Git Bash which is required for Fabric scripts.
    pause
    exit /b 1
)

set MSYS_NO_PATHCONV=1
"%BASH%" scripts/setup-fabric-testnet.sh
echo.
pause
exit /b %ERRORLEVEL%
