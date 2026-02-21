@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo Deploying DSCM chaincode to Fabric testnet
echo.

if not exist "fabric-samples\test-network" (
    echo ERROR: Fabric testnet not found. Run run_fabric_setup.bat first.
    pause
    exit /b 1
)

set "BASH="
if exist "C:\Program Files\Git\bin\bash.exe" set "BASH=C:\Program Files\Git\bin\bash.exe"
if exist "C:\Program Files (x86)\Git\bin\bash.exe" set "BASH=C:\Program Files (x86)\Git\bin\bash.exe"
if "%BASH%"=="" set "BASH=bash"
set MSYS_NO_PATHCONV=1
"%BASH%" scripts/deploy-dscm-chaincode.sh
echo.
pause
exit /b %ERRORLEVEL%
