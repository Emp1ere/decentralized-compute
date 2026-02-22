@echo off
if "%~1"=="" (
    start cmd /k "cd /d "%~dp0" & "%~f0" _run"
    exit /b 0
)

cd /d "%~dp0"
chcp 65001 >nul

echo Fabric setup via WSL
echo.
echo.
echo Project: %CD%
echo.

where wsl >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo ERROR: WSL not found. Install: wsl --install
    goto :end
)

echo Stopping Fabric containers and freeing port 7051...
docker stop peer0.org1.example.com peer0.org2.example.com orderer.example.com ca_org1 ca_org2 ca_orderer 2>nul
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :7051') do taskkill /F /PID %%a 2>nul

echo.
echo Fixing CRLF in scripts...
wsl sed -i "s/\r$//" scripts/setup-fabric-testnet.sh scripts/deploy-dscm-chaincode.sh 2>nul
echo.
echo Running setup in WSL...
for /f "delims=" %%i in ('wsl wslpath -a "%~dp0." 2^>nul') do set "WSL_DIR=%%i"
if "%WSL_DIR%"=="" (
    echo WARNING: wslpath failed, trying fallback path...
    set "WSL_DIR=/mnt/c/Users/Alexandra/OneDrive/Desktop/Projects/decentralized-compute"
)
echo WSL path: %WSL_DIR%
wsl -e /bin/bash -c "WSD=\"$(echo '%WSL_DIR%' | tr -d '\r')\"; cd \"$WSD\" && sed -i 's/\r$//' scripts/setup-fabric-testnet.sh 2>/dev/null; /bin/bash scripts/setup-fabric-testnet.sh"
if %ERRORLEVEL% neq 0 (
    echo.
    echo ERROR: Setup failed with code %ERRORLEVEL%
)

:end
echo.
echo Press any key to close...
pause >nul
