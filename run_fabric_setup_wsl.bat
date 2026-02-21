@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo Fabric setup via WSL (recommended for Windows)
echo.

where wsl >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo ERROR: WSL not found. Install: wsl --install
    pause
    exit /b 1
)

echo Stopping Fabric containers and freeing port 7051...
docker stop peer0.org1.example.com peer0.org2.example.com orderer.example.com ca_org1 ca_org2 ca_orderer 2>nul
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :7051') do taskkill /F /PID %%a 2>nul

echo.
echo Running setup in WSL...
for /f "delims=" %%i in ('wsl wslpath -a "%~dp0." 2^>nul') do set "WSL_DIR=%%i"
if "%WSL_DIR%"=="" set "WSL_DIR=/mnt/c/Projects/decentralized-compute"
wsl -e /bin/bash -c "cd '%WSL_DIR%' && /bin/bash scripts/setup-fabric-testnet.sh"
echo.
pause
exit /b %ERRORLEVEL%
