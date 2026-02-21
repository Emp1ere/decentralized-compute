@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo Deploy chaincode via WSL
echo.
for /f "delims=" %%i in ('wsl wslpath -a "%~dp0." 2^>nul') do set "WSL_DIR=%%i"
if "%WSL_DIR%"=="" set "WSL_DIR=/mnt/c/Projects/decentralized-compute"
wsl -e /bin/bash -c "cd '%WSL_DIR%' && /bin/bash scripts/deploy-dscm-chaincode.sh"
echo.
pause
exit /b %ERRORLEVEL%
