@echo off
chcp 65001 >nul
cd /d "%~dp0"

set "CRYPTO_PATH=%~dp0fabric-samples\test-network\organizations\peerOrganizations\org1.example.com"
if not exist "%CRYPTO_PATH%" (
    echo ERROR: Fabric crypto not found at %CRYPTO_PATH%
    echo Run run_fabric_setup.bat first.
    pause
    exit /b 1
)

set FABRIC_CRYPTO_PATH=%CRYPTO_PATH%
set FABRIC_PEER_ENDPOINT=localhost:7051
set FABRIC_CHANNEL=public-marketplace
set FABRIC_CHAINCODE_NAME=dscm
set PORT=8080

echo Starting Sidecar with Fabric...
echo   FABRIC_CRYPTO_PATH=%FABRIC_CRYPTO_PATH%
echo   FABRIC_PEER_ENDPOINT=%FABRIC_PEER_ENDPOINT%
echo.

cd fabric_sidecar
go run .
pause
