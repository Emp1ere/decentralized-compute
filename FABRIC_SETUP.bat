@echo off
chcp 65001 >nul

if exist "C:\Projects\decentralized-compute" (
    cd /d "C:\Projects\decentralized-compute"
) else (
    cd /d "%~dp0"
)

echo ============================================
echo Fabric Testnet Setup
echo ============================================
echo Project: %CD%
echo.

where wsl >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo ERROR: WSL not found. Run: wsl --install
    goto :end
)

echo [1/3] Stopping old Fabric containers...
docker stop peer0.org1.example.com peer0.org2.example.com orderer.example.com ca_org1 ca_org2 ca_orderer 2>nul

echo [2/3] Fixing line endings (CRLF to LF)...
wsl -e bash -c "cd /mnt/c/Projects/decentralized-compute && python3 -c 'import pathlib; [p.write_text(p.read_text().replace(chr(13), \"\")) for p in pathlib.Path(\"scripts\").glob(\"*.sh\") if p.exists()]'"

echo [3/3] Running Fabric setup...
wsl -e bash -c "cd /mnt/c/Projects/decentralized-compute && bash scripts/setup-fabric-testnet.sh"

:end
echo.
echo ============================================
echo Done. Press any key to close.
pause >nul
