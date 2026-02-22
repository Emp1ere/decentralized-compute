@echo off
cd /d "%~dp0"
echo Fixing CRLF in shell scripts...
wsl sed -i "s/\r$//" scripts/setup-fabric-testnet.sh scripts/deploy-dscm-chaincode.sh
echo Done. Now run: wsl bash scripts/setup-fabric-testnet.sh
pause
