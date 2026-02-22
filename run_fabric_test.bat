@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo Running 10 chaincode flows (requires Sidecar on http://localhost:8080)
echo.

cd fabric_sidecar
python test_chaincode_flows.py --base-url http://localhost:8080
echo.
pause
exit /b %ERRORLEVEL%
