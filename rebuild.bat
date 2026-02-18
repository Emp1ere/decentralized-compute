@echo off
setlocal EnableExtensions
if /I "%~1"=="__run" goto run
start "rebuild" cmd /k call "%~f0" __run
exit /b 0

:run
cd /d "%~dp0"

if not "%NODE_SECRET%"=="" goto have_secret
for /f "skip=2 tokens=1,2,*" %%A in ('reg query "HKCU\Environment" /v NODE_SECRET 2^>nul') do @if /I "%%A"=="NODE_SECRET" set "NODE_SECRET=%%C"

:have_secret
if "%NODE_SECRET%"=="" goto missing_secret

echo ========================================
echo FULL REBUILD
echo ========================================
echo.

echo [1/4] Stop and remove containers...
docker-compose down
if errorlevel 1 docker compose down
echo.

echo [2/4] Rebuild images without cache...
docker-compose build --no-cache
if errorlevel 1 docker compose build --no-cache
if errorlevel 1 goto build_failed
echo.

echo [3/4] Start containers...
docker-compose up -d
if errorlevel 1 docker compose up -d
if errorlevel 1 goto up_failed
echo.

echo [4/4] Wait 10 seconds...
timeout /t 10 /nobreak >nul
echo.

echo ========================================
echo CONTAINERS STATUS
echo ========================================
docker-compose ps
echo.
echo UI: http://localhost:8080
echo Node1: http://localhost:5000
echo Node2: http://localhost:5001
echo Node3: http://localhost:5002
echo.
echo Logs:
echo   docker logs orchestrator_node_1
echo   docker logs orchestrator_node_2
echo   docker logs orchestrator_node_3
echo.
echo Stop:
echo   docker-compose down
echo.
pause
exit /b 0

:missing_secret
echo ERROR: NODE_SECRET is not set.
echo.
echo Set NODE_SECRET and run again.
echo Example:
echo   set NODE_SECRET=replace_with_long_random_secret
echo   rebuild.bat
echo.
echo Permanent setup:
echo   setup_node_secret.bat --generate
echo.
pause
exit /b 1

:build_failed
echo.
echo ERROR: Failed to rebuild Docker images.
echo Check Docker Desktop is running.
echo.
pause
exit /b 1

:up_failed
echo.
echo ERROR: Failed to start containers.
echo.
pause
exit /b 1
