@echo off
setlocal EnableExtensions
chcp 65001 >nul 2>&1
cd /d "%~dp0"
echo Current folder: %CD%
echo.

if not "%NODE_SECRET%"=="" goto have_node_secret
for /f "skip=2 tokens=1,2,*" %%A in ('reg query "HKCU\Environment" /v NODE_SECRET 2^>nul') do @if /I "%%A"=="NODE_SECRET" set "NODE_SECRET=%%C"

:have_node_secret
if "%NODE_SECRET%"=="" goto missing_secret

echo Starting Docker...
echo.
docker-compose up -d --build
if errorlevel 1 docker compose up -d --build
if errorlevel 1 goto docker_failed

echo.
echo Waiting 10 sec...
timeout /t 10 /nobreak >nul
echo.
echo Opening browser: http://localhost:8080
start "" "http://localhost:8080"
echo.
echo Done. To stop: docker-compose down
if "%BOOTSTRAP_PROVIDER_LOGIN%"=="" set BOOTSTRAP_PROVIDER_LOGIN=first_provider
if "%BOOTSTRAP_PROVIDER_PASSWORD%"=="" set BOOTSTRAP_PROVIDER_PASSWORD=first_provider_change_me
echo.
echo Bootstrap first provider:
echo   login: %BOOTSTRAP_PROVIDER_LOGIN%
echo   password: %BOOTSTRAP_PROVIDER_PASSWORD%
echo   (change via environment variables or .env before start)
echo.
pause
exit /b 0

:missing_secret
echo ERROR: NODE_SECRET is not set.
echo.
echo Set NODE_SECRET before start, for example:
echo   set NODE_SECRET=replace_with_long_random_secret
echo.
echo For permanent setup (recommended):
echo   setup_node_secret.bat --generate
echo   start.bat
echo.
pause
exit /b 1:docker_failed
echo.
echo Docker failed. Start Docker Desktop and run this script again.
echo Or open cmd, cd to this folder, run: docker-compose up -d --build
echo.
pause
exit /b 1
