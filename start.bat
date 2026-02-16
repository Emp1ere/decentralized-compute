@echo off
setlocal EnableExtensions
if /I "%~1"=="__run" goto run
start "start" cmd /k call "%~f0" __run
exit /b 0

:run
cd /d "%~dp0"
echo Current folder: %CD%
echo.

if not "%NODE_SECRET%"=="" goto have_secret
for /f "skip=2 tokens=1,2,*" %%A in ('reg query "HKCU\Environment" /v NODE_SECRET 2^>nul') do @if /I "%%A"=="NODE_SECRET" set "NODE_SECRET=%%C"

:have_secret
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
echo.
pause
exit /b 0

:missing_secret
echo ERROR: NODE_SECRET is not set.
echo.
echo Set NODE_SECRET and run again.
echo Example:
echo   set NODE_SECRET=replace_with_long_random_secret
echo   start.bat
echo.
echo Permanent setup:
echo   setup_node_secret.bat --generate
echo.
pause
exit /b 1

:docker_failed
echo.
echo ERROR: Docker start failed.
echo Make sure Docker Desktop is running.
echo.
pause
exit /b 1
