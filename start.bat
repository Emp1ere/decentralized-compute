@echo off
chcp 65001 >nul 2>&1
cd /d "%~dp0"
echo Current folder: %CD%
echo.
echo Starting Docker...
echo.

docker-compose up -d --build
if errorlevel 1 (
  echo Trying: docker compose ...
  docker compose up -d --build
)
if errorlevel 1 (
  echo.
  echo Docker failed. Start Docker Desktop and run this script again.
  echo Or open cmd, cd to this folder, run: docker-compose up -d --build
  echo.
  pause
  exit /b 1
)

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
