@echo off
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
echo.
pause
