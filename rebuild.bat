@echo off
setlocal EnableExtensions
chcp 65001 >nul 2>&1
cd /d "%~dp0"

if not "%NODE_SECRET%"=="" goto have_node_secret
for /f "skip=2 tokens=1,2,*" %%A in ('reg query "HKCU\Environment" /v NODE_SECRET 2^>nul') do @if /I "%%A"=="NODE_SECRET" set "NODE_SECRET=%%C"

:have_node_secret
if "%NODE_SECRET%"=="" goto missing_secret

echo ========================================
echo   ПОЛНАЯ ПЕРЕСБОРКА СИСТЕМЫ
echo ========================================
echo.

echo [1/4] Остановка и удаление контейнеров...
docker-compose down
if errorlevel 1 docker compose down
echo.

echo [2/4] Пересборка образов (без кэша)...
docker-compose build --no-cache
if errorlevel 1 docker compose build --no-cache
if errorlevel 1 goto build_failed
echo.

echo [3/4] Запуск системы...
docker-compose up -d
if errorlevel 1 docker compose up -d
if errorlevel 1 goto up_failed
echo.

echo [4/4] Ожидание запуска сервисов (10 сек)...
timeout /t 10 /nobreak >nul
echo.

echo ========================================
echo   СТАТУС КОНТЕЙНЕРОВ
echo ========================================
docker-compose ps
echo.

echo ========================================
echo   СИСТЕМА ПЕРЕСОБРАНА И ЗАПУЩЕНА
echo ========================================
echo.
echo Интерфейс: http://localhost:8080
echo Узел 1:    http://localhost:5000
echo Узел 2:    http://localhost:5001
if "%BOOTSTRAP_PROVIDER_LOGIN%"=="" set BOOTSTRAP_PROVIDER_LOGIN=first_provider
if "%BOOTSTRAP_PROVIDER_PASSWORD%"=="" set BOOTSTRAP_PROVIDER_PASSWORD=first_provider_change_me
echo.
echo Bootstrap first provider:
echo   login: %BOOTSTRAP_PROVIDER_LOGIN%
echo   password: %BOOTSTRAP_PROVIDER_PASSWORD%
echo   (change via environment variables or .env before rebuild)
echo.
echo Для просмотра логов:
echo   docker logs orchestrator_node_1
echo   docker logs orchestrator_node_2
echo.
echo Для остановки:
echo   docker-compose down
echo.
pause
exit /b 0

:missing_secret
echo ERROR: NODE_SECRET is not set.
echo.
echo Set NODE_SECRET before rebuild, for example:
echo   set NODE_SECRET=replace_with_long_random_secret
echo.
echo For permanent setup (recommended):
echo   setup_node_secret.bat --generate
echo   rebuild.bat
echo.
pause
exit /b 1:build_failed
echo.
echo ОШИБКА: Не удалось пересобрать образы.
echo Убедитесь, что Docker Desktop запущен.
echo.
pause
exit /b 1

:up_failed
echo.
echo ОШИБКА: Не удалось запустить систему.
echo.
pause
exit /b 1
