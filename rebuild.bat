@echo off
chcp 65001 >nul 2>&1
cd /d "%~dp0"
echo ========================================
echo   ПОЛНАЯ ПЕРЕСБОРКА СИСТЕМЫ
echo ========================================
echo.

echo [1/4] Остановка и удаление контейнеров...
docker-compose down
if errorlevel 1 (
  echo Пробую: docker compose down
  docker compose down
)
echo.

echo [2/4] Пересборка образов (без кэша)...
docker-compose build --no-cache
if errorlevel 1 (
  echo Пробую: docker compose build --no-cache
  docker compose build --no-cache
)
if errorlevel 1 (
  echo.
  echo ОШИБКА: Не удалось пересобрать образы.
  echo Убедитесь, что Docker Desktop запущен.
  echo.
  pause
  exit /b 1
)
echo.

echo [3/4] Запуск системы...
docker-compose up -d
if errorlevel 1 (
  echo Пробую: docker compose up -d
  docker compose up -d
)
if errorlevel 1 (
  echo.
  echo ОШИБКА: Не удалось запустить систему.
  echo.
  pause
  exit /b 1
)
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
