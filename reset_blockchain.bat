@echo off
cd /d "%~dp0"
echo ========================================
echo   ОБНУЛЕНИЕ БЛОКЧЕЙНА
echo ========================================
echo.

REM Проверяем наличие Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ОШИБКА: Python не найден!
    echo Установите Python или используйте docker-compose exec
    pause
    exit /b 1
)

echo Запуск скрипта обнуления...
echo.
python reset_blockchain.py

if errorlevel 1 (
    echo.
    echo ОШИБКА при выполнении скрипта
    pause
    exit /b 1
)

echo.
pause
