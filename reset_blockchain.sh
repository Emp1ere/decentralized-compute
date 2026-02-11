#!/bin/sh
set -e

echo "========================================"
echo "  ОБНУЛЕНИЕ БЛОКЧЕЙНА"
echo "========================================"
echo

# Проверяем наличие Python
if ! command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then
    echo "ОШИБКА: Python не найден!"
    echo "Установите Python или используйте docker-compose exec"
    exit 1
fi

echo "Запуск скрипта обнуления..."
echo

if command -v python3 >/dev/null 2>&1; then
    python3 reset_blockchain.py
else
    python reset_blockchain.py
fi

if [ $? -ne 0 ]; then
    echo
    echo "ОШИБКА при выполнении скрипта"
    exit 1
fi

echo
