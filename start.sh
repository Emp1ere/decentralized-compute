#!/bin/sh
set -e
echo "Запуск системы..."
docker-compose up -d --build || docker compose up -d --build
echo "Ожидание запуска сервисов (10 сек)..."
sleep 10
echo "Открываю интерфейс в браузере."
if command -v xdg-open >/dev/null 2>&1; then
  xdg-open "http://localhost:8080"
elif command -v open >/dev/null 2>&1; then
  open "http://localhost:8080"
else
  echo "Откройте в браузере: http://localhost:8080"
fi
echo "Готово. Интерфейс: http://localhost:8080"
echo "Чтобы остановить: docker-compose down"
