#!/bin/sh
set -e

echo "========================================"
echo "  ПОЛНАЯ ПЕРЕСБОРКА СИСТЕМЫ"
echo "========================================"
echo

echo "[1/4] Остановка и удаление контейнеров..."
docker-compose down || docker compose down
echo

echo "[2/4] Пересборка образов (без кэша)..."
docker-compose build --no-cache || docker compose build --no-cache
if [ $? -ne 0 ]; then
  echo
  echo "ОШИБКА: Не удалось пересобрать образы."
  echo "Убедитесь, что Docker запущен."
  exit 1
fi
echo

echo "[3/4] Запуск системы..."
docker-compose up -d || docker compose up -d
if [ $? -ne 0 ]; then
  echo
  echo "ОШИБКА: Не удалось запустить систему."
  exit 1
fi
echo

echo "[4/4] Ожидание запуска сервисов (10 сек)..."
sleep 10
echo

echo "========================================"
echo "  СТАТУС КОНТЕЙНЕРОВ"
echo "========================================"
docker-compose ps || docker compose ps
echo

echo "========================================"
echo "  СИСТЕМА ПЕРЕСОБРАНА И ЗАПУЩЕНА"
echo "========================================"
echo
echo "Интерфейс: http://localhost:8080"
echo "Узел 1:    http://localhost:5000"
echo "Узел 2:    http://localhost:5001"
echo
echo "Для просмотра логов:"
echo "  docker logs orchestrator_node_1"
echo "  docker logs orchestrator_node_2"
echo
echo "Для остановки:"
echo "  docker-compose down"
echo
