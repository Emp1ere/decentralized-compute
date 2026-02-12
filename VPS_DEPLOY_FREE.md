# Деплой distributed-compute на бесплатный VPS (Oracle Cloud Always Free)

Эта инструкция позволяет запустить проект 24/7, чтобы он был доступен даже при выключенном ПК.

## 1) Создать бесплатный VPS

1. Зарегистрируйся в Oracle Cloud (Always Free).
2. Создай VM (Ubuntu 22.04/24.04, лучше Ampere A1).
3. Сохрани внешний IP сервера: `PUBLIC_IP`.

## 2) Открыть нужные порты в Oracle Cloud

В Security List / Network Security Group открой:

- `22/tcp` (SSH)
- `8080/tcp` (вход в приложение)

Рекомендуется не открывать наружу `5000/5001`.

## 3) Подключиться к серверу и установить Docker

```bash
ssh ubuntu@<PUBLIC_IP>

sudo apt update
sudo apt install -y git docker.io docker-compose-plugin
sudo usermod -aG docker $USER
newgrp docker
```

## 4) Клонировать проект и запустить

```bash
git clone https://github.com/Emp1ere/distributed-compute.git
cd distributed-compute
```

Создать `.env` и задать секрет:

```bash
cat > .env << 'EOF'
NODE_SECRET=super-long-random-secret-change-me
EOF
```

Запуск:

```bash
docker compose up -d --build
```

## 5) Проверка работы

```bash
docker compose ps
curl http://localhost:8080/health
```

Открыть в браузере:

- `http://<PUBLIC_IP>:8080/dashboard`
- `http://<PUBLIC_IP>:8080/explorer`

## 6) Автозапуск после перезагрузки VPS

В текущем compose рестарт-политика закомментирована, поэтому можно быстро включить через:

```bash
docker update --restart unless-stopped orchestrator_node_1 orchestrator_node_2 loadbalancer
```

## 7) Полезные команды

Остановить:

```bash
docker compose down
```

Перезапустить:

```bash
docker compose up -d
```

Обновить проект:

```bash
git pull
docker compose up -d --build
```

Логи:

```bash
docker compose logs -f
```

## 8) Минимальная безопасность

- Обязательно поменяй `NODE_SECRET` на длинный уникальный.
- Не публикуй `5000/5001` наружу без необходимости.
- Для продакшена желательно добавить HTTPS (например, через Cloudflare Tunnel или reverse proxy с TLS).
