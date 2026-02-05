# Как включить автозапуск воркера из интерфейса

Чтобы кнопка **«Запустить воркер автоматически»** работала, оркестратор должен работать **в Docker** с доступом к Docker-демону и правильными переменными окружения.

## Шаг 1. Запуск через Docker Compose

Не запускайте оркестратор вручную (`python app.py`). Запускайте весь стек через Docker Compose:

```bash
# В каталоге проекта (где лежит docker-compose.yml)
docker-compose up --build
```

Или в фоне:

```bash
docker-compose up -d --build
```

Так оркестратор (orchestrator_node_1) будет работать в контейнере с:
- примонтированным сокетом Docker (`/var/run/docker.sock`);
- переменными `WORKER_IMAGE`, `ORCHESTRATOR_URL_FOR_WORKER`, `DOCKER_NETWORK`.

## Шаг 2. Собрать образ воркера

Образ воркера должен существовать. При первом запуске выполните:

```bash
docker-compose build client_worker_1
```

Или просто `docker-compose up --build` — соберутся все сервисы, включая воркер.

## Шаг 3. Открывать интерфейс узла 1

Открывайте дашборд **узла, у которого смонтирован сокет** — это **orchestrator_node_1**:

- **http://localhost:5000** — узел 1 (автозапуск воркера включён);
- http://localhost:5001 — узел 2 (сокет не монтируется, кнопка там вернёт ошибку).

Если заходите через балансировщик (http://localhost:8080), запросы могут попадать на узел 2 — тогда автозапуск не сработает. Для проверки автозапуска используйте именно **http://localhost:5000**.

## Шаг 4. Если имя проекта не «distributed-compute»

Docker Compose даёт проекту имя по имени каталога. По умолчанию ожидаются:

- образ: `distributed-compute_client_worker_1`;
- сеть: `distributed-compute_default`.

Если ваш каталог называется иначе (например, `distributed_compute` или `myproject`), создайте в каталоге проекта файл **.env** и задайте явно:

```env
WORKER_IMAGE=имя_вашего_проекта_client_worker_1
DOCKER_NETWORK=имя_вашего_проекта_default
```

Узнать фактические имена после `docker-compose up`:

```bash
docker images
docker network ls
```

В списке образов ищите образ, собранный для сервиса `client_worker_1` (например, `myproject_client_worker_1`). В сетях — сеть с суффиксом `_default` (например, `myproject_default`). Эти значения и подставьте в `.env`.

## Windows: Docker Desktop

На Windows должен быть запущен **Docker Desktop**. Тогда монтирование `/var/run/docker.sock` в контейнер обрабатывается автоматически, и дополнительных настроек не нужно.

## Проверка

1. `docker-compose up -d --build`
2. Открыть http://localhost:5000
3. Зарегистрироваться или ввести API-ключ
4. Получить задачу или нажать «Взять задачу» у контракта
5. Нажать **«Запустить воркер автоматически»**

Должно появиться сообщение вроде: «Воркер запущен. Контейнер выполнит одну задачу и завершится.» В логах Docker (`docker ps -a` или `docker logs <container_id>`) можно увидеть контейнер воркера, который выполнил задачу и завершился.

## Если кнопка всё равно не работает

- **«Worker auto-start disabled (WORKER_IMAGE not set)»** — оркестратор не видит переменную `WORKER_IMAGE`. Проверьте, что вы заходите на узел 1 (порт 5000) и что перезапустили контейнеры после правок в `docker-compose.yml` или `.env` (`docker-compose up -d`).
- **«Failed to start worker» / «Cannot connect to the Docker daemon»** — в контейнере оркестратора нет доступа к сокету. Убедитесь, что в `docker-compose.yml` у `orchestrator_node_1` есть `volumes: - /var/run/docker.sock:/var/run/docker.sock` и что на хосте запущен Docker.
- **«No such image»** — образ воркера не собран. Выполните `docker-compose build client_worker_1` и снова нажмите кнопку.
