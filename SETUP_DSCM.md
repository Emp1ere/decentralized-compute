# Настройка DSCM v2

Инструкция по запуску компонентов, подготовленных для внедрения.

## 0. Fabric Testnet (Phase 0)

```bash
./scripts/setup-fabric-testnet.sh
```

Требует: Docker, Git, curl, Bash. На Windows — Git Bash или WSL.

Создаётся канал `public-marketplace`. Деплой chaincode:
```bash
./scripts/deploy-dscm-chaincode.sh
```

См. [fabric_network/README.md](fabric_network/README.md).

## 1. PostgreSQL + MinIO

```bash
docker-compose -f docker-compose.yml -f docker-compose.dscm.yml up -d postgres minio
```

Переменные (опционально в `.env`):
- `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`
- `MINIO_ROOT_USER`, `MINIO_ROOT_PASSWORD`

Схема PostgreSQL применяется при первом запуске из `orchestrator_node/migrations/postgres_schema.sql`.

## 2. Оркестраторы с PostgreSQL и MinIO

```bash
docker-compose -f docker-compose.yml -f docker-compose.dscm.yml up -d
```

Оркестраторы получат `DATABASE_URL` и `MINIO_*`. Для использования PostgreSQL нужна доработка в коде (подключение SQLAlchemy/psycopg2).

## 3. Fabric Sidecar (заглушка)

```bash
docker-compose -f docker-compose.yml -f docker-compose.dscm.yml --profile fabric up -d fabric_sidecar
```

Sidecar слушает порт 7051. Без `FABRIC_GATEWAY_URL` работает в stub-режиме.

## 4. Chaincode (Node.js)

```bash
cd chaincode
npm install
```

Для установки в Fabric нужна настроенная сеть. См. [ROADMAP.md](ROADMAP.md) Phase 1.

## 5. Seccomp для Docker-раннера

Файл `desktop_agent/runner-seccomp.json` подхватывается автоматически при `engine: docker`.

## 6. Профиль dscm_verified (3x, 24h)

В `decentralized_fiat_policy.TASK_CLASS_PROFILES["dscm_verified"]`:
- `replication_factor`: 3
- `quorum_threshold`: 2
- `challenge_window_seconds`: 86400 (24 ч)

Использование: укажите `task_class: dscm_verified` при создании контракта.

## 7. Платёжные провайдеры

Интерфейс в `orchestrator_node/payment_providers.py`. Текущая реализация — `SimulatedProvider`. Интеграция ЮKassa/Stripe/Adyen — Phase 2.
