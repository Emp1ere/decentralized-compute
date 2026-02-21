# Заметки по внедрению DSCM v2

Реализовано по ТЗ DSCM_v2_final (февраль 2026).

## Что внедрено

### Документация
- **ADR/001-fabric-sdk.md** — Go Fabric Sidecar
- **ADR/002-storage.md** — MinIO вместо IPFS
- **ADR/003-chaincode-lang.md** — Node.js Chaincode
- **ARCHITECTURE.md** — архитектура
- **SECURITY_RUNNER.md** — безопасность Docker-раннеров
- **PAYMENT_PROVIDERS.md** — региональные провайдеры
- **ECONOMICS.md** — комиссия 8%/12%
- **ROADMAP.md** — фазы разработки
- **CONSENSUS.md** — обновлён (два уровня: Raft + PoUW)

### Код
- **platform_economics.py** — комиссия 8% до $10k/мес, 12% выше
- **manifest_schema.py** — схема manifest.json, типы верификации (exact, metric, statistical, tee)
- **docker_runner.py** — Docker-раннер с security flags (--network=none, --read-only, uid=65534, etc.)
- **minio_adapter.py** — адаптер MinIO (S3)
- **migrations/postgres_schema.sql** — схема PostgreSQL

### Интеграция
- **runners.py** — добавлен engine `docker` для вызова docker_runner

---

## Условия для внедрения (созданы)

- **docker-compose.dscm.yml** — PostgreSQL, MinIO, Fabric Sidecar
- **fabric_sidecar/** — Go-проект (stub-режим без Fabric)
- **chaincode/** — Node.js Chaincode (Marketplace, Contract, Reputation, EscrowTrigger)
- **payment_providers.py** — интерфейс региональных провайдеров
- **runner-seccomp.json** — Seccomp profile для Docker-раннера
- **dscm_verified** — профиль 3x (2/3), challenge 24 ч
- **TEE** — placeholder в verify_contract_result
- **SETUP_DSCM.md** — инструкция по запуску

## Что требует доработки

| Компонент | Следующий шаг |
|-----------|---------------|
| **Fabric** | Развернуть testnet (см. Hyperledger Fabric docs) |
| **Sidecar** | Подключить fabric-gateway-go при наличии Fabric |
| **Chaincode** | `npm install` в chaincode/, установка в Fabric |
| **PostgreSQL** | Подключить SQLAlchemy в app.py, миграция данных |
| **MinIO** | Создать бакеты, переключить ingestion/results на minio_adapter |
| **Провайдеры** | Реализовать ЮKassa, Stripe, Adyen |
| **TEE** | Реализовать attestation verification |
