# Roadmap DSCM v2

**Контекст:** ТЗ раздел 8

## Phase 0: Bootstrap & ADR

- [x] ADR/001-fabric-sdk.md, ADR/002-storage.md, ADR/003-chaincode-lang.md
- [x] PostgreSQL schema (migrations/postgres_schema.sql)
- [x] docker-compose.dscm.yml (PostgreSQL, MinIO)
- [x] Fabric testnet (scripts/setup-fabric-testnet.sh)

## Phase 1: Fabric + Chaincode

- [x] Node.js Chaincode: скелет (chaincode/)
- [x] Go Fabric Sidecar: stub (fabric_sidecar/)
- [x] Подключение к Fabric, 10 сквозных транзакций (fabric_sidecar/gateway.go, test_chaincode_flows.py)

## Phase 2: Payment Integration

- [x] Интерфейс payment_providers.py
- [x] Региональные провайдеры (stub: YooKassaSandboxProvider, StripeSandboxProvider, AdyenSandboxProvider)
- [x] Sandbox payout flow (payment_hub_adapter → payment_providers.create_payout)

## Phase 3: Worker + Runner

- [x] hello_world → MinIO (ingestion upload, presigned download/upload, results download)
- [x] Docker-раннер с security flags (docker_runner.py, seccomp)

## Phase 4: Verification + Security

- [x] Профиль dscm_verified (3x, 2/3, challenge 24 ч)
- [x] TEE placeholder в contracts.py
- [ ] Verification types: metric, statistical, tee (attestation)

## Phase 5: Multi-Region RU + EU

- [ ] Региональные провайдеры в production
- [ ] Latency 48 ч стандарт, 1 ч GPU-priority

## Phase 6: Enterprise + CN

- [ ] GDPR, ФЗ-152, CCPA, CN compliance
- [ ] Uptime 99.9%+
