# Архитектура DSCM (Decentralized Scientific Compute Marketplace)

**Версия:** 2.0  
**Репозиторий:** github.com/Emp1ere/decentralized-compute

## Обзор

Гибридная архитектура: Python Orchestrator + Go Fabric Sidecar + Node.js Chaincode + MinIO + Payment Adapter.

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  desktop_agent  │────▶│ Python Orchestrator│────▶│  Go Fabric      │
│  client_worker  │     │ (Flask + REST)    │     │  Sidecar        │
└─────────────────┘     └────────┬─────────┘     └────────┬────────┘
                                 │                         │
                    ┌────────────┼────────────┐            │
                    ▼            ▼            ▼            ▼
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────────────────┐
│  MinIO   │  │PostgreSQL│  │ Payment Adapter│  │ Hyperledger Fabric│
│  (S3)    │  │          │  │ (RU/EU/US/CN)  │  │ (Chaincode)       │
└──────────┘  └──────────┘  └──────────┘  └─────────────────────────┘
```

## Компоненты

| Компонент | Роль | Текущий статус |
|-----------|------|----------------|
| **Python Orchestrator** | KEEP + extend | Flask, REST, блокчейн (MVP) |
| **Go Fabric Sidecar** | NEW | Прокси к Fabric |
| **Node.js Chaincode** | NEW | Marketplace, Contract, Reputation, EscrowTrigger |
| **MinIO** | NEW | S3-хранилище вместо IPFS |
| **Payment Adapter** | NEW | Региональные провайдеры |
| **PostgreSQL** | NEW | Вместо SQLite/JSON |
| **client_worker** | KEEP + extend | Pull-модель через REST |
| **desktop_agent** | KEEP + extend | Контракт, загрузка zip |

## Консенсус

- **Два уровня:** Raft (Fabric ordering) + PoUW (верифицированная работа)
- **Текущий MVP:** longest valid chain (Python blockchain)
- **Целевой:** Fabric 2.5+ с ordering service

## Платёжный flow

1. Депозит → 2. Холд (Escrow) → 3. Выполнение → 4. Challenge window (24 ч) → 5. Payout → 6. Dispute

## Регионы

- **RU:** ЮKassa (входящие), СБП/банк (исходящие)
- **EU:** Stripe (карты, SEPA), Stripe Connect
- **US:** Stripe (карты, ACH), Stripe Connect
- **CN:** Alipay/WeChat Pay (через Adyen)

## См. также

- [CONSENSUS.md](CONSENSUS.md)
- [SECURITY_RUNNER.md](SECURITY_RUNNER.md)
- [PAYMENT_PROVIDERS.md](PAYMENT_PROVIDERS.md)
- [ECONOMICS.md](ECONOMICS.md)
- [ADR/](ADR/)
