# ADR 003: Node.js для Chaincode

**Статус:** Принят  
**Дата:** 2026-02  
**Контекст:** DSCM v2, ТЗ раздел 4

## Решение

Писать Chaincode на **Node.js** (JavaScript/TypeScript).

- **Модули:** Marketplace.js, Contract.js, Reputation.js, EscrowTrigger.js
- **Каналы:** public-marketplace, private-science
- **Fabric:** 2.5+

## Обоснование

1. **Экосистема:** npm-пакеты для криптографии, валидации
2. **Совместимость:** Fabric поддерживает Node.js chaincode
3. **Команда:** единый стек с frontend (если используется JS)
4. **Типизация:** TypeScript для надёжности

## Последствия

- Node.js runtime в Fabric peer
- Текущая логика (Python blockchain, onchain_accounting) — эталон для портирования в chaincode
- Миграция: Phase 1 (10 сквозных транзакций на Fabric)
