# ADR 001: Hyperledger Fabric SDK и Sidecar

**Статус:** Принят  
**Дата:** 2026-02  
**Контекст:** DSCM v2, ТЗ раздел 2

## Решение

Использовать **Go Fabric Sidecar** (fabric-gateway-go) вместо прямого вызова Python SDK.

- **Sidecar:** отдельный сервис на Go, прокси к Fabric
- **Эндпоинты:** `POST /chaincode/invoke`, `GET /chaincode/query`
- **Orchestrator:** Flask вызывает Sidecar по HTTP, не держит Fabric-соединение

## Обоснование

1. **Стабильность:** fabric-gateway-go — официальный клиент, лучше поддерживается
2. **Изоляция:** сбои Fabric не роняют Python-оркестратор
3. **Масштабирование:** Sidecar можно масштабировать отдельно
4. **TLS/MSP:** конфигурация сертификатов в одном месте (Sidecar)

## Последствия

- Новый компонент в стеке (Go-сервис)
- Сетевая задержка между Orchestrator и Sidecar
- Текущий Python-блокчейн остаётся для MVP; миграция на Fabric — Phase 1
