# Платёжные провайдеры

**Контекст:** DSCM v2, ТЗ раздел 3

## Регионы и провайдеры

| Регион | Входящие | Исходящие |
|--------|----------|-----------|
| **RU** | ЮKassa | СБП, банковский перевод |
| **EU** | Stripe (карты, SEPA) | Stripe Connect |
| **US** | Stripe (карты, ACH) | Stripe Connect |
| **CN** | Alipay, WeChat Pay (через Adyen) | Adyen |

## Flow

1. **Депозит** — пополнение баланса
2. **Холд (Escrow)** — резервирование под контракт
3. **Выполнение** — работа воркера
4. **Challenge window** — 24 ч на оспаривание
5. **Payout** — выплата воркеру
6. **Dispute** — разрешение споров

## Текущий статус

- **MVP:** simulated payment provider (payment_hub_adapter.py)
- **Phase 2:** Payment Integration, sandbox payout flow
- **Production:** интеграция с региональными провайдерами
