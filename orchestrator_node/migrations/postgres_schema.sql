-- PostgreSQL schema для DSCM v2 (Phase 0)
-- Миграция с JSON/SQLite на PostgreSQL

-- Пользователи (замена users.json)
CREATE TABLE IF NOT EXISTS users (
    client_id VARCHAR(255) PRIMARY KEY,
    api_key_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Контракты (замена provider_contracts.json)
CREATE TABLE IF NOT EXISTS contracts (
    contract_id VARCHAR(255) PRIMARY KEY,
    provider_client_id VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL,
    budget_currency VARCHAR(10),
    budget_amount BIGINT,
    benchmark_meta JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Операции вывода (замена payment_hub)
CREATE TABLE IF NOT EXISTS withdrawal_operations (
    operation_id VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    currency VARCHAR(10) NOT NULL,
    amount BIGINT NOT NULL,
    status VARCHAR(50) NOT NULL,
    provider VARCHAR(100),
    provider_ref VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Индексы
CREATE INDEX IF NOT EXISTS idx_contracts_provider ON contracts(provider_client_id);
CREATE INDEX IF NOT EXISTS idx_contracts_status ON contracts(status);
CREATE INDEX IF NOT EXISTS idx_withdrawals_client ON withdrawal_operations(client_id);
