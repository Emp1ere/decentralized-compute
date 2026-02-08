# Общий модуль вычислений

Единственный источник правды для логики задач и верификации:

- **orchestrator_node** использует `shared.computation_types` для строгой проверки сданных работ (пересчёт с тем же seed).
- **client_worker** использует тот же модуль для вычислений.

**Важно:** при изменении алгоритмов (cosmological, supernova, mhd и т.д.) править только файлы в `shared/`. После изменений пересобрать оба образа:  
`docker-compose build orchestrator_node_1 orchestrator_node_2 client_worker_1 client_worker_2`

**Seed:** задаётся через `deterministic_seed(client_id, contract_id)` (SHA256), чтобы результат совпадал у воркера и оркестратора. Не использовать `hash()` для согласования между процессами.
