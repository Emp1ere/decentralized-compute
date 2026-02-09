# Согласованность архитектуры проекта

Проверка согласованности компонентов: воркер ↔ оркестратор ↔ контракты ↔ блокчейн ↔ Docker/nginx.

---

## 1. API «Воркер ↔ Оркестратор»

| Эндпоинт | Метод | Воркер отправляет | Оркестратор ожидает / возвращает | Статус |
|----------|--------|-------------------|-----------------------------------|--------|
| /register | GET | — | Возвращает `client_id`, `api_key` | ✅ Воркер читает оба поля |
| /get_task | GET | Header `Authorization: Bearer <api_key>` | 401 без ключа; 200 + `contract_id`, `work_units_required`, `difficulty` | ✅ Воркер проверяет `contract_id` в ответе |
| /submit_work | POST | Header + JSON: `client_id`, `contract_id`, `work_units_done`, `result_data`, `nonce` | Проверка client_id == владелец ключа; контракт.verify(...); 200 + `reward_issued` | ✅ Поля совпадают |
| /get_balance/<id> | GET | Header + client_id в path | 401 без ключа; 403 если id ≠ владелец ключа; 200 + `balance` | ✅ Воркер логирует `balance` |

---

## 2. Формула хеша и result_data «Воркер ↔ Контракт»

- **simple_pow (sc-*):** Воркер: `text = f"{client_id}-{contract_id}-{nonce}"`, `result_data = sha256(text).hexdigest()`. Контракт: тот же `expected_input`, проверка `expected_hash != result_data`. Строка и алгоритм совпадают. ✅
- **Астро-контракты (astro-*):** Вычисление в `shared/computation_types.py`: `result_data = sha256(client_id + "|" + final_state).hexdigest()`. Контракт вызывает те же функции и сравнивает с присланным `result_data`. Один и тот же результат вычислений даёт разный `result_data` для разных `client_id` — защита от переиспользования доказательства другим клиентом. ✅
- **Общее правило:** У каждого контракта `result_data` должен быть уникален для пары (client_id, вычисление); replay другого клиента даёт 409 (proof already used by different client). ✅

---

## 3. Спецификация задачи «get_task ↔ perform_computation»

- **Контракт** (contracts.py): возвращает `contract_id`, `work_units_required`, `difficulty`; в shared — `SEED_MAX = (1<<64)-1`, сиды 64-bit.
- **Оркестратор** (app.py get_task): `task_seed = (base ^ client_bits) & ((1<<64)-1)` — сид привязан к client_id, коллизии между клиентами пренебрежимо малы.
- **Воркер** использует: `task["contract_id"]`, `task["work_units_required"]`, `task["difficulty"]`, сид из задания; префикс `"0" * difficulty`.

Поля, 64-bit сид и смысл совпадают. ✅

---

## 4. Транзакции и idempotency «app.py ↔ blockchain»

- **reward_tx:** `type`, `from`, `to`, `amount`, `contract_id` — блокчейн проверяет только `type`, `to`, `amount` (_is_valid_reward_tx).
- **work_receipt_tx:** `type`, `client_id`, `contract_id`, `work_units`, `result_data`, `fee` — блокчейн проверяет структуру и fee; в get_used_proof_ids / find_work_receipt_by_proof используется `result_data` для проверки replay.
- **Idempotency:** Один и тот же proof для одного и того же client_id+contract_id: если уже в цепочке или в pending — возврат 200 «Proof already processed» (без повторной награды). Тот же proof от другого client_id — 409 «proof already used by another worker».

Формат и валидация согласованы. ✅

---

## 5. Синхронизация узлов «цепочка и блоки»

- **Отправка блока:** `POST /receive_block` с телом `new_block.__dict__` (index, timestamp, transactions, previous_hash, nonce, hash).
- **Приём блока:** `add_block_from_peer(block_dict)` ожидает те же ключи; при необходимости используется `block_dict.get("nonce", 0)`.
- **Цепочка:** `GET /chain` → `blockchain.get_chain_json()` → список `block.__dict__`; `replace_chain_from_peer(peer_chain)` ожидает список таких же словарей.

Формат блока и цепочки единый. ✅

---

## 6. Секреты и заголовки между узлами

- Оркестратор при вызове пира отправляет `X-Node-Secret: NODE_SECRET` (GET /chain, POST /receive_block).
- Эндпоинты `/receive_block`, `/receive_chain`, `/add_pending_tx` проверяют `X-Node-Secret` через `require_node_secret`.
- `/chain` не требует секрета (доступен для синхронизации).

Docker-compose задаёт один и тот же `NODE_SECRET` для обоих узлов. ✅

---

## 7. Docker и сеть

- **Имена сервисов:** `orchestrator_node_1`, `orchestrator_node_2`, `loadbalancer`, `client_worker_1`, `client_worker_2`.
- **Воркеры:** `ORCHESTRATOR_URL=http://orchestrator_node_1:5000` или `http://orchestrator_node_2:5000`; при использовании балансировщика — `http://loadbalancer` (внутри сети порт 80, с хоста — localhost:8080).
- **Пиры:** `PEER_URL=http://orchestrator_node_2:5000` у узла 1 и наоборот.
- **Nginx upstream:** `orchestrator_node_1:5000`, `orchestrator_node_2:5000`; при добавлении узла 3 нужно добавить сервер в конфиг.

Порты и имена согласованы. ✅

---

## 8. Экономическая модель

- **app.py** добавляет в work_receipt поле `fee: FEE_PER_WORK_RECEIPT` (импорт из blockchain).
- **blockchain** применяет reward, затем списание fee в `_apply_block_transactions`; лимиты спама проверяются в `add_transaction`.

Константы и порядок применения совпадают. ✅

---

## 9. Контракты (CONTRACTS)

- **simple_pow:** sc-001, sc-002 (difficulty 2–3, разное число work_units).
- **QuickTestPoW (sc-000):** 100 work units, difficulty 1, reward 2; категория «Тестовая» — быстрая проверка submit/reward.
- **Астро:** astro-001 … astro-003 (shared/computation_types: run_astro_*, result_data = sha256(client_id|final_state)).

Все зарегистрированы в CONTRACTS в contracts.py; оркестратор отдаёт их в get_task, верификация через contract.verify(). ✅

---

## 10. Риски и потенциальные источники ошибок

| Риск | Митигация |
|------|-----------|
| **Гонка при создании блока** | `_block_creation_lock`: добавление reward_tx + work_receipt_tx, sync_pending_from_peer и mine_pending выполняются под одной блокировкой. |
| **«Сирота» reward_tx в pending** | Перед добавлением под блокировкой проверяется лимит work_receipt на клиента; при достижении лимита возврат 429 «wait for next block». Добавление обеих транзакций только после проверки. |
| **Replay proof другим клиентом** | result_data привязан к client_id (sha256(client_id\|…)); find_work_receipt_by_proof + 409 при том же proof, другой client_id. |
| **Двойная награда за один proof** | Idempotency: если proof уже в цепочке/pending для этого client_id — 200 «Proof already processed», награда не дублируется. |
| **Исключение при поиске владельца proof** | auth_find_by_client_id в submit_work обёрнут в try/except; при ошибке логируется префикс, ответ 409 не раскрывает внутренние сбои. |
| **Старые записи в цепочке** | Старые блоки с прежним форматом result_data (без client_id) остаются валидными; новые proof всегда в новом формате. При полном пересборке (rebuild) образы единообразны. |
| **Лимиты pending** | MAX_PENDING_TOTAL и MAX_PENDING_WORK_PER_CLIENT в blockchain; при переполнении add_transaction выбрасывает ValueError, submit_work возвращает 400/429. |
| **Синхронизация перед майнингом** | sync_pending_from_peer() вызывается под блокировкой перед mine_pending_transactions(), чтобы учитывать транзакции с пира. |

---

## 11. Итог

| Область | Согласованность |
|---------|------------------|
| API воркер ↔ оркестратор | ✅ |
| Формула хеша и result_data (simple_pow, astro) | ✅ |
| Спецификация задачи, 64-bit task_seed | ✅ |
| Формат транзакций, idempotency, replay | ✅ |
| Формат блока и цепочки при синхронизации | ✅ |
| NODE_SECRET и заголовки между узлами | ✅ |
| Docker: имена, порты, PEER_URL, ORCHESTRATOR_URL | ✅ |
| Экономика (fee, лимиты) | ✅ |
| Контракты (sc-000, sc-*, astro-*) | ✅ |

Архитектура согласована; риски учтены и смягчены в коде и процессе (см. раздел 10).
