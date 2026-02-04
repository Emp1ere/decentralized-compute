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

## 2. Формула хеша «Воркер ↔ Контракт»

- **Воркер** (worker.py): `text = f"{self.client_id}-{contract_id}-{nonce}"`, `hash_result = hashlib.sha256(text.encode()).hexdigest()`.
- **Контракт** (contracts.py): `expected_input = f"{client_id}-{contract_id}-{nonce}"`, `expected_hash = hashlib.sha256(expected_input.encode()).hexdigest()`, проверка `expected_hash != result_data`.

Строка и алгоритм совпадают. ✅

---

## 3. Спецификация задачи «get_task_spec ↔ perform_computation»

- **Контракт** возвращает: `contract_id`, `work_units_required`, `difficulty`.
- **Воркер** использует: `task["contract_id"]`, `task["work_units_required"]`, `task["difficulty"]` и строит префикс `"0" * difficulty`.

Поля и смысл совпадают. ✅

---

## 4. Транзакции «app.py ↔ blockchain»

- **reward_tx:** `type`, `from`, `to`, `amount`, `contract_id` — блокчейн проверяет только `type`, `to`, `amount` (_is_valid_reward_tx). Остальные поля допустимы.
- **work_receipt_tx:** `type`, `client_id`, `contract_id`, `work_units`, `result_data`, `fee` — блокчейн проверяет структуру и fee (_is_valid_work_receipt_tx), в get_used_proof_ids используется `result_data`.

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

## 9. Итог

| Область | Согласованность |
|---------|------------------|
| API воркер ↔ оркестратор | ✅ |
| Формула хеша воркер ↔ контракт | ✅ |
| Спецификация задачи (get_task_spec ↔ perform_computation) | ✅ |
| Формат транзакций и валидация в блокчейне | ✅ |
| Формат блока и цепочки при синхронизации | ✅ |
| NODE_SECRET и заголовки между узлами | ✅ |
| Docker: имена, порты, PEER_URL, ORCHESTRATOR_URL | ✅ (комментарий про loadbalancer уточнён: внутри Docker — порт 80) |
| Экономика (fee, лимиты) | ✅ |

Архитектура согласована; расхождений не обнаружено.
