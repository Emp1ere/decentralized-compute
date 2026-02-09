# Задача не сдаётся: «proof already used by different client»

## 1. Обязательно: полная пересборка образов без кэша

Если в логах оркестратора по-прежнему **result_data=4ca3b9183f9a21ea...**, значит воркер запущен из **старого образа** (без привязки proof к client_id). Нужна пересборка **без кэша**.

В папке проекта (где лежит `docker-compose.yml`) выполните по порядку:

```bat
docker-compose down
docker-compose build --no-cache client_worker_1 orchestrator_node_1 orchestrator_node_2
docker-compose up -d
```

Или пересобрать всё:

```bat
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

Дождитесь окончания сборки (может занять 2–5 минут). Затем подождите 10–15 секунд после `up -d` и снова: Взять задачу → Запустить воркер.

---

## 2. Что прислать для анализа (если снова не сдаётся)

### A) Подтверждение, что образы свежие

В командной строке:

```bat
docker images | findstr distributed-compute
```

Пришлите вывод (дата создания образов должна быть **после** последних правок в коде).

### B) Логи воркера после 100%

Контейнер воркера теперь **не удаляется** после выхода (можно снять логи).

1. В логах оркестратора после «Запустить воркер» появится строка вида:  
   `run_worker started container ... container_id=XXXXXXXXXXXX`  
   Запомните этот **container_id** (первые 12 символов).

2. После 100% или после ошибки выполните:
   ```bat
   docker ps -a
   ```
   Найдите контейнер с образом `distributed-compute-client_worker_1` (Status: Exited) и возьмите его CONTAINER ID (или используйте id из лога оркестратора). Затем:
   ```bat
   docker logs <CONTAINER_ID>
   ```

**Что важно в логах воркера:**

- Строка: `Computation completed: result_hash=XXXXXXXX... nonce=... client_id_in_proof=yes`  
  Если есть **client_id_in_proof=yes** — в образе новый код. Если нет — образ старый, пересоберите с `--no-cache`.
- Строка `Starting computation: ... task_seed=...` — пришлите (по ней видно задачу и seed).

### C) Логи оркестратора

Как и раньше: фрагмент логов оркестратора с момента `submit_work request received` до `proof already used` (или до успешной сдачи). По ним видно, какой `result_data` пришёл и под каким client_id он уже есть в цепочке.

---

## 3. Кратко, почему «proof already used» пропадёт после пересборки

В коде теперь:

- Proof (result_data) считается как **hash(client_id + "|" + final_state)**.
- У клиента 5c4fd466 будет свой result_data, у 1844e794 в старых блоках — старый формат (без client_id в хеше).
- Они не совпадают, поэтому оркестратор не найдёт «уже использованный» proof для 5c4fd466 и примет сдачу.

Старый образ воркера всё ещё считает result_data без client_id, поэтому результат совпадает со старыми записями 1844e794. После `build --no-cache` в контейнерах будет новый код.

**Примечание:** Контейнеры воркеров после выхода остаются (для снятия логов). Чтобы удалить остановленные контейнеры воркеров: `docker container prune`.
