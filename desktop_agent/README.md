# Desktop Agent (MVP)

Локальное desktop-приложение для вычислителя:

- выбор сектора/контракта;
- расписание окна работы;
- фоновое выполнение задач;
- переключатель авто-перехода на следующую часть.
- регистрация устройства (device_id/device_name) и heartbeat.
- проверка обновлений версии агента.
- мягкий CPU throttle (добавляет паузы в ходе вычислений).

## Запуск

1. Убедитесь, что установлен Python 3.
2. Установите зависимость:

```bash
pip install -r requirements.txt
```

3. Запустите приложение:

```bash
python desktop_agent_app.py
```

Windows:

```bat
start_desktop_agent.bat
```

## Что нужно заполнить в UI

- URL оркестратора (например `http://localhost:8080`);
- API key вычислителя;
- client_id вычислителя.

Далее:

1. `Проверить /me`
2. `Обновить секторы/контракты`
3. выбрать сектор/контракт
4. настроить расписание
5. `Старт`

## Важно

- `api_key` хранится в `settings.json` в зашифрованном виде (`api_key_encrypted`).
- Ключ шифрования хранится локально в `settings.key`.
- Диагностические логи пишутся в `agent.log` с ротацией.
- Агент отправляет `device_capabilities` (CPU/RAM/GPU/engines), чтобы оркестратор
  выдавал совместимые задачи по policy matching.
- Планировщик агента по умолчанию использует `adaptive` профиль:
  для heavy MD пытается `performance`, но автоматически откатывается в `balanced`
  при признаках деградации (expired/reassigned/rejected jobs).
- Профиль можно выбрать в UI: `adaptive`, `balanced`, `performance`, `eco`.
- Для ручного оверрайда capabilities можно использовать env:
  - `AGENT_HAS_GPU=true`
  - `AGENT_HAS_GROMACS=true`
