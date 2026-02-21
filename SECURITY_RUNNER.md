# Безопасность Docker-раннеров

**Контекст:** DSCM v2, ТЗ раздел 6

## Обязательные меры

| Мера | Описание |
|------|----------|
| `--network=none` | Изоляция сети; whitelist при необходимости |
| `--read-only` rootfs | Root только для чтения |
| `/tmp` tmpfs | Временные файлы в tmpfs |
| Seccomp profile | Ограничение системных вызовов |
| `uid=65534` (nobody) | Запуск от непривилегированного пользователя |
| Image whitelist | Только разрешённые образы |
| Resource limits | CPU, memory, timeout |
| Audit log | Логирование всех запусков |

## Реализация

```bash
docker run \
  --network=none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=512m \
  --security-opt seccomp=runner-seccomp.json \
  --user 65534:65534 \
  --cpus=2 \
  --memory=4g \
  --rm \
  <image> <entry_point> <args>
```

## Seccomp profile

Минимальный набор: `read`, `write`, `open`, `close`, `mmap`, `mprotect`, `munmap`, `brk`, `exit_group`, `futex`. Исключены: `network`, `mount`, `ptrace`, `chmod`, `chown`.

## Текущий статус

- **MVP:** Python subprocess (desktop_agent/runners.py) — без Docker
- **Phase 3:** Docker-раннер с перечисленными флагами
- **Phase 4:** Verification + Security, redundancy 3x, challenge 24ч
