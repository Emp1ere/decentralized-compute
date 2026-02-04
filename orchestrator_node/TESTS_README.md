# Запуск тестов

## Если PowerShell выдаёт ошибку (кодировка, путь с кириллицей)

Используйте один из способов ниже.

### 1. BAT-файл (проще всего)

- Из **корня проекта**: запустите **`run_tests.bat`** (двойной щелчок или из cmd: `run_tests.bat`).
- Из папки **orchestrator_node**: запустите **`run_tests.bat`**.

Скрипт сам перейдёт в нужную папку, установит зависимости и запустит pytest.

### 2. Командная строка (cmd.exe)

1. Откройте **cmd** (Win+R → `cmd` → Enter).
2. Перейдите в папку оркестратора:
   ```text
   cd /d "C:\Users\Alexandra\OneDrive\Рабочий стол\Прогер\distributed-compute\orchestrator_node"
   ```
   (подставьте свой путь, если проект лежит в другом месте).
3. Выполните:
   ```text
   pip install -r requirements-test.txt
   python -m pytest tests/ -v
   ```

### 3. Путь без кириллицы

Если ошибки связаны с русскими буквами в пути:

- Скопируйте проект в каталог без кириллицы, например: `C:\dc`.
- В cmd выполните:
  ```text
  cd /d C:\dc\distributed-compute\orchestrator_node
  pip install -r requirements-test.txt
  python -m pytest tests/ -v
  ```

### 4. Из IDE (Cursor / VS Code)

- Откройте терминал в IDE и выберите **Command Prompt** или **cmd** вместо PowerShell (если доступно).
- Либо в интегрированном терминале выполните:
  ```text
  cd orchestrator_node
  python -m pytest tests/ -v
  ```
  (рабочая папка должна быть корень проекта).

### С покрытием кода

```text
python -m pytest tests/ -v --cov=. --cov-report=term-missing
```
