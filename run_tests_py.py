#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Временный скрипт для запуска тестов (обход проблемы с кириллицей в PowerShell)."""
import os
import sys
import subprocess

# Переходим в директорию orchestrator_node
script_dir = os.path.dirname(os.path.abspath(__file__))
orchestrator_dir = os.path.join(script_dir, "orchestrator_node")
os.chdir(orchestrator_dir)

# Устанавливаем зависимости для тестов
print("Installing test dependencies...")
subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements-test.txt", "-q"], check=False)

# Запускаем тесты
print("\nRunning tests...")
result = subprocess.run([sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short"])
sys.exit(result.returncode)
