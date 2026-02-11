#!/usr/bin/env python3
"""
Скрипт для обнуления прогресса контрактов и балансов вычислителей.

ВНИМАНИЕ: Этот скрипт удаляет все блоки кроме genesis, что приведёт к:
- Обнулению всех балансов вычислителей
- Обнулению прогресса выполнения контрактов
- Удалению всех транзакций (reward и work_receipt)

Пользователи (users.json) сохраняются, но их балансы будут 0 после пересчёта.
"""

import json
import os
import sys
from pathlib import Path

# Путь к файлу блокчейна
SCRIPT_DIR = Path(__file__).parent
CHAIN_FILE = SCRIPT_DIR / "orchestrator_node" / "data" / "chain.json"
BACKUP_FILE = SCRIPT_DIR / "orchestrator_node" / "data" / "chain.json.backup"

def create_genesis_block():
    """
    Создание genesis-блока (тот же код, что в blockchain.py).
    Genesis блок имеет фиксированную структуру для одинакового хеша на всех узлах.
    """
    import hashlib
    
    genesis_dict = {
        "index": 0,
        "timestamp": 0,
        "transactions": [],
        "previous_hash": "0",
        "nonce": 0
    }
    
    # Вычисляем хеш genesis-блока (тот же алгоритм, что в Block.calculate_hash)
    block_string = json.dumps(genesis_dict, sort_keys=True)
    genesis_hash = hashlib.sha256(block_string.encode()).hexdigest()
    genesis_dict["hash"] = genesis_hash
    
    return genesis_dict

def reset_blockchain():
    """
    Обнуление блокчейна: оставляет только genesis блок.
    Создаёт резервную копию перед изменением.
    """
    print("=" * 60)
    print("  ОБНУЛЕНИЕ БЛОКЧЕЙНА")
    print("=" * 60)
    print()
    
    # Проверяем существование файла
    if not CHAIN_FILE.exists():
        print(f"❌ Файл блокчейна не найден: {CHAIN_FILE}")
        print("   Блокчейн уже пуст или файл находится в другом месте.")
        return False
    
    # Загружаем текущий блокчейн для информации
    try:
        with open(CHAIN_FILE, 'r', encoding='utf-8') as f:
            current_chain = json.load(f)
        
        if not isinstance(current_chain, list) or len(current_chain) == 0:
            print("❌ Файл блокчейна пуст или имеет неверный формат.")
            return False
        
        blocks_count = len(current_chain)
        print(f"📊 Текущее состояние:")
        print(f"   Блоков в цепочке: {blocks_count}")
        
        # Подсчитываем транзакции
        total_transactions = 0
        reward_transactions = 0
        work_receipt_transactions = 0
        unique_clients = set()
        
        for block in current_chain:
            if isinstance(block, dict) and "transactions" in block:
                transactions = block.get("transactions", [])
                total_transactions += len(transactions)
                for tx in transactions:
                    tx_type = tx.get("type", "")
                    if tx_type == "reward":
                        reward_transactions += 1
                        to_addr = tx.get("to", "")
                        if to_addr:
                            unique_clients.add(to_addr)
                    elif tx_type == "work_receipt":
                        work_receipt_transactions += 1
                        client_id = tx.get("client_id", "")
                        if client_id:
                            unique_clients.add(client_id)
        
        print(f"   Всего транзакций: {total_transactions}")
        print(f"   Reward транзакций: {reward_transactions}")
        print(f"   Work receipt транзакций: {work_receipt_transactions}")
        print(f"   Уникальных вычислителей: {len(unique_clients)}")
        print()
        
    except Exception as e:
        print(f"⚠️  Не удалось прочитать текущий блокчейн: {e}")
        print("   Продолжаем сброс...")
        print()
    
    # Создаём резервную копию
    try:
        import shutil
        shutil.copy2(CHAIN_FILE, BACKUP_FILE)
        print(f"✅ Резервная копия создана: {BACKUP_FILE}")
    except Exception as e:
        print(f"⚠️  Не удалось создать резервную копию: {e}")
        response = input("   Продолжить без резервной копии? (yes/no): ")
        if response.lower() != "yes":
            print("❌ Операция отменена.")
            return False
    
    # Создаём новый блокчейн только с genesis блоком
    genesis_block = create_genesis_block()
    new_chain = [genesis_block]
    
    # Сохраняем новый блокчейн
    try:
        with open(CHAIN_FILE, 'w', encoding='utf-8') as f:
            json.dump(new_chain, f, ensure_ascii=False, indent=2)
        
        print()
        print("✅ Блокчейн успешно обнулён!")
        print(f"   Оставлен только genesis блок (index=0)")
        print(f"   Все балансы и прогресс контрактов обнулены")
        print()
        print("📝 Следующие шаги:")
        print("   1. Перезапустите систему: docker-compose restart")
        print("   2. Или пересоберите: docker-compose down && docker-compose up -d")
        print("   3. Проверьте балансы в интерфейсе - они должны быть 0")
        print()
        print(f"💾 Резервная копия сохранена: {BACKUP_FILE}")
        print("   Для восстановления переименуйте backup в chain.json")
        
        return True
        
    except Exception as e:
        print(f"❌ Ошибка при сохранении нового блокчейна: {e}")
        # Пытаемся восстановить из резервной копии
        if BACKUP_FILE.exists():
            try:
                import shutil
                shutil.copy2(BACKUP_FILE, CHAIN_FILE)
                print(f"✅ Восстановлено из резервной копии")
            except Exception as restore_error:
                print(f"❌ Не удалось восстановить из резервной копии: {restore_error}")
        return False

if __name__ == "__main__":
    print()
    print("⚠️  ВНИМАНИЕ: Этот скрипт удалит все блоки кроме genesis!")
    print("   Это приведёт к обнулению всех балансов и прогресса контрактов.")
    print()
    response = input("Продолжить? (yes/no): ")
    
    if response.lower() != "yes":
        print("❌ Операция отменена.")
        sys.exit(0)
    
    print()
    success = reset_blockchain()
    
    if success:
        print()
        print("=" * 60)
        print("  ОБНУЛЕНИЕ ЗАВЕРШЕНО УСПЕШНО")
        print("=" * 60)
        sys.exit(0)
    else:
        print()
        print("=" * 60)
        print("  ОШИБКА ПРИ ОБНУЛЕНИИ")
        print("=" * 60)
        sys.exit(1)
