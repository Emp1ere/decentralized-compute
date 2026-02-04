# Общие фикстуры и настройки pytest
import os
import sys

# Корень пакета оркестратора (для импортов)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# В тестах не дергаем внешний пир
os.environ.setdefault("PEER_URL", "")
os.environ.setdefault("NODE_SECRET", "")
