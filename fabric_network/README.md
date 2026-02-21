# Fabric Testnet для DSCM

Phase 0: развёртывание Hyperledger Fabric 2.5+ test-network.

## Требования

- Docker и Docker Compose
- Git
- curl
- Bash (на Windows: Git Bash или WSL)

## Быстрый старт

```bash
# Из корня проекта
./scripts/setup-fabric-testnet.sh
```

Скрипт:
1. Скачивает Fabric 2.5 и fabric-samples
2. Поднимает test-network (2 org, Raft ordering)
3. Создаёт канал `public-marketplace`
4. Опционально деплоит chaincode

## Ручная установка

### 1. Установка Fabric

```bash
curl -sSLO https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh
chmod +x install-fabric.sh
./install-fabric.sh docker samples binary
```

### 2. Запуск сети

```bash
cd fabric-samples/test-network
./network.sh up -ca
```

### 3. Создание канала DSCM

```bash
./network.sh createChannel -c public-marketplace -ca
```

### 4. Деплой chaincode (опционально)

```bash
./network.sh deployCC -ccn dscm -ccp ../../chaincode -ccl javascript -c public-marketplace -ca
```

## Каналы DSCM

| Канал | Назначение |
|-------|------------|
| public-marketplace | Публичный маркетплейс контрактов |
| private-science | Приватные научные контракты (Phase 1+) |

## Подключение Sidecar

### Windows (bat)

1. **Запуск Fabric** (один раз): `run_fabric_setup.bat`
2. **Деплой chaincode** (один раз): `run_fabric_deploy.bat`
3. **Sidecar с Fabric**: `run_fabric_sidecar.bat` — задаёт env и запускает Sidecar
4. **Тест** (в другом терминале): `run_fabric_test.bat`

### Переменные окружения

```
FABRIC_CRYPTO_PATH=<путь к fabric-samples/test-network/organizations/peerOrganizations/org1.example.com>
FABRIC_PEER_ENDPOINT=localhost:7051
FABRIC_CHANNEL=public-marketplace
FABRIC_CHAINCODE_NAME=dscm
```

`run_fabric_sidecar.bat` задаёт их автоматически.

## Остановка

```bash
cd fabric-samples/test-network
./network.sh down
```

## Troubleshooting

**Sidecar: connection refused / TLS error** — убедитесь, что Fabric запущен (`docker ps` показывает контейнеры peer, orderer). При ошибках TLS добавьте в `C:\Windows\System32\drivers\etc\hosts`:
```
127.0.0.1 peer0.org1.example.com
```
и используйте `FABRIC_PEER_ENDPOINT=peer0.org1.example.com:7051`.
