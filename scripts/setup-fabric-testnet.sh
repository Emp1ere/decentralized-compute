#!/usr/bin/env bash
#
# Phase 0: Развёртывание Fabric testnet для DSCM
# Требует: Docker, Git, curl
#
# Git Bash/Windows: отключаем преобразование путей (иначе /var -> C:\Program Files\Git\var)
export MSYS_NO_PATHCONV=1
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

FABRIC_VERSION="${FABRIC_VERSION:-2.5}"
CHANNEL_NAME="${FABRIC_CHANNEL:-public-marketplace}"

echo "==> DSCM Fabric Testnet Setup"
echo "    Project: $PROJECT_ROOT"
echo "    Channel: $CHANNEL_NAME"
echo ""

# 1. Скачать Fabric и samples
if [ ! -d "fabric-samples" ]; then
    echo "==> Downloading Fabric $FABRIC_VERSION and samples..."
    curl -sSLO "https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh"
    chmod +x install-fabric.sh
    ./install-fabric.sh docker samples binary -f "${FABRIC_VERSION}.14"
    rm -f install-fabric.sh
else
    echo "==> fabric-samples already exists, skipping download"
fi

# 2. Проверка
if [ ! -d "fabric-samples/test-network" ]; then
    echo "ERROR: fabric-samples/test-network not found"
    exit 1
fi

cd fabric-samples/test-network

# 3. Остановить старую сеть (если была)
./network.sh down 2>/dev/null || true

# 4. Поднять сеть с CA
echo "==> Starting Fabric test network (CA mode)..."
./network.sh up -ca

# 5. Создать канал
echo "==> Creating channel: $CHANNEL_NAME"
./network.sh createChannel -c "$CHANNEL_NAME" -ca

echo ""
echo "==> Fabric testnet is ready"
echo "    Channel: $CHANNEL_NAME"
echo "    To deploy DSCM chaincode:"
echo "      cd fabric-samples/test-network"
echo "      ./network.sh deployCC -ccn dscm -ccp ../../chaincode -ccl javascript -c $CHANNEL_NAME -ca"
echo ""
