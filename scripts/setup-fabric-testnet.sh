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

# 1. Скачать Fabric и samples (с CA для регистрации пользователей)
if [ ! -d "fabric-samples" ]; then
    echo "==> Downloading Fabric $FABRIC_VERSION and samples (CA mode)..."
    curl -sSLO "https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh"
    bash install-fabric.sh docker samples binary -f "${FABRIC_VERSION}.14"
    rm -f install-fabric.sh
else
    echo "==> fabric-samples already exists, skipping download"
    # fabric-ca-client нужен для CA mode (регистрация пользователей)
    if ! command -v fabric-ca-client &>/dev/null && [ ! -f "fabric-samples/bin/fabric-ca-client" ]; then
        echo "==> Installing Fabric CA binaries (NTFS workaround: install to /tmp, then copy)..."
        INSTALL_DIR="/tmp/fabric-ca-install-$$"
        mkdir -p "$INSTALL_DIR" && cd "$INSTALL_DIR"
        curl -sSLO "https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh"
        bash install-fabric.sh binary -f "${FABRIC_VERSION}.14"
        mkdir -p "$PROJECT_ROOT/fabric-samples/bin"
        cp -f bin/fabric-ca-* "$PROJECT_ROOT/fabric-samples/bin/" 2>/dev/null || cp -f bin/* "$PROJECT_ROOT/fabric-samples/bin/"
        cd "$PROJECT_ROOT" && rm -rf "$INSTALL_DIR"
    fi
fi

# 2. Проверка
if [ ! -d "fabric-samples/test-network" ]; then
    echo "ERROR: fabric-samples/test-network not found"
    exit 1
fi

cd fabric-samples/test-network

# Fix CRLF in all Fabric scripts and configs (needed on Windows/WSL with NTFS)
python3 -c "
import pathlib
for ext in ('*.sh', '*.config'):
    for p in pathlib.Path('.').rglob(ext):
        if p.is_file():
            p.write_text(p.read_text().replace(chr(13), ''))
" 2>/dev/null || true

# 3. Остановить старую сеть (если была)
./network.sh down 2>/dev/null || true

# 4. Поднять сеть (CA mode — регистрация пользователей через fabric-ca-client)
echo "==> Starting Fabric test network (CA mode)..."
./network.sh up -ca

# 5. Создать канал
echo "==> Creating channel: $CHANNEL_NAME"
./network.sh createChannel -c "$CHANNEL_NAME" -ca

echo ""
echo "==> Fabric testnet is ready (CA mode)"
echo "    Channel: $CHANNEL_NAME"
echo "    To deploy DSCM chaincode:"
echo "      cd fabric-samples/test-network"
echo "      ./network.sh deployCC -ccn dscm -ccp ../../chaincode -ccl javascript -c $CHANNEL_NAME -ca"
echo ""
