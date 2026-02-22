#!/usr/bin/env bash
#
# Деплой DSCM chaincode в Fabric testnet
# Запускать после setup-fabric-testnet.sh
#
export MSYS_NO_PATHCONV=1
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# Path from test-network to chaincode (test-network is in fabric-samples/)
CHAINCODE_PATH="$(cd "$PROJECT_ROOT" && pwd)/chaincode"
CHANNEL_NAME="${FABRIC_CHANNEL:-public-marketplace}"

if [ ! -d "$PROJECT_ROOT/fabric-samples/test-network" ]; then
    echo "ERROR: Run setup-fabric-testnet.sh first"
    exit 1
fi

cd "$PROJECT_ROOT/fabric-samples/test-network"

# WSL2: localhost не доходит до Docker. Добавляем hostnames в /etc/hosts для TLS (сертификаты для hostname, не IP)
if grep -qi microsoft /proc/version 2>/dev/null; then
  HOST_IP=$(ip route show 2>/dev/null | grep -i default | awk '{print $3}' | head -1)
  if [ -z "$HOST_IP" ] || [[ "$HOST_IP" =~ ^(8\.8\.|1\.1\.|127\.) ]]; then
    HOST_IP=$(grep nameserver /etc/resolv.conf 2>/dev/null | head -1 | awk '{print $2}')
  fi
  if [ -n "$HOST_IP" ] && [[ ! "$HOST_IP" =~ ^(8\.8\.|1\.1\.|127\.) ]]; then
    FABRIC_HOSTS="peer0.org1.example.com peer0.org2.example.com orderer.example.com"
    if ! grep -q "peer0.org1.example.com" /etc/hosts 2>/dev/null; then
      echo "==> WSL2: adding Fabric hostnames to /etc/hosts (sudo required)"
      echo "$HOST_IP $FABRIC_HOSTS" | sudo tee -a /etc/hosts >/dev/null || true
    fi
    if grep -q "peer0.org1.example.com" /etc/hosts 2>/dev/null; then
      export FABRIC_PEER_HOST_ORG1="peer0.org1.example.com"
      export FABRIC_PEER_HOST_ORG2="peer0.org2.example.com"
      export FABRIC_PEER_HOST="peer0.org1.example.com"
      export ORDERER_ADDRESS="orderer.example.com:7050"
      echo "==> WSL2: using hostnames for TLS ($HOST_IP -> $FABRIC_HOSTS)"
    else
      export FABRIC_PEER_HOST="$HOST_IP"
      echo "==> WSL2: using host IP $HOST_IP (TLS may fail - add hosts manually)"
    fi
  fi
fi

# peer lifecycle требует config (core.yaml), не configtx
export FABRIC_CFG_PATH="$PROJECT_ROOT/fabric-samples/config"

# Обход "too_many_pings" / ENHANCE_YOUR_CALM при долгой установке chaincode
export GRPC_GO_KEEPALIVE_MIN_TIME=60
export GRPC_GO_KEEPALIVE_INTERVAL=60

echo "==> Deploying DSCM chaincode to channel $CHANNEL_NAME"
./network.sh deployCC -ccn dscm -ccp "$CHAINCODE_PATH" -ccl javascript -c "$CHANNEL_NAME" -ca

echo "==> Chaincode deployed. Invoke with: peer chaincode invoke ... -C $CHANNEL_NAME -n dscm -c '{\"function\":\"listContract\",\"Args\":[\"...\"]}'"
