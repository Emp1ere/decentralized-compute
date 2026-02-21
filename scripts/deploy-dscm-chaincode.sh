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

echo "==> Deploying DSCM chaincode to channel $CHANNEL_NAME"
./network.sh deployCC -ccn dscm -ccp "$CHAINCODE_PATH" -ccl javascript -c "$CHANNEL_NAME" -ca

echo "==> Chaincode deployed. Invoke with: peer chaincode invoke ... -C $CHANNEL_NAME -n dscm -c '{\"function\":\"listContract\",\"Args\":[\"...\"]}'"
