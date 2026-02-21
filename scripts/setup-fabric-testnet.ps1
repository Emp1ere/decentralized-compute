# Phase 0: Fabric testnet для DSCM (PowerShell)
# Требует: Docker, Git. Запуск: powershell -ExecutionPolicy Bypass -File setup-fabric-testnet.ps1

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ChannelName = if ($env:FABRIC_CHANNEL) { $env:FABRIC_CHANNEL } else { "public-marketplace" }

Set-Location $ProjectRoot

Write-Host "==> DSCM Fabric Testnet Setup" -ForegroundColor Cyan
Write-Host "    Project: $ProjectRoot"
Write-Host "    Channel: $ChannelName"
Write-Host ""

if (-not (Test-Path "fabric-samples")) {
    Write-Host "==> Downloading Fabric and samples..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh" -OutFile "install-fabric.sh" -UseBasicParsing
    # Bash required - use Git Bash or WSL
    $bash = Get-Command bash -ErrorAction SilentlyContinue
    if ($bash) {
        bash install-fabric.sh docker samples binary
        Remove-Item install-fabric.sh -Force
    } else {
        Write-Host "ERROR: bash not found. Install Git for Windows or use WSL, then run:" -ForegroundColor Red
        Write-Host "  ./scripts/setup-fabric-testnet.sh"
        exit 1
    }
} else {
    Write-Host "==> fabric-samples already exists" -ForegroundColor Green
}

if (-not (Test-Path "fabric-samples/test-network")) {
    Write-Host "ERROR: fabric-samples/test-network not found" -ForegroundColor Red
    exit 1
}

Set-Location "fabric-samples/test-network"

Write-Host "==> Stopping any existing network..." -ForegroundColor Yellow
try { bash network.sh down 2>$null } catch {}

Write-Host "==> Starting Fabric test network (CA mode)..." -ForegroundColor Yellow
bash network.sh up -ca

Write-Host "==> Creating channel: $ChannelName" -ForegroundColor Yellow
bash network.sh createChannel -c $ChannelName -ca

Write-Host ""
Write-Host "==> Fabric testnet is ready" -ForegroundColor Green
Write-Host "    Channel: $ChannelName"
Write-Host "    Deploy chaincode: bash scripts/deploy-dscm-chaincode.sh"
