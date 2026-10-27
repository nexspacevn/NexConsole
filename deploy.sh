#!/bin/bash
set -e

SERVER_IP="${DEPLOY_HOST:-your-server-ip}"
SERVER_PORT="${DEPLOY_PORT:-22}"
REMOTE_DIR="/app/nexconsole"

if [ -z "${SERVER_PASS:-}" ] && [ -n "${DEPLOY_PASS:-}" ]; then
    SERVER_PASS="$DEPLOY_PASS"
fi

if [ -z "${SERVER_PASS:-}" ]; then
    read -s -p "Enter SSH password for root@$SERVER_IP:$SERVER_PORT: " SERVER_PASS
    echo ""
fi

echo "================================================================================"
echo "       NEXCONSOLE - REMOTE SERVER DEPLOYMENT ($SERVER_IP)"
echo "================================================================================"

# 1. Stop legacy or currently running service on remote server
echo "[1/4] Stopping previous service instances on remote server..."
sshpass -p "$SERVER_PASS" ssh -p $SERVER_PORT -o StrictHostKeyChecking=no root@$SERVER_IP "pm2 delete webconsole 2>/dev/null || true; pm2 save 2>/dev/null || true; systemctl stop nexconsole.service 2>/dev/null || true; pkill -f nexconsole 2>/dev/null || true" || true

# 2. Prepare remote directory structure
echo "[2/4] Preparing remote directory structure at $REMOTE_DIR..."
sshpass -p "$SERVER_PASS" ssh -p $SERVER_PORT -o StrictHostKeyChecking=no root@$SERVER_IP "mkdir -p $REMOTE_DIR/public $REMOTE_DIR/src"

# 3. Synchronize modern Rust source files and web assets
echo "[3/4] Synchronizing source code, configurations, and assets..."
sshpass -p "$SERVER_PASS" scp -P $SERVER_PORT -o StrictHostKeyChecking=no Cargo.toml Cargo.lock install.sh nexctl root@$SERVER_IP:$REMOTE_DIR/
sshpass -p "$SERVER_PASS" scp -P $SERVER_PORT -o StrictHostKeyChecking=no src/main.rs root@$SERVER_IP:$REMOTE_DIR/src/
sshpass -p "$SERVER_PASS" scp -r -P $SERVER_PORT -o StrictHostKeyChecking=no public/* root@$SERVER_IP:$REMOTE_DIR/public/

# 4. Execute installation and setup on remote server
echo "[4/4] Executing remote automated build and service initialization..."
sshpass -p "$SERVER_PASS" ssh -p $SERVER_PORT -o StrictHostKeyChecking=no root@$SERVER_IP "source ~/.cargo/env 2>/dev/null; cd $REMOTE_DIR && chmod +x install.sh nexctl && ./install.sh"

echo "================================================================================"
echo "       REMOTE DEPLOYMENT SUCCESSFUL"
echo "================================================================================"
echo "  Direct Gateway: http://$SERVER_IP:7681"
echo "================================================================================"
