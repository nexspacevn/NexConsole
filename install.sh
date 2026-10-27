#!/bin/bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "================================================================================"
echo "       NEXCONSOLE - AUTOMATED INSTALLATION & SETUP"
echo "================================================================================"

# 1. Check build dependencies
echo "[1/4] Checking build environment (Rust & OpenSSL)..."
if [ -f "$HOME/.cargo/env" ]; then
    source "$HOME/.cargo/env"
fi

if ! command -v cargo &> /dev/null; then
    echo "[!] Rust/Cargo is not installed. Please install Rust via: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

# 2. Build release binary
echo "[2/4] Building optimized release binary..."
cargo build --release

# 3. Create .env if not exists
if [ ! -f .env ]; then
    echo "[3/4] Initializing environment configuration (.env)..."
    JWT_RANDOM=$(openssl rand -hex 24 2>/dev/null || head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 32)
    
    DETECTED_SSH_PORT=$(netstat -tlpn 2>/dev/null | grep sshd | awk '{print $4}' | awk -F':' '{print $NF}' | head -n 1 || echo "22")
    if [ -z "$DETECTED_SSH_PORT" ]; then
        DETECTED_SSH_PORT="22"
    fi

    cat <<EOF > .env
BIND_HOST=127.0.0.1
PORT=7681
JWT_SECRET=${JWT_RANDOM}
LAYER1_USER=admin
SSH_HOST=127.0.0.1
SSH_PORT=${DETECTED_SSH_PORT}
TERMINAL_IDLE_TIMEOUT_SECS=1800
EOF
fi

# Secure sensitive configuration and database permissions (owner read/write only)
chmod 600 "$DIR/.env" "$DIR/servers.db" "$DIR/passkeys.json" 2>/dev/null || true

# 4. Generate secure random admin password
chmod +x "$DIR/nexctl"
EXISTING_PASS=$(grep "^LAYER1_PASS=" .env 2>/dev/null | cut -d'=' -f2- | tr -d '"' | tr -d "'" || true)
if [ -n "$EXISTING_PASS" ] && [ -f "$DIR/nexconsole.db" ]; then
    echo "[4/4] Preserving existing admin credentials..."
    ADMIN_PASS="$EXISTING_PASS"
else
    echo "[4/4] Generating secure random credentials for admin..."
    OUTPUT=$("$DIR/nexctl" random-admin admin)
    ADMIN_PASS=$(echo "$OUTPUT" | grep "Password:" | awk -F': ' '{print $2}' | xargs)
fi

# Ensure permissions after initial credential generation
chmod 600 "$DIR/.env" "$DIR/servers.db" "$DIR/passkeys.json" 2>/dev/null || true

# 5. Service management
echo "[*] Initializing NexConsole service..."
SERVICE_STATUS="Running"

if [ -d "/etc/systemd/system" ] && [ "$(id -u)" -eq 0 ]; then
    cat <<EOF > /etc/systemd/system/nexconsole.service
[Unit]
Description=NexConsole Web Terminal Gateway
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$DIR
ExecStart=$DIR/target/release/nexconsole
Restart=always
RestartSec=3
LimitNOFILE=65535

# Security Sandboxing & Least Privilege
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictRealtime=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable nexconsole
    systemctl restart nexconsole
    SERVICE_STATUS="Systemd Service (nexconsole.service)"
else
    # Terminate any previously running instance
    pkill -f "$DIR/target/release/nexconsole" 2>/dev/null || true
    sleep 1
    nohup "$DIR/target/release/nexconsole" > "$DIR/nexconsole.log" 2>&1 &
    SERVICE_STATUS="Background Process (PID: $!)"
fi

# Detect external or primary local IP address
SERVER_IP=$(ip -4 addr show scope global 2>/dev/null | grep inet | awk '{print $2}' | cut -d/ -f1 | head -n 1)
if [ -z "$SERVER_IP" ]; then
    SERVER_IP=$(ifconfig 2>/dev/null | grep -E "inet " | grep -v 127.0.0.1 | awk '{print $2}' | head -n 1)
fi
if [ -z "$SERVER_IP" ]; then
    SERVER_IP="localhost"
fi

PORT_VAL=$(grep "^PORT=" .env | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "7681")
if [ -z "$PORT_VAL" ]; then
    PORT_VAL="7681"
fi

echo ""
echo "================================================================================"
echo "       NEXCONSOLE LOGIN CREDENTIALS"
echo "================================================================================"
echo "  Url:       http://$SERVER_IP:$PORT_VAL  (or http://localhost:$PORT_VAL)"
echo "  Username:  admin"
echo "  Password:  $ADMIN_PASS"
echo "================================================================================"
echo "  Service Status: $SERVICE_STATUS"
echo "  Admin CLI:      ./nexctl --help"
echo "================================================================================"
echo "  Notice: Password has been hashed and saved to SQLite + .env. Please save this!"
echo "================================================================================"
