# NexConsole - High-Performance Secure Web Terminal Gateway

**Language:** [English](README_EN.md) | [Tieng Viet](README.md)

---

## 1. Project Overview

NexConsole is an enterprise-grade, high-performance Web Terminal Gateway written natively in **Rust** using the asynchronous **Tokio 1.38** runtime and **Axum 0.7** framework. It creates a secure bridge between modern web browsers and remote Linux shell environments via encrypted WebSockets and interactive SSH PTY streams.

NexConsole is designed with a Zero-Trust architecture featuring two independent security layers:
- **Layer 1 (Perimeter Gateway)**: Web application access control supporting traditional passwords, FIDO2 biometric Passkeys (Touch ID, Face ID, YubiKey), and RFC 6238 TOTP two-factor authentication (Google Authenticator, Authy).
- **Layer 2 (Linux OS Shell)**: Interactive PTY terminal session (`xterm-256color`) directly authenticated against the target Linux operating system via OpenSSH.

The gateway features an embedded AES-256 encrypted SQLite database for server profiles, real-time hardware telemetry streaming (CPU, RAM, Uptime), a customizable Quick Commands bar, comprehensive internationalization (English & Vietnamese), and a responsive mobile-first interface.

---

## 2. Key Technical Features

- **Pure Rust Backend**:
  - Built on Axum 0.7, Tokio, and ssh2-rs.
  - Sub-30MB RAM footprint during standard operation.
  - Zero garbage collection pauses, delivering minimal latency for terminal keystrokes.

- **Two-Layer Independent Security**:
  - Layer 1: Secure JWT sessions, salted password hashing, FIDO2 WebAuthn Passkeys, and RFC 6238 TOTP two-factor authentication.
  - Layer 2: Real PTY allocation directly attached to the target host's OpenSSH daemon.

- **Modern Terminal Experience**:
  - Xterm.js v5 engine with WebLinks and Fit Addons for responsive resizing.
  - Full 256-color ANSI support for demanding CLI applications such as `vim`, `nano`, `htop`, and `tmux`.
  - Configurable font scaling, fullscreen toggle, and terminal shortcuts.

- **Embedded SQLite Server Directory**:
  - Stores server connection profiles in `servers.db`.
  - Credentials encrypted at rest using AES-256-GCM.

- **Real-Time Telemetry Streaming**:
  - Live system stats (RAM usage, CPU load, and system uptime) streamed continuously over WebSocket.

- **Interactive Quick Commands Bar**:
  - One-click action chips for commonly used maintenance commands (`htop`, `pm2 list`, `docker ps`, `df -h`, `free -h`).
  - Customizable and reorderable via the Account settings portal.

- **Complete Internationalization (i18n)**:
  - Instant runtime switching between English (default) and Vietnamese without page reloading.
  - Selections automatically persisted in browser localStorage.

- **Mobile-First Responsive Interface**:
  - Slide-out drawer navigation with darkened backdrop and tap-to-close behavior.
  - Horizontally scrollable command chips with smooth touch inertia.
  - Dynamic 100dvh viewport height to prevent virtual keyboard cutoff.
  - 16px form inputs to prevent unwanted iOS Safari zooming.

- **Host CLI Administration Tool (`nexctl`)**:
  - Allows server operators to manage accounts directly from the host console without using the web UI.

---

## 3. Architecture & Data Flow

```text
+-------------------------------------------------------------------------+
|                              CLIENT BROWSER                             |
|  +-------------------------+  +---------------------------------------+ |
|  | Modern Desktop View     |  | Touch-Optimized Mobile View (100dvh)  | |
|  | - Xterm.js v5 Terminal  |  | - Slide-out Drawer & Backdrop         | |
|  | - Glassmorphism UI      |  | - Touch-Scroll Quick Command Chips    | |
|  | - Language Switcher     |  | - Segmented Settings Tabs             | |
|  +-------------------------+  +---------------------------------------+ |
+------------------------------------+------------------------------------+
                                     |
                          HTTPS / WSS (Port 7681)
                                     |
+------------------------------------v------------------------------------+
|                         NEXCONSOLE GATEWAY (RUST)                       |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  | Layer 1: Perimeter Security Engine                                |  |
|  | - JWT Session Authentication & Token Verification                 |  |
|  | - WebAuthn / FIDO2 Authenticator (Touch ID, Face ID, Security Key)|  |
|  | - TOTP Multi-Factor Authentication (RFC 6238)                     |  |
|  | - Rate-Limiting & Brute-Force Defense                             |  |
|  +-------------------------------------------------------------------+  |
|                                                                         |
|  +-------------------+  +---------------------+  +-------------------+  |
|  | Axum HTTP Server  |  | WebSocket Bridge    |  | Embedded SQLite   |  |
|  | - Static Assets   |  | - Binary PTY Stream |  | - User Accounts   |  |
|  | - REST API Router |  | - Window Resizing   |  | - Server Profiles |  |
|  | - System Telemetry|  | - Raw Keypresses    |  | - AES-256 Storage |  |
|  +-------------------+  +---------------------+  +-------------------+  |
+------------------------------------+------------------------------------+
                                     |
                             SSH2 TCP Channel
                                     |
+------------------------------------v------------------------------------+
|                       TARGET LINUX HOST / SERVER                        |
|  - OpenSSH Daemon (SSHD)                                                |
|  - Interactive Shell / PTY Allocation (Bash, Zsh)                       |
|  - Target Host Hardware & Containers                                    |
+-------------------------------------------------------------------------+
```

---

## 4. Directory Structure

```text
nexconsole/
|-- Cargo.toml              # Rust crate manifest and dependencies
|-- Cargo.lock              # Locked dependency versions
|-- src/
|   `-- main.rs             # Core server: Axum HTTP, WebSocket SSH, SQLite, WebAuthn, CLI
|-- nexctl                  # Administrative CLI wrapper script
|-- servers.db              # Embedded SQLite database (accounts, servers, settings)
|-- passkeys.json           # WebAuthn / FIDO2 credential store
|-- deploy.sh               # Remote deployment automation script
|-- .env                    # Environment variables and security configurations
|-- public/                 # Web client static assets
|   |-- index.html          # Gateway web page: Login view & Terminal console
|   |-- style.css           # Dark Cyberpunk / Glassmorphic UI styling
|   |-- app.js              # Client terminal logic: Xterm.js & WebSocket handler
|   |-- i18n.js             # Internationalization dictionaries (EN & VI)
|   |-- favicon.svg         # Primary vector SVG favicon
|   |-- favicon.ico         # Legacy favicon fallback
|   |-- qrcode.min.js       # Client-side QR generator for TOTP setup
|   `-- account/            # Account & Security Hub
|       |-- index.html      # Password, 2FA, Passkey, and Repeater management
|       |-- style.css       # Dedicated account portal styles
|       `-- account.js      # Account management and WebAuthn client logic
|-- README_EN.md            # Standalone English documentation
`-- README.md               # Bilingual project documentation
```

---

## 5. Configuration (`.env`)

Configure the application by creating or editing `.env` in the project root:

```ini
# Gateway HTTP/WebSocket binding port
PORT=7681

# Cryptographic secret for signing JWT session tokens
JWT_SECRET=nexconsole_super_secret_jwt_key_example_change_me

# Default Master Gateway User (Fallback when database is uninitialized)
LAYER1_USER=admin
LAYER1_PASS="AdminSecurePassword123!"

# Default SSH Target Host and Port
SSH_HOST=127.0.0.1
SSH_PORT=22
```

---

## 6. Command-Line Administration (`nexctl`)

Manage accounts directly on the host machine without web access:

```bash
# Display administrative help
./nexctl --help

# List all registered user accounts
./nexctl list

# Add a new user or update credentials
./nexctl add <username> <password> [display_name] [email]

# Change an existing user's password (minimum 6 characters)
./nexctl passwd <username> <new_password>

# Update a user's registered email
./nexctl email <username> <new_email>

# Disable Two-Factor Authentication (TOTP) for an account
./nexctl disable-2fa <username>

# Clear all registered Touch ID / Passkeys for a user
./nexctl clear-passkeys <username>

# Delete a user account
./nexctl delete <username>
```

---

## 7. Installation and Local Development

### Prerequisites
- Rust compiler and toolchain (version 1.75+)
- OpenSSL development packages (`libssl-dev` on Debian/Ubuntu, `openssl` via Homebrew on macOS)
- Standard C compiler and CMake

### Build and Run

```bash
# Navigate to the project directory
cd /path/to/nexconsole

# Build optimized release binary
cargo build --release

# Run the release binary
./target/release/nexconsole
```

The gateway will listen on `http://localhost:7681`.

---

## 8. Production Deployment

1. Set up a systemd service (`/etc/systemd/system/nexconsole.service`):

```ini
[Unit]
Description=NexConsole Web Terminal Gateway
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/app/nexconsole
ExecStart=/app/nexconsole/target/release/nexconsole
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

2. Enable and start:
```bash
systemctl daemon-reload
systemctl enable nexconsole
systemctl start nexconsole
```

3. Ensure HTTPS is enabled via Cloudflare Tunnel or a reverse proxy (e.g. NGINX) to allow browser WebAuthn (Touch ID / Face ID) execution.
