use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path as AxumPath, State,
    },
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, post, put},
    Router,
};
use base64::prelude::*;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssh2::Session;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use sysinfo::System;
use tower_http::{cors::CorsLayer, services::ServeDir};
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::*;

#[allow(dead_code)]
#[derive(Clone)]
struct AppConfig {
    port: u16,
    jwt_secret: String,
    layer1_user: String,
    layer1_pass: String,
    ssh_host: String,
    ssh_port: u16,
}

#[derive(Clone)]
struct AppState {
    config: Arc<AppConfig>,
    webauthn_local: Arc<Webauthn>,
    webauthn_cloud: Arc<Webauthn>,
    passkeys: Arc<tokio::sync::RwLock<Vec<Passkey>>>,
    reg_state: Arc<tokio::sync::Mutex<std::collections::HashMap<String, (PasskeyRegistration, std::time::Instant)>>>,
    auth_state: Arc<tokio::sync::Mutex<std::collections::HashMap<String, (PasskeyAuthentication, std::time::Instant)>>>,
    db: Arc<tokio::sync::Mutex<Connection>>,
    login_limiter: Arc<tokio::sync::Mutex<std::collections::HashMap<String, (u32, std::time::Instant)>>>,
    twofa_limiter: Arc<tokio::sync::Mutex<std::collections::HashMap<String, (u32, std::time::Instant)>>>,
    passkey_limiter: Arc<tokio::sync::Mutex<std::collections::HashMap<String, (u32, std::time::Instant)>>>,
    pwd_change_limiter: Arc<tokio::sync::Mutex<std::collections::HashMap<String, (u32, std::time::Instant)>>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Claims {
    sub: String,
    username: String,
    role: String,
    exp: usize,
    #[serde(default)]
    stage: Option<String>,
}

#[derive(Deserialize)]
struct LoginPayload {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct ProfileUpdatePayload {
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    email: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct QuickCommandItem {
    label: String,
    command: String,
}

#[derive(Deserialize)]
struct QuickCommandsUpdatePayload {
    commands: Vec<QuickCommandItem>,
}

fn default_quick_commands() -> serde_json::Value {
    serde_json::json!([
        { "label": "clear", "command": "clear" },
        { "label": "htop", "command": "htop" },
        { "label": "pm2 list", "command": "pm2 list" },
        { "label": "free -h", "command": "free -h" },
        { "label": "df -h /", "command": "df -h /" },
        { "label": "status postgresql", "command": "systemctl status postgresql" },
        { "label": "status nginx", "command": "systemctl status nginx" },
        { "label": "open ports", "command": "ss -tulnp" }
    ])
}

#[derive(Deserialize)]
struct ProfilePasswordPayload {
    #[serde(rename = "currentPassword")]
    current_password: String,
    #[serde(rename = "newPassword")]
    new_password: String,
}

#[derive(Deserialize)]
struct TwofaVerifyPayload {
    code: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct TwofaDisablePayload {
    password: Option<String>,
    code: Option<String>,
}

#[derive(Deserialize)]
struct TwofaLoginVerifyPayload {
    #[serde(rename = "tempToken")]
    temp_token: String,
    code: String,
}

#[derive(Deserialize)]
struct CreateServerPayload {
    name: String,
    host: String,
    port: Option<u16>,
    username: Option<String>,
    password: Option<String>,
    overwrite: Option<bool>,
}

#[derive(Deserialize)]
struct UpdateServerPayload {
    name: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    username: Option<String>,
    password: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum WsClientMessage {
    #[serde(rename = "ssh_connect")]
    SshConnect {
        server_id: Option<String>,
        host: Option<String>,
        port: Option<u16>,
        username: Option<String>,
        password: Option<String>,
        cols: Option<u32>,
        rows: Option<u32>,
    },
    #[serde(rename = "ssh_disconnect")]
    SshDisconnect,
    #[serde(rename = "data")]
    Data { data: String },
    #[serde(rename = "resize")]
    Resize { cols: u32, rows: u32 },
    #[serde(rename = "ping")]
    Ping,
    #[serde(rename = "pong")]
    Pong,
}

enum SshCommand {
    Data(Vec<u8>),
    Resize { cols: u32, rows: u32 },
    Disconnect,
}

enum SshEvent {
    Status(String),
    SshError(String),
    Output(String),
    Disconnected,
}

fn passkey_file_path() -> PathBuf {
    if PathBuf::from("/etc/nexconsole").exists() {
        PathBuf::from("/etc/nexconsole/passkeys.json")
    } else {
        PathBuf::from("passkeys.json")
    }
}

fn load_passkeys() -> Vec<Passkey> {
    let path = passkey_file_path();
    if let Ok(content) = std::fs::read_to_string(&path) {
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        Vec::new()
    }
}

fn save_passkeys(passkeys: &[Passkey]) {
    let path = passkey_file_path();
    if let Ok(json) = serde_json::to_string_pretty(passkeys) {
        let _ = std::fs::write(&path, json);
    }
}

fn get_master_encryption_key(jwt_secret: &str) -> [u8; 32] {
    if let Ok(env_key) = std::env::var("MASTER_KEY").or_else(|_| std::env::var("ENCRYPTION_KEY")) {
        let trimmed = env_key.trim();
        if !trimmed.is_empty() {
            let mut hasher = Sha256::new();
            hasher.update(b"nexconsole_dedicated_master_key:");
            hasher.update(trimmed.as_bytes());
            return hasher.finalize().into();
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(b"nexconsole_encryption_master_key:");
    hasher.update(jwt_secret.as_bytes());
    hasher.finalize().into()
}

fn is_allowed_origin(origin: &str, headers: &HeaderMap) -> bool {
    if let Ok(parsed_origin) = url::Url::parse(origin) {
        if let Some(host) = parsed_origin.host_str() {
            if host == "localhost" || host == "127.0.0.1" || host == "::1" {
                return true;
            }
            if host == "nexspace.vn" || host.ends_with(".nexspace.vn") {
                return true;
            }
            if let Some(req_host) = headers.get(header::HOST).and_then(|h| h.to_str().ok()) {
                let req_domain = req_host.split(':').next().unwrap_or("");
                if host == req_domain {
                    return true;
                }
            }
        }
    }
    false
}

fn get_client_ip(headers: &HeaderMap) -> String {
    headers
        .get("cf-connecting-ip")
        .or_else(|| headers.get("x-real-ip"))
        .or_else(|| headers.get("x-forwarded-for"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

async fn security_headers_middleware(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    headers.insert(header::X_FRAME_OPTIONS, header::HeaderValue::from_static("DENY"));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, header::HeaderValue::from_static("nosniff"));
    headers.insert(header::REFERRER_POLICY, header::HeaderValue::from_static("strict-origin-when-cross-origin"));
    headers.insert(
        header::HeaderName::from_static("permissions-policy"),
        header::HeaderValue::from_static("geolocation=(), camera=(), microphone=()"),
    );
    headers.insert(
        header::HeaderName::from_static("x-xss-protection"),
        header::HeaderValue::from_static("1; mode=block"),
    );
    res
}

fn is_request_secure(headers: &HeaderMap) -> bool {
    if let Some(proto) = headers.get("x-forwarded-proto").and_then(|v| v.to_str().ok()) {
        if proto.eq_ignore_ascii_case("https") {
            return true;
        }
    }
    if let Some(forwarded) = headers.get("forwarded").and_then(|v| v.to_str().ok()) {
        if forwarded.to_ascii_lowercase().contains("proto=https") {
            return true;
        }
    }
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        if origin.starts_with("https://") {
            return true;
        }
    }
    if let Some(referer) = headers.get(header::REFERER).and_then(|v| v.to_str().ok()) {
        if referer.starts_with("https://") {
            return true;
        }
    }
    if let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) {
        let domain = host.split(':').next().unwrap_or("");
        if domain == "nexspace.vn" || domain.ends_with(".nexspace.vn") {
            return true;
        }
    }
    false
}

fn build_auth_cookie(token: &str, max_age: u64, is_secure: bool) -> String {
    let secure_flag = if is_secure { "; Secure" } else { "" };
    format!(
        "console_token={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}{}",
        token, max_age, secure_flag
    )
}

fn encrypt_password(plain: &str, master_key: &[u8; 32]) -> Result<(String, String), String> {
    let cipher = Aes256Gcm::new_from_slice(master_key).map_err(|e| e.to_string())?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plain.as_bytes())
        .map_err(|e| e.to_string())?;
    Ok((
        BASE64_STANDARD.encode(ciphertext),
        BASE64_STANDARD.encode(nonce_bytes),
    ))
}

fn decrypt_password(ciphertext_b64: &str, nonce_b64: &str, master_key: &[u8; 32]) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(master_key).map_err(|e| e.to_string())?;
    let ciphertext = BASE64_STANDARD.decode(ciphertext_b64).map_err(|e| e.to_string())?;
    let nonce_bytes = BASE64_STANDARD.decode(nonce_b64).map_err(|e| e.to_string())?;
    if nonce_bytes.len() != 12 {
        return Err("Invalid nonce length".to_string());
    }
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| e.to_string())?;
    String::from_utf8(plaintext).map_err(|e| e.to_string())
}

fn db_file_path() -> PathBuf {
    if PathBuf::from("/etc/nexconsole").exists() {
        PathBuf::from("/etc/nexconsole/servers.db")
    } else {
        PathBuf::from("servers.db")
    }
}

fn init_sqlite_db() -> Result<Connection, rusqlite::Error> {
    let path = db_file_path();
    let conn = Connection::open(path)?;
    let _ = conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;");
    conn.execute(
        "CREATE TABLE IF NOT EXISTS servers (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL DEFAULT 22,
            username TEXT NOT NULL DEFAULT 'root',
            auth_type TEXT NOT NULL DEFAULT 'password',
            encrypted_secret TEXT,
            iv TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS user_security (
            username TEXT PRIMARY KEY,
            display_name TEXT,
            email TEXT,
            totp_secret TEXT,
            totp_enabled INTEGER NOT NULL DEFAULT 0,
            totp_verified_at INTEGER,
            password_hash TEXT,
            updated_at INTEGER NOT NULL
        )",
        [],
    )?;
    let _ = conn.execute("ALTER TABLE user_security ADD COLUMN quick_commands TEXT", []);
    Ok(conn)
}

fn get_webauthn(headers: &HeaderMap, state: &AppState) -> Arc<Webauthn> {
    if let Some(host_val) = headers.get(header::HOST) {
        if let Ok(host_str) = host_val.to_str() {
            if host_str.contains("nexspace.vn") {
                return state.webauthn_cloud.clone();
            }
        }
    }
    state.webauthn_local.clone()
}

fn extract_token_from_headers(headers: &HeaderMap) -> Option<String> {
    if let Some(auth_val) = headers.get(header::AUTHORIZATION) {
        if let Ok(s) = auth_val.to_str() {
            if let Some(bearer) = s.strip_prefix("Bearer ") {
                let trimmed = bearer.trim();
                if !trimmed.is_empty() && trimmed != "null" && trimmed != "undefined" {
                    return Some(trimmed.to_string());
                }
            }
        }
    }
    if let Some(cookie_val) = headers.get(header::COOKIE) {
        if let Ok(cookies_str) = cookie_val.to_str() {
            for cookie in cookies_str.split(';') {
                let trimmed = cookie.trim();
                if let Some(token) = trimmed.strip_prefix("console_token=") {
                    let t = token.trim();
                    if !t.is_empty() && t != "null" && t != "undefined" {
                        return Some(t.to_string());
                    }
                }
            }
        }
    }
    None
}

fn verify_jwt(token: &str, secret: &str) -> Result<Claims, ()> {
    let decoding_key = DecodingKey::from_secret(secret.as_bytes());
    let mut validation = Validation::default();
    validation.validate_exp = true;
    match decode::<Claims>(token, &decoding_key, &validation) {
        Ok(token_data) => {
            // Chống Bypass 2FA: từ chối tuyệt đối các token tạm thời có stage (ví dụ 2fa_pending)
            if token_data.claims.stage.is_some() {
                return Err(());
            }
            Ok(token_data.claims)
        }
        Err(_) => Err(()),
    }
}

fn verify_temp_2fa_jwt(token: &str, secret: &str) -> Result<Claims, ()> {
    let decoding_key = DecodingKey::from_secret(secret.as_bytes());
    let mut validation = Validation::default();
    validation.validate_exp = true;
    match decode::<Claims>(token, &decoding_key, &validation) {
        Ok(token_data) => {
            if token_data.claims.stage.as_deref() == Some("2fa_pending") {
                Ok(token_data.claims)
            } else {
                Err(())
            }
        }
        Err(_) => Err(()),
    }
}

fn base32_decode(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let mut bits = String::new();
    for c in cleaned.chars() {
        let val = ALPHABET.iter().position(|&x| x == c as u8)?;
        bits.push_str(&format!("{:05b}", val));
    }
    let mut bytes = Vec::new();
    let mut i = 0;
    while i + 8 <= bits.len() {
        let byte = u8::from_str_radix(&bits[i..i + 8], 2).ok()?;
        bytes.push(byte);
        i += 8;
    }
    Some(bytes)
}

fn generate_base32_secret(len: usize) -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..ALPHABET.len());
            ALPHABET[idx] as char
        })
        .collect()
}

fn generate_secure_password(len: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*+-=";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

fn generate_random_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

fn update_env_var(key: &str, value: &str) {
    let env_path = std::path::Path::new(".env");
    if !env_path.exists() {
        let default_content = format!("{}=\"{}\"\n", key, value);
        let _ = std::fs::write(env_path, default_content);
        return;
    }
    if let Ok(content) = std::fs::read_to_string(env_path) {
        let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
        let mut found = false;
        let prefix = format!("{}=", key);
        for line in lines.iter_mut() {
            if line.trim_start().starts_with(&prefix) {
                *line = format!("{}=\"{}\"", key, value);
                found = true;
                break;
            }
        }
        if !found {
            lines.push(format!("{}=\"{}\"", key, value));
        }
        let _ = std::fs::write(env_path, lines.join("\n") + "\n");
    }
}

fn generate_totp(secret: &str, time_offset: i64) -> Option<String> {
    let key_bytes = base32_decode(secret)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    let counter = (now / 30) + time_offset;
    let counter_bytes = counter.to_be_bytes();

    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &key_bytes);
    let signature = ring::hmac::sign(&key, &counter_bytes);
    let hash = signature.as_ref();
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let binary = ((hash[offset] as u32 & 0x7f) << 24)
        | ((hash[offset + 1] as u32 & 0xff) << 16)
        | ((hash[offset + 2] as u32 & 0xff) << 8)
        | (hash[offset + 3] as u32 & 0xff);
    let code = binary % 1_000_000;
    Some(format!("{:06}", code))
}

fn verify_totp(secret: &str, code: &str) -> bool {
    let clean_code = code.trim();
    if clean_code.len() != 6 {
        return false;
    }
    for offset in [-1, 0, 1] {
        if let Some(generated) = generate_totp(secret, offset) {
            if generated == clean_code {
                return true;
            }
        }
    }
    false
}

fn hash_password(password: &str, secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}", password, secret).as_bytes());
    format!("{:x}", hasher.finalize())
}

fn create_temp_2fa_jwt(username: &str, secret: &str) -> Result<String, ()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;
    let exp = now + 300; // 5 phút

    let claims = Claims {
        sub: username.to_string(),
        username: username.to_string(),
        role: "admin".to_string(),
        exp,
        stage: Some("2fa_pending".to_string()),
    };

    let encoding_key = EncodingKey::from_secret(secret.as_bytes());
    encode(&Header::default(), &claims, &encoding_key).map_err(|_| ())
}

struct UserSecurityRow {
    username: String,
    display_name: String,
    email: String,
    totp_secret: Option<String>,
    totp_enabled: bool,
    totp_verified_at: Option<i64>,
    password_hash: Option<String>,
    quick_commands: Option<String>,
}

fn get_user_security(conn: &Connection, username: &str) -> Result<Option<UserSecurityRow>, rusqlite::Error> {
    let mut stmt = conn.prepare("SELECT username, display_name, email, totp_secret, totp_enabled, totp_verified_at, password_hash, quick_commands FROM user_security WHERE username = ?1")?;
    let row = stmt.query_row([username], |r| {
        Ok(UserSecurityRow {
            username: r.get(0)?,
            display_name: r.get::<_, Option<String>>(1)?.unwrap_or_else(|| username.to_string()),
            email: r.get::<_, Option<String>>(2)?.unwrap_or_else(|| format!("{}@nexspace.vn", username)),
            totp_secret: r.get(3)?,
            totp_enabled: r.get::<_, i64>(4)? == 1,
            totp_verified_at: r.get(5)?,
            password_hash: r.get(6)?,
            quick_commands: r.get(7)?,
        })
    }).optional()?;
    Ok(row)
}

fn get_or_create_user_security(conn: &Connection, username: &str) -> Result<UserSecurityRow, rusqlite::Error> {
    if let Some(r) = get_user_security(conn, username)? {
        Ok(r)
    } else {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        let d_name = if username == "admin" { "Administrator" } else { username };
        let d_email = format!("{}@nexspace.vn", username);
        conn.execute(
            "INSERT INTO user_security (username, display_name, email, totp_secret, totp_enabled, totp_verified_at, updated_at)
             VALUES (?1, ?2, ?3, NULL, 0, NULL, ?4)",
            params![username, d_name, d_email, now],
        )?;
        Ok(UserSecurityRow {
            username: username.to_string(),
            display_name: d_name.to_string(),
            email: d_email,
            totp_secret: None,
            totp_enabled: false,
            totp_verified_at: None,
            password_hash: None,
            quick_commands: None,
        })
    }
}

fn create_jwt(username: &str, secret: &str) -> Result<String, ()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;
    let exp = now + 7 * 24 * 3600; // 7 ngày

    let claims = Claims {
        sub: username.to_string(),
        username: username.to_string(),
        role: "admin".to_string(),
        exp,
        stage: None,
    };

    let encoding_key = EncodingKey::from_secret(secret.as_bytes());
    encode(&Header::default(), &claims, &encoding_key).map_err(|_| ())
}

// 1. API Đăng nhập Lớp 1 bằng Mật khẩu (Hỗ trợ 2FA & Rate Limiting)
async fn login_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<LoginPayload>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let client_ip = get_client_ip(&headers);
    let rate_key = format!("{}:{}", client_ip, payload.username.trim());

    // 1. Kiểm tra Rate Limiting chống Brute-Force
    {
        let mut limiter = state.login_limiter.lock().await;
        let now = std::time::Instant::now();
        limiter.retain(|_, (_, last_time)| now.duration_since(*last_time) < Duration::from_secs(300));
        if let Some((attempts, last_time)) = limiter.get(&rate_key) {
            if *attempts >= 5 && now.duration_since(*last_time) < Duration::from_secs(60) {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(serde_json::json!({
                        "success": false,
                        "message": "Quá nhiều lần đăng nhập không thành công. Vui lòng đợi 1 phút trước khi thử lại."
                    })),
                ));
            }
        }
    }

    let db = state.db.lock().await;
    let mut user_sec = match get_user_security(&db, &payload.username) {
        Ok(u) => u,
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "success": false, "message": "Lỗi truy vấn cơ sở dữ liệu" })),
            ));
        }
    };

    // Khởi tạo tài khoản root admin lần đầu nếu chưa có trong DB
    if user_sec.is_none() && payload.username == state.config.layer1_user && payload.password == state.config.layer1_pass {
        user_sec = get_or_create_user_security(&db, &payload.username).ok();
    }

    let user_sec = match user_sec {
        Some(u) => u,
        None => {
            let mut limiter = state.login_limiter.lock().await;
            let entry = limiter.entry(rate_key).or_insert((0, std::time::Instant::now()));
            entry.0 += 1;
            entry.1 = std::time::Instant::now();
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "success": false,
                    "message": "Tài khoản hoặc mật khẩu Lớp 1 không chính xác!"
                })),
            ));
        }
    };

    let mut is_valid = false;
    if let Some(ref ph) = user_sec.password_hash {
        let computed = hash_password(&payload.password, &state.config.jwt_secret);
        if &computed == ph {
            is_valid = true;
        }
    } else if payload.username == state.config.layer1_user && payload.password == state.config.layer1_pass {
        is_valid = true;
    }

    if !is_valid {
        let mut limiter = state.login_limiter.lock().await;
        let entry = limiter.entry(rate_key).or_insert((0, std::time::Instant::now()));
        entry.0 += 1;
        entry.1 = std::time::Instant::now();
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "success": false,
                "message": "Tài khoản hoặc mật khẩu Lớp 1 không chính xác!"
            })),
        ));
    }

    // Xóa bộ đếm rate limit khi đăng nhập thành công
    {
        let mut limiter = state.login_limiter.lock().await;
        limiter.remove(&rate_key);
    }

    // Nếu người dùng đã kích hoạt 2FA (Google Authenticator)
    if user_sec.totp_enabled && user_sec.totp_secret.is_some() {
        let temp_token = match create_temp_2fa_jwt(&payload.username, &state.config.jwt_secret) {
            Ok(t) => t,
            Err(_) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "success": false, "message": "Không thể tạo mã tạm 2FA" })),
                ));
            }
        };

        return Ok(Json(serde_json::json!({
            "success": true,
            "require2fa": true,
            "tempToken": temp_token,
            "username": payload.username
        })).into_response());
    }

    // Đăng nhập trực tiếp (không yêu cầu 2FA)
    let token = match create_jwt(&payload.username, &state.config.jwt_secret) {
        Ok(t) => t,
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "message": "Không thể tạo mã xác thực JWT"
                })),
            ));
        }
    };

    let is_sec = is_request_secure(&headers);
    let cookie_val = build_auth_cookie(&token, 7 * 24 * 3600, is_sec);

    let body = Json(serde_json::json!({
        "success": true,
        "user": {
            "username": payload.username,
            "displayName": user_sec.display_name,
            "role": "admin",
            "totpEnabled": false
        },
        "token": token
    }));

    let mut res = body.into_response();
    if let Ok(hv) = cookie_val.parse() {
        res.headers_mut().insert(header::SET_COOKIE, hv);
    }
    Ok(res)
}

// 1b. API Xác thực mã OTP 2FA khi đăng nhập
async fn twofa_login_verify_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<TwofaLoginVerifyPayload>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let claims = match verify_temp_2fa_jwt(&payload.temp_token, &state.config.jwt_secret) {
        Ok(c) => c,
        Err(_) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "success": false, "message": "Phiên xác thực 2FA đã hết hạn hoặc không hợp lệ" })),
            ));
        }
    };

    let twofa_key = claims.username.clone();
    {
        let mut limiter = state.twofa_limiter.lock().await;
        let now = std::time::Instant::now();
        limiter.retain(|_, (_, last_time)| now.duration_since(*last_time) < Duration::from_secs(300));
        let entry = limiter.entry(twofa_key.clone()).or_insert((0, now));
        if entry.0 >= 5 {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "success": false,
                    "message": "Đã nhập sai OTP quá 5 lần. Vui lòng đăng nhập lại để nhận mã phiên mới."
                })),
            ));
        }
    }

    let db = state.db.lock().await;
    let user_sec = match get_user_security(&db, &claims.username) {
        Ok(Some(u)) => u,
        Ok(None) | Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "success": false, "message": "Lỗi truy vấn cơ sở dữ liệu" })),
            ));
        }
    };

    let secret = match user_sec.totp_secret {
        Some(s) if user_sec.totp_enabled => s,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "success": false, "message": "Tài khoản chưa kích hoạt 2FA" })),
            ));
        }
    };

    if !verify_totp(&secret, &payload.code) {
        let remaining = {
            let mut limiter = state.twofa_limiter.lock().await;
            let entry = limiter.entry(twofa_key).or_insert((0, std::time::Instant::now()));
            entry.0 += 1;
            entry.1 = std::time::Instant::now();
            5_u32.saturating_sub(entry.0)
        };
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "success": false,
                "message": format!("Mã xác thực 2 bước không chính xác hoặc đã hết hạn (còn {} lần thử)", remaining)
            })),
        ));
    }

    // Reset bộ đếm thử OTP khi thành công
    {
        let mut limiter = state.twofa_limiter.lock().await;
        limiter.remove(&twofa_key);
    }

    let token = match create_jwt(&claims.username, &state.config.jwt_secret) {
        Ok(t) => t,
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "success": false, "message": "Không thể tạo token phiên làm việc" })),
            ));
        }
    };

    let is_sec = is_request_secure(&headers);
    let cookie_val = build_auth_cookie(&token, 7 * 24 * 3600, is_sec);

    let body = Json(serde_json::json!({
        "success": true,
        "user": {
            "username": claims.username,
            "displayName": user_sec.display_name,
            "role": "admin",
            "totpEnabled": true
        },
        "token": token
    }));

    let mut res = body.into_response();
    if let Ok(hv) = cookie_val.parse() {
        res.headers_mut().insert(header::SET_COOKIE, hv);
    }
    Ok(res)
}

// 2. API Kiểm tra trạng thái đăng nhập
async fn me_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    if let Some(token) = extract_token_from_headers(&headers) {
        if let Ok(claims) = verify_jwt(&token, &state.config.jwt_secret) {
            let db = state.db.lock().await;
            let (display_name, email, totp_enabled, quick_commands) = if let Ok(u) = get_or_create_user_security(&db, &claims.username) {
                let qc: serde_json::Value = if let Some(ref s) = u.quick_commands {
                    serde_json::from_str(s).unwrap_or_else(|_| default_quick_commands())
                } else {
                    default_quick_commands()
                };
                (u.display_name, u.email, u.totp_enabled, qc)
            } else {
                (claims.username.clone(), format!("{}@nexspace.vn", claims.username), false, default_quick_commands())
            };

            return Json(serde_json::json!({
                "loggedIn": true,
                "user": {
                    "username": claims.username,
                    "displayName": display_name,
                    "email": email,
                    "role": claims.role,
                    "totpEnabled": totp_enabled,
                    "quickCommands": quick_commands
                }
            }));
        }
    }
    Json(serde_json::json!({ "loggedIn": false }))
}

// API Thông tin hồ sơ người dùng
async fn profile_get_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = extract_token_from_headers(&headers).ok_or_else(|| {
        (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "success": false, "message": "Chưa xác thực Lớp 1" })))
    })?;
    let claims = verify_jwt(&token, &state.config.jwt_secret).map_err(|_| {
        (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "success": false, "message": "Token hết hạn" })))
    })?;

    let db = state.db.lock().await;
    let user_sec = get_or_create_user_security(&db, &claims.username).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "success": false, "message": "Lỗi cơ sở dữ liệu" })))
    })?;

    let quick_commands_val: serde_json::Value = if let Some(ref qc_str) = user_sec.quick_commands {
        serde_json::from_str(qc_str).unwrap_or_else(|_| default_quick_commands())
    } else {
        default_quick_commands()
    };

    Ok(Json(serde_json::json!({
        "success": true,
        "profile": {
            "username": user_sec.username,
            "displayName": user_sec.display_name,
            "email": user_sec.email,
            "role": "admin",
            "totpEnabled": user_sec.totp_enabled,
            "totpVerifiedAt": user_sec.totp_verified_at,
            "quickCommands": quick_commands_val
        }
    })))
}

async fn profile_update_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ProfileUpdatePayload>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = extract_token_from_headers(&headers).ok_or_else(|| {
        (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "success": false, "message": "Chưa xác thực Lớp 1" })))
    })?;
    let claims = verify_jwt(&token, &state.config.jwt_secret).map_err(|_| {
        (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "success": false, "message": "Token hết hạn" })))
    })?;

    let db = state.db.lock().await;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let d_name = payload.display_name.unwrap_or_else(|| claims.username.clone());
    let email = payload.email.unwrap_or_default();

    db.execute(
        "UPDATE user_security SET display_name = ?1, email = ?2, updated_at = ?3 WHERE username = ?4",
        params![d_name.trim(), email.trim(), now, claims.username],
    ).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "success": false, "message": "Lỗi cập nhật hồ sơ" })))
    })?;

    Ok(Json(serde_json::json!({ "success": true, "message": "Đã cập nhật thông tin hồ sơ thành công!" })))
}

async fn profile_quick_commands_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<QuickCommandsUpdatePayload>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = extract_token_from_headers(&headers).ok_or_else(|| {
        (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "success": false, "message": "Chưa xác thực Lớp 1" })))
    })?;
    let claims = verify_jwt(&token, &state.config.jwt_secret).map_err(|_| {
        (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "success": false, "message": "Token hết hạn" })))
    })?;

    let json_str = serde_json::to_string(&payload.commands).unwrap_or_else(|_| "[]".to_string());

    let db = state.db.lock().await;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;

    db.execute(
        "UPDATE user_security SET quick_commands = ?1, updated_at = ?2 WHERE username = ?3",
        params![json_str, now, claims.username],
    ).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "success": false, "message": "Lỗi cập nhật danh sách lệnh" })))
    })?;

    Ok(Json(serde_json::json!({ "success": true, "message": "Đã lưu danh sách lệnh nhanh thành công!" })))
}

async fn profile_password_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ProfilePasswordPayload>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = extract_token_from_headers(&headers).ok_or_else(|| {
        (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "success": false, "message": "Chưa xác thực Lớp 1" })))
    })?;
    let claims = verify_jwt(&token, &state.config.jwt_secret).map_err(|_| {
        (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "success": false, "message": "Token hết hạn" })))
    })?;

    if payload.new_password.len() < 6 {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({ "success": false, "message": "Mật khẩu mới phải có ít nhất 6 ký tự" }))));
    }

    let pwd_key = claims.username.clone();
    {
        let mut limiter = state.pwd_change_limiter.lock().await;
        let now = std::time::Instant::now();
        limiter.retain(|_, (_, last_time)| now.duration_since(*last_time) < Duration::from_secs(60));
        if let Some((attempts, last_time)) = limiter.get(&pwd_key) {
            if *attempts >= 5 && now.duration_since(*last_time) < Duration::from_secs(60) {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(serde_json::json!({
                        "success": false,
                        "message": "Quá nhiều lần nhập sai mật khẩu cũ. Vui lòng đợi 1 phút trước khi thử lại."
                    })),
                ));
            }
        }
    }

    let db = state.db.lock().await;
    let user_sec = get_or_create_user_security(&db, &claims.username).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "success": false, "message": "Lỗi cơ sở dữ liệu" })))
    })?;

    let mut is_valid = false;
    if let Some(ref ph) = user_sec.password_hash {
        let computed = hash_password(&payload.current_password, &state.config.jwt_secret);
        if &computed == ph {
            is_valid = true;
        }
    } else if payload.current_password == state.config.layer1_pass {
        is_valid = true;
    }

    if !is_valid {
        let mut limiter = state.pwd_change_limiter.lock().await;
        let entry = limiter.entry(pwd_key).or_insert((0, std::time::Instant::now()));
        entry.0 += 1;
        entry.1 = std::time::Instant::now();
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({ "success": false, "message": "Mật khẩu hiện tại không chính xác" }))));
    }

    {
        let mut limiter = state.pwd_change_limiter.lock().await;
        limiter.remove(&pwd_key);
    }

    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let new_hash = hash_password(&payload.new_password, &state.config.jwt_secret);

    db.execute(
        "UPDATE user_security SET password_hash = ?1, updated_at = ?2 WHERE username = ?3",
        params![new_hash, now, claims.username],
    ).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "success": false, "message": "Lỗi lưu mật khẩu mới" })))
    })?;

    Ok(Json(serde_json::json!({ "success": true, "message": "Đã đổi mật khẩu thành công!" })))
}

// 2FA Endpoints
async fn twofa_status_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = extract_token_from_headers(&headers).ok_or_else(|| {
        (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "success": false, "message": "Chưa xác thực Lớp 1" })))
    })?;
    let claims = verify_jwt(&token, &state.config.jwt_secret).map_err(|_| {
        (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "success": false, "message": "Token hết hạn" })))
    })?;

    let db = state.db.lock().await;
    let user_sec = get_or_create_user_security(&db, &claims.username).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "success": false, "message": "Lỗi cơ sở dữ liệu" })))
    })?;

    Ok(Json(serde_json::json!({
        "success": true,
        "enabled": user_sec.totp_enabled,
        "verifiedAt": user_sec.totp_verified_at
    })))
}

async fn twofa_setup_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = extract_token_from_headers(&headers).ok_or_else(|| {
        (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "success": false, "message": "Chưa xác thực Lớp 1" })))
    })?;
    let claims = verify_jwt(&token, &state.config.jwt_secret).map_err(|_| {
        (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "success": false, "message": "Token hết hạn" })))
    })?;

    let secret = generate_base32_secret(32);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;

    let db = state.db.lock().await;
    let _ = get_or_create_user_security(&db, &claims.username);

    db.execute(
        "UPDATE user_security SET totp_secret = ?1, totp_enabled = 0, updated_at = ?2 WHERE username = ?3",
        params![secret, now, claims.username],
    ).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "success": false, "message": "Lỗi lưu khóa 2FA" })))
    })?;

    let otpauth_url = format!(
        "otpauth://totp/NexConsole:{}?secret={}&issuer=NexConsole",
        claims.username, secret
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "secret": secret,
        "otpauthUrl": otpauth_url,
        "issuer": "NexConsole",
        "account": claims.username
    })))
}

async fn twofa_enable_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<TwofaVerifyPayload>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = extract_token_from_headers(&headers).ok_or_else(|| {
        (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "success": false, "message": "Chưa xác thực Lớp 1" })))
    })?;
    let claims = verify_jwt(&token, &state.config.jwt_secret).map_err(|_| {
        (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "success": false, "message": "Token hết hạn" })))
    })?;

    let db = state.db.lock().await;
    let user_sec = get_or_create_user_security(&db, &claims.username).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "success": false, "message": "Lỗi cơ sở dữ liệu" })))
    })?;

    let secret = user_sec.totp_secret.ok_or_else(|| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "success": false, "message": "Chưa khởi tạo khóa 2FA" })))
    })?;

    if !verify_totp(&secret, &payload.code) {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({ "success": false, "message": "Mã xác thực 2 bước không chính xác" }))));
    }

    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    db.execute(
        "UPDATE user_security SET totp_enabled = 1, totp_verified_at = ?1, updated_at = ?2 WHERE username = ?3",
        params![now, now, claims.username],
    ).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "success": false, "message": "Lỗi cập nhật trạng thái 2FA" })))
    })?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Đã kích hoạt xác thực 2 bước (Google Authenticator) thành công!"
    })))
}

async fn twofa_disable_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<TwofaDisablePayload>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = extract_token_from_headers(&headers).ok_or_else(|| {
        (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "success": false, "message": "Chưa xác thực Lớp 1" })))
    })?;
    let claims = verify_jwt(&token, &state.config.jwt_secret).map_err(|_| {
        (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "success": false, "message": "Token hết hạn" })))
    })?;

    let db = state.db.lock().await;
    let user_sec = get_or_create_user_security(&db, &claims.username).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "success": false, "message": "Lỗi cơ sở dữ liệu" })))
    })?;

    if !user_sec.totp_enabled {
        return Ok(Json(serde_json::json!({ "success": true, "message": "2FA hiện đang tắt" })));
    }

    let code = payload.code.as_deref().map(|s| s.trim()).filter(|s| !s.is_empty()).ok_or_else(|| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "success": false, "message": "Vui lòng cung cấp mã OTP 6 số để xác thực trước khi tắt 2FA" })))
    })?;

    let s = user_sec.totp_secret.as_deref().ok_or_else(|| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "success": false, "message": "Không tìm thấy cấu hình mã bí mật 2FA" })))
    })?;

    if !verify_totp(s, code) {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({ "success": false, "message": "Mã xác thực OTP không chính xác" }))));
    }

    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    db.execute(
        "UPDATE user_security SET totp_enabled = 0, totp_secret = NULL, totp_verified_at = NULL, updated_at = ?1 WHERE username = ?2",
        params![now, claims.username],
    ).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "success": false, "message": "Lỗi tắt 2FA" })))
    })?;

    Ok(Json(serde_json::json!({ "success": true, "message": "Đã tắt xác thực 2 bước thành công" })))
}

async fn account_page_handler() -> impl IntoResponse {
    let path = if PathBuf::from("public/account/index.html").exists() {
        PathBuf::from("public/account/index.html")
    } else if PathBuf::from("../public/account/index.html").exists() {
        PathBuf::from("../public/account/index.html")
    } else {
        PathBuf::from("public/account/index.html")
    };

    match tokio::fs::read_to_string(path).await {
        Ok(html) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html,
        ).into_response(),
        Err(_) => (
            StatusCode::NOT_FOUND,
            "Trang Account không tìm thấy",
        ).into_response(),
    }
}

// 3. API Đăng xuất
async fn logout_handler(headers: HeaderMap) -> Response {
    let is_sec = is_request_secure(&headers);
    let sec_flag = if is_sec { "; Secure" } else { "" };
    let cookie_val = format!("console_token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{}", sec_flag);
    let mut res = Json(serde_json::json!({ "success": true })).into_response();
    if let Ok(hv) = cookie_val.parse() {
        res.headers_mut().insert(header::SET_COOKIE, hv);
    }
    res
}

// 4. API Thông số máy chủ (CPU, RAM, Uptime)
async fn stats_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = extract_token_from_headers(&headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "success": false, "message": "Chưa xác thực Lớp 1" })),
        )
    })?;

    verify_jwt(&token, &state.config.jwt_secret).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "success": false, "message": "Token Lớp 1 hết hạn hoặc không hợp lệ" })),
        )
    })?;

    let mut sys = System::new_all();
    sys.refresh_memory();
    sys.refresh_cpu();

    let total_bytes = sys.total_memory();
    let used_bytes = sys.used_memory();
    let total_gb = (total_bytes as f64 / (1024.0 * 1024.0 * 1024.0)).round() as u64;
    let used_gb = format!("{:.1}", used_bytes as f64 / (1024.0 * 1024.0 * 1024.0));
    let percent = if total_bytes > 0 {
        ((used_bytes as f64 / total_bytes as f64) * 100.0).round() as u64
    } else {
        0
    };

    let load = System::load_average();
    let uptime = System::uptime();
    let hostname = System::host_name().unwrap_or_else(|| "NexConsole-Host".to_string());

    Ok(Json(serde_json::json!({
        "success": true,
        "hostname": hostname,
        "uptime": uptime,
        "memory": {
            "total": total_gb,
            "used": used_gb,
            "percent": percent
        },
        "load": format!("{:.2}", load.one)
    })))
}

// ========================================================
// 4B. QUẢN LÝ MÁY CHỦ SSH (SQLITE + AES-256)
// ========================================================

// Lấy danh sách máy chủ đã lưu
async fn list_servers_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = extract_token_from_headers(&headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "success": false, "message": "Chưa xác thực Lớp 1" })),
        )
    })?;
    verify_jwt(&token, &state.config.jwt_secret).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "success": false, "message": "Phiên đăng nhập đã hết hạn" })),
        )
    })?;

    let conn = state.db.lock().await;
    let mut stmt = conn
        .prepare("SELECT id, name, host, port, username, (encrypted_secret IS NOT NULL AND encrypted_secret != '') AS has_pwd, created_at FROM servers ORDER BY created_at DESC")
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "success": false, "error": e.to_string() })),
            )
        })?;

    let rows = stmt
        .query_map([], |row| {
            let id: String = row.get(0)?;
            let name: String = row.get(1)?;
            let host: String = row.get(2)?;
            let port: u16 = row.get(3)?;
            let username: String = row.get(4)?;
            let has_pwd: bool = row.get(5)?;
            let created_at: i64 = row.get(6)?;
            Ok(serde_json::json!({
                "id": id,
                "name": name,
                "host": host,
                "port": port,
                "username": username,
                "hasPassword": has_pwd,
                "createdAt": created_at
            }))
        })
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "success": false, "error": e.to_string() })),
            )
        })?;

    let mut list = Vec::new();
    for r in rows {
        if let Ok(v) = r {
            list.push(v);
        }
    }

    Ok(Json(serde_json::json!({ "success": true, "servers": list })))
}

// Thêm máy chủ mới
async fn create_server_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateServerPayload>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = extract_token_from_headers(&headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "success": false, "message": "Chưa xác thực Lớp 1" })),
        )
    })?;
    verify_jwt(&token, &state.config.jwt_secret).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "success": false, "message": "Phiên đăng nhập đã hết hạn" })),
        )
    })?;

    let name = payload.name.trim().to_string();
    let host = payload.host.trim().to_string();
    let port = payload.port.unwrap_or(22);
    let username = payload.username.unwrap_or_else(|| "root".to_string()).trim().to_string();

    if name.is_empty() || host.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "success": false, "message": "Tên máy chủ và Host không được để trống" })),
        ));
    }

    let overwrite = payload.overwrite.unwrap_or(false);
    let conn = state.db.lock().await;

    // 1. Kiểm tra trùng lặp target (host + port + username)
    let dup_target: Option<(String, String)> = conn
        .query_row(
            "SELECT id, name FROM servers WHERE LOWER(host) = LOWER(?1) AND port = ?2 AND LOWER(username) = LOWER(?3)",
            params![host, port, username],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "success": false, "error": e.to_string() })),
            )
        })?;

    if let Some((dup_id, dup_name)) = dup_target {
        if overwrite {
            let master_key = get_master_encryption_key(&state.config.jwt_secret);
            let (enc_secret, iv) = if let Some(ref pass) = payload.password {
                if !pass.is_empty() {
                    let (c, i) = encrypt_password(pass, &master_key).map_err(|e| {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({ "success": false, "error": e })),
                        )
                    })?;
                    (Some(c), Some(i))
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;

            if enc_secret.is_some() {
                conn.execute(
                    "UPDATE servers SET name = ?1, encrypted_secret = ?2, iv = ?3, updated_at = ?4 WHERE id = ?5",
                    params![name, enc_secret, iv, now, dup_id],
                )
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({ "success": false, "error": e.to_string() })),
                    )
                })?;
            } else {
                conn.execute(
                    "UPDATE servers SET name = ?1, updated_at = ?2 WHERE id = ?3",
                    params![name, now, dup_id],
                )
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({ "success": false, "error": e.to_string() })),
                    )
                })?;
            }

            return Ok(Json(serde_json::json!({
                "success": true,
                "updated": true,
                "server": {
                    "id": dup_id,
                    "name": name,
                    "host": host,
                    "port": port,
                    "username": username,
                    "hasPassword": true,
                    "updatedAt": now
                },
                "message": format!("Đã cập nhật máy chủ \"{}\" ({}@{}:{})", name, username, host, port)
            })));
        }

        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "success": false,
                "duplicate": true,
                "duplicateField": "target",
                "existingId": dup_id,
                "existingName": dup_name,
                "message": format!("Máy chủ {}@{}:{} đã có trong danh bạ với tên \"{}\".", username, host, port, dup_name)
            })),
        ));
    }

    // 2. Kiểm tra trùng tên gợi nhớ
    let dup_name_exists: bool = conn
        .query_row(
            "SELECT 1 FROM servers WHERE LOWER(name) = LOWER(?1)",
            params![name],
            |_| Ok(true),
        )
        .optional()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "success": false, "error": e.to_string() })),
            )
        })?
        .unwrap_or(false);

    if dup_name_exists {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "success": false,
                "duplicate": true,
                "duplicateField": "name",
                "message": format!("Tên gợi nhớ \"{}\" đã được sử dụng. Vui lòng chọn tên khác.", name)
            })),
        ));
    }

    let master_key = get_master_encryption_key(&state.config.jwt_secret);
    let (enc_secret, iv) = if let Some(ref pass) = payload.password {
        if !pass.is_empty() {
            let (c, i) = encrypt_password(pass, &master_key).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "success": false, "error": e })),
                )
            })?;
            (Some(c), Some(i))
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    let id = Uuid::new_v4().to_string();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let has_pwd = enc_secret.is_some();

    conn.execute(
        "INSERT INTO servers (id, name, host, port, username, auth_type, encrypted_secret, iv, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 'password', ?6, ?7, ?8, ?9)",
        params![id, name, host, port, username, enc_secret, iv, now, now],
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "success": false, "error": e.to_string() })),
        )
    })?;

    Ok(Json(serde_json::json!({
        "success": true,
        "server": {
            "id": id,
            "name": name,
            "host": host,
            "port": port,
            "username": username,
            "hasPassword": has_pwd,
            "createdAt": now
        }
    })))
}

// Cập nhật máy chủ
async fn update_server_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(payload): Json<UpdateServerPayload>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = extract_token_from_headers(&headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "success": false, "message": "Chưa xác thực Lớp 1" })),
        )
    })?;
    verify_jwt(&token, &state.config.jwt_secret).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "success": false, "message": "Phiên đăng nhập đã hết hạn" })),
        )
    })?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let master_key = get_master_encryption_key(&state.config.jwt_secret);
    let conn = state.db.lock().await;

    let existing: Option<(String, String, u16, String)> = conn
        .query_row(
            "SELECT name, host, port, username FROM servers WHERE id = ?1",
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "success": false, "error": e.to_string() })),
            )
        })?;

    let (cur_name, cur_host, cur_port, cur_user) = match existing {
        Some(t) => t,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "success": false, "message": "Máy chủ không tồn tại" })),
            ));
        }
    };

    let new_name = payload.name.as_deref().map(str::trim).unwrap_or(&cur_name);
    let new_host = payload.host.as_deref().map(str::trim).unwrap_or(&cur_host);
    let new_port = payload.port.unwrap_or(cur_port);
    let new_user = payload.username.as_deref().map(str::trim).unwrap_or(&cur_user);

    // Kiểm tra trùng target với server khác
    let dup_target: Option<String> = conn
        .query_row(
            "SELECT name FROM servers WHERE LOWER(host) = LOWER(?1) AND port = ?2 AND LOWER(username) = LOWER(?3) AND id != ?4",
            params![new_host, new_port, new_user, id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "success": false, "error": e.to_string() })),
            )
        })?;

    if let Some(dup_name) = dup_target {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "success": false,
                "duplicate": true,
                "duplicateField": "target",
                "message": format!("Máy chủ {}@{}:{} đã trùng với máy chủ khác (\"{}\").", new_user, new_host, new_port, dup_name)
            })),
        ));
    }

    // Kiểm tra trùng tên với server khác
    let dup_name_exists: bool = conn
        .query_row(
            "SELECT 1 FROM servers WHERE LOWER(name) = LOWER(?1) AND id != ?2",
            params![new_name, id],
            |_| Ok(true),
        )
        .optional()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "success": false, "error": e.to_string() })),
            )
        })?
        .unwrap_or(false);

    if dup_name_exists {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "success": false,
                "duplicate": true,
                "duplicateField": "name",
                "message": format!("Tên gợi nhớ \"{}\" đã trùng với một máy chủ khác.", new_name)
            })),
        ));
    }

    let _ = conn.execute(
        "UPDATE servers SET name = ?1, host = ?2, port = ?3, username = ?4, updated_at = ?5 WHERE id = ?6",
        params![new_name, new_host, new_port, new_user, now, id],
    );

    if let Some(ref pass) = payload.password {
        if !pass.is_empty() {
            if let Ok((c, i)) = encrypt_password(pass, &master_key) {
                let _ = conn.execute(
                    "UPDATE servers SET encrypted_secret = ?1, iv = ?2, updated_at = ?3 WHERE id = ?4",
                    params![c, i, now, id],
                );
            }
        }
    }

    Ok(Json(serde_json::json!({ "success": true, "message": "Cập nhật máy chủ thành công" })))
}

// Xóa máy chủ
async fn delete_server_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = extract_token_from_headers(&headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "success": false, "message": "Chưa xác thực Lớp 1" })),
        )
    })?;
    verify_jwt(&token, &state.config.jwt_secret).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "success": false, "message": "Phiên đăng nhập đã hết hạn" })),
        )
    })?;

    let conn = state.db.lock().await;
    conn.execute("DELETE FROM servers WHERE id = ?1", params![id])
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "success": false, "error": e.to_string() })),
            )
        })?;

    Ok(Json(serde_json::json!({ "success": true, "message": "Đã xóa máy chủ thành công" })))
}

// ========================================================
// 5. CÁC API PASSKEY / WEBAUTHN (TOUCH ID, FACE ID, HELLO)
// ========================================================

// A. Kiểm tra xem đã có Passkey nào được lưu chưa
async fn passkey_status_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    let passkeys = state.passkeys.read().await;
    Json(serde_json::json!({
        "hasPasskey": !passkeys.is_empty(),
        "count": passkeys.len()
    }))
}

// B. Tạo Challenge để Đăng ký Passkey mới (yêu cầu đã đăng nhập Lớp 1)
async fn passkey_register_challenge_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<CreationChallengeResponse>, (StatusCode, Json<serde_json::Value>)> {
    let token = extract_token_from_headers(&headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "success": false, "message": "Chưa đăng nhập Lớp 1" })),
        )
    })?;

    let claims = verify_jwt(&token, &state.config.jwt_secret).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "success": false, "message": "Token Lớp 1 hết hạn hoặc không hợp lệ" })),
        )
    })?;

    let webauthn = get_webauthn(&headers, &state);
    let user_id = Uuid::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    let passkeys = state.passkeys.read().await;
    let exclude_keys = if passkeys.is_empty() {
        None
    } else {
        Some(passkeys.iter().map(|p| p.cred_id().clone()).collect())
    };

    let (ccr, reg_state) = webauthn.start_passkey_registration(
        user_id,
        &claims.username,
        "Administrator",
        exclude_keys,
    ).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "success": false,
                "message": format!("Lỗi khởi tạo đăng ký Passkey: {:?}", e)
            })),
        )
    })?;

    let mut reg_map = state.reg_state.lock().await;
    let now = std::time::Instant::now();
    reg_map.retain(|_, (_, t)| now.duration_since(*t) < Duration::from_secs(120));
    reg_map.insert(claims.username.clone(), (reg_state, now));
    Ok(Json(ccr))
}

// C. Xác thực và Lưu Passkey mới
async fn passkey_register_verify_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(reg_cred): Json<RegisterPublicKeyCredential>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = extract_token_from_headers(&headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "success": false, "message": "Chưa đăng nhập Lớp 1" })),
        )
    })?;

    let claims = verify_jwt(&token, &state.config.jwt_secret).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "success": false, "message": "Token Lớp 1 hết hạn hoặc không hợp lệ" })),
        )
    })?;

    let (reg_state, created_at) = state
        .reg_state
        .lock()
        .await
        .remove(&claims.username)
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "success": false,
                    "message": "Phiên đăng ký Passkey đã hết hạn. Vui lòng bấm thử lại."
                })),
            )
        })?;

    if created_at.elapsed() > Duration::from_secs(120) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "success": false,
                "message": "Phiên đăng ký Passkey đã quá thời gian (120s). Vui lòng thử lại."
            })),
        ));
    }

    let webauthn = get_webauthn(&headers, &state);
    match webauthn.finish_passkey_registration(&reg_cred, &reg_state) {
        Ok(passkey) => {
            let mut passkeys = state.passkeys.write().await;
            passkeys.push(passkey);
            save_passkeys(&passkeys);
            Ok(Json(serde_json::json!({
                "success": true,
                "message": "Đã lưu Passkey thiết bị thành công! Lần sau bạn có thể chạm vân tay để đăng nhập nhanh."
            })))
        }
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "success": false,
                "message": format!("Xác thực đăng ký Passkey thất bại: {:?}", e)
            })),
        )),
    }
}

// D. Tạo Challenge để Đăng nhập bằng Passkey (Không cần mật khẩu)
async fn passkey_login_challenge_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<RequestChallengeResponse>, (StatusCode, Json<serde_json::Value>)> {
    let client_ip = get_client_ip(&headers);

    // Rate limiting cho Passkey challenge (tối đa 10 lần / phút per IP)
    {
        let mut limiter = state.passkey_limiter.lock().await;
        let now = std::time::Instant::now();
        limiter.retain(|_, (_, t)| now.duration_since(*t) < Duration::from_secs(60));
        let entry = limiter.entry(client_ip.clone()).or_insert((0, now));
        if entry.0 >= 10 {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "success": false,
                    "message": "Quá nhiều yêu cầu xác thực Passkey. Vui lòng thử lại sau 1 phút."
                })),
            ));
        }
        entry.0 += 1;
        entry.1 = now;
    }

    let passkeys = state.passkeys.read().await;
    if passkeys.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "success": false,
                "message": "Chưa có Passkey nào được đăng ký trên thiết bị này"
            })),
        ));
    }

    let webauthn = get_webauthn(&headers, &state);
    match webauthn.start_passkey_authentication(&passkeys) {
        Ok((rcr, auth_state)) => {
            let mut map = state.auth_state.lock().await;
            let now = std::time::Instant::now();
            map.retain(|_, (_, t)| now.duration_since(*t) < Duration::from_secs(120));
            map.insert(client_ip, (auth_state, now));
            Ok(Json(rcr))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "success": false,
                "message": format!("Lỗi tạo phiên đăng nhập Passkey: {:?}", e)
            })),
        )),
    }
}

// E. Xác thực chữ ký Passkey và Đăng nhập Lớp 1
async fn passkey_login_verify_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(auth_cred): Json<PublicKeyCredential>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let client_ip = get_client_ip(&headers);
    let (auth_state, created_at) = state
        .auth_state
        .lock()
        .await
        .remove(&client_ip)
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "success": false,
                    "message": "Phiên xác thực Passkey đã hết hạn hoặc không tìm thấy. Vui lòng bấm thử lại."
                })),
            )
        })?;

    if created_at.elapsed() > Duration::from_secs(120) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "success": false,
                "message": "Phiên xác thực Passkey đã quá thời gian (120s). Vui lòng thử lại."
            })),
        ));
    }

    let webauthn = get_webauthn(&headers, &state);
    match webauthn.finish_passkey_authentication(&auth_cred, &auth_state) {
        Ok(auth_res) => {
            // Cập nhật counter chống replay attack
            let mut passkeys = state.passkeys.write().await;
            if let Some(pk) = passkeys.iter_mut().find(|p| p.cred_id() == auth_res.cred_id()) {
                pk.update_credential(&auth_res);
                save_passkeys(&passkeys);
            }

            {
                let mut limiter = state.passkey_limiter.lock().await;
                limiter.remove(&client_ip);
            }

            let token = match create_jwt(&state.config.layer1_user, &state.config.jwt_secret) {
                Ok(t) => t,
                Err(_) => {
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({ "success": false, "message": "Không thể tạo mã JWT" })),
                    ))
                }
            };

            let is_sec = is_request_secure(&headers);
            let cookie_val = build_auth_cookie(&token, 7 * 24 * 3600, is_sec);

            let body = Json(serde_json::json!({
                "success": true,
                "user": { "username": state.config.layer1_user, "role": "admin" },
                "token": token
            }));

            let mut res = body.into_response();
            if let Ok(hv) = cookie_val.parse() {
                res.headers_mut().insert(header::SET_COOKIE, hv);
            }
            Ok(res)
        }
        Err(e) => Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "success": false,
                "message": format!("Xác thực Passkey (Touch ID) không thành công: {:?}", e)
            })),
        )),
    }
}

// ========================================================
// 6. WEBSOCKET TERMINAL GATEWAY (LỚP 2: SSH)
// ========================================================
async fn ws_terminal_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: axum::http::Uri,
) -> Response {
    // Chống Cross-Site WebSocket Hijacking (CSWSH): Xác thực header Origin
    if let Some(origin_val) = headers.get(header::ORIGIN) {
        if let Ok(origin_str) = origin_val.to_str() {
            if !is_allowed_origin(origin_str, &headers) {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "type": "error",
                        "message": "Từ chối: Cross-Site WebSocket Origin không được phép"
                    })),
                ).into_response();
            }
        }
    }

    let mut token = extract_token_from_headers(&headers);
    if token.is_none() {
        if let Some(query) = uri.query() {
            for pair in query.split('&') {
                if let Some(val) = pair.strip_prefix("token=") {
                    token = Some(val.to_string());
                    break;
                }
            }
        }
    }

    let is_authorized = match token {
        Some(ref t) => verify_jwt(t, &state.config.jwt_secret).is_ok(),
        None => false,
    };

    if !is_authorized {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "type": "error",
                "message": "Từ chối: Chưa xác thực Lớp 1"
            })),
        )
            .into_response();
    }

    ws.on_upgrade(move |socket| handle_terminal_socket(socket, state))
}

async fn handle_terminal_socket(mut socket: WebSocket, state: AppState) {
    let (from_ssh_tx, mut from_ssh_rx) = tokio::sync::mpsc::channel::<SshEvent>(100);
    let mut to_ssh_tx: Option<mpsc::Sender<SshCommand>> = None;
    let is_cancelled = Arc::new(AtomicBool::new(false));
    let mut ssh_thread_handle: Option<std::thread::JoinHandle<()>> = None;

    let idle_timeout_secs: u64 = std::env::var("TERMINAL_IDLE_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1800); // Mặc định 30 phút (0 = tắt timeout)
    let mut last_activity = std::time::Instant::now();

    // Heartbeat ticker to keep Cloudflare Tunnel, reverse proxies, and browser sockets alive (every 20s)
    let mut heartbeat_interval = tokio::time::interval(tokio::time::Duration::from_secs(20));
    heartbeat_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat_interval.tick().await;

    loop {
        tokio::select! {
            // Heartbeat & Timeout: tự động ngắt kết nối phiên nhàn rỗi sau thời gian quy định
            _ = heartbeat_interval.tick() => {
                if idle_timeout_secs > 0 && last_activity.elapsed() >= std::time::Duration::from_secs(idle_timeout_secs) {
                    let mins = idle_timeout_secs / 60;
                    let warning = format!(
                        "\r\n\x1b[1;33m[NexConsole] Phiên làm việc đã tự động ngắt kết nối do không có thao tác trong {} phút.\x1b[0m\r\n",
                        mins
                    );
                    let payload = serde_json::json!({ "type": "status", "message": warning });
                    let _ = socket.send(Message::Text(payload.to_string())).await;
                    break;
                }
                if socket.send(Message::Ping(vec![])).await.is_err() {
                    break;
                }
            }

            // Nhận output từ SSH thread và gửi về client qua WebSocket
            Some(event) = from_ssh_rx.recv() => {
                match event {
                    SshEvent::Status(message) => {
                        let payload = serde_json::json!({ "type": "status", "message": message });
                        if socket.send(Message::Text(payload.to_string())).await.is_err() {
                            break;
                        }
                    }
                    SshEvent::SshError(message) => {
                        let payload = serde_json::json!({ "type": "ssh_error", "message": message });
                        let _ = socket.send(Message::Text(payload.to_string())).await;
                    }
                    SshEvent::Output(text) => {
                        let payload = serde_json::json!({ "type": "data", "data": text });
                        if socket.send(Message::Text(payload.to_string())).await.is_err() {
                            break;
                        }
                    }
                    SshEvent::Disconnected => {
                        let payload = serde_json::json!({ "type": "status", "message": "\nPhiên SSH đã kết thúc." });
                        let _ = socket.send(Message::Text(payload.to_string())).await;
                        break;
                    }
                }
            }

            // Nhận message từ client WebSocket
            incoming = socket.recv() => {
                let msg = match incoming {
                    Some(Ok(m)) => m,
                    _ => break,
                };

                let text = match msg {
                    Message::Text(t) => t,
                    Message::Close(_) => break,
                    Message::Ping(payload) => {
                        let _ = socket.send(Message::Pong(payload)).await;
                        continue;
                    }
                    Message::Pong(_) => continue,
                    _ => continue,
                };

                if let Ok(client_msg) = serde_json::from_str::<WsClientMessage>(&text) {
                    match client_msg {
                        WsClientMessage::Ping => {
                            let _ = socket.send(Message::Text(r#"{"type":"pong"}"#.to_string())).await;
                        }
                        WsClientMessage::Pong => {}
                        WsClientMessage::SshConnect {
                            server_id,
                            host,
                            port,
                            username,
                            password,
                            cols,
                            rows,
                        } => {
                            last_activity = std::time::Instant::now();
                            if let Some(old_tx) = to_ssh_tx.take() {
                                let _ = old_tx.send(SshCommand::Disconnect);
                            }

                            let (tx, rx) = mpsc::channel::<SshCommand>();
                            to_ssh_tx = Some(tx);

                            let mut ssh_host = state.config.ssh_host.clone();
                            let mut ssh_port = state.config.ssh_port;
                            let mut user = "root".to_string();
                            let mut pass = String::new();

                            if let Some(sid) = server_id {
                                let conn = state.db.lock().await;
                                let row_opt: Option<(String, u16, String, Option<String>, Option<String>)> = conn
                                    .query_row(
                                        "SELECT host, port, username, encrypted_secret, iv FROM servers WHERE id = ?1",
                                        params![sid],
                                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                                    )
                                    .ok();

                                if let Some((db_host, db_port, db_user, db_enc, db_iv)) = row_opt {
                                    ssh_host = db_host;
                                    ssh_port = db_port;
                                    user = db_user;
                                    if let (Some(enc), Some(iv)) = (db_enc, db_iv) {
                                        let master_key = get_master_encryption_key(&state.config.jwt_secret);
                                        if let Ok(decrypted) = decrypt_password(&enc, &iv, &master_key) {
                                            pass = decrypted;
                                        }
                                    }
                                }
                            } else {
                                if let Some(raw_h) = host {
                                    let trimmed = raw_h.trim();
                                    if !trimmed.is_empty() {
                                        if let Some((h_part, p_part)) = trimmed.split_once(':') {
                                            ssh_host = h_part.trim().to_string();
                                            if let Ok(parsed_p) = p_part.trim().parse::<u16>() {
                                                ssh_port = parsed_p;
                                            }
                                        } else {
                                            ssh_host = trimmed.to_string();
                                        }
                                    }
                                }
                                if let Some(p) = port {
                                    ssh_port = p;
                                }
                                if let Some(u) = username {
                                    user = u;
                                }
                                if let Some(pw) = password {
                                    pass = pw;
                                }
                            }

                            let term_cols = cols.unwrap_or(100);
                            let term_rows = rows.unwrap_or(30);

                            let event_tx = from_ssh_tx.clone();
                            let is_cancel = Arc::clone(&is_cancelled);

                            let handle = std::thread::spawn(move || {
                                run_ssh_session(
                                    ssh_host,
                                    ssh_port,
                                    user,
                                    pass,
                                    term_cols,
                                    term_rows,
                                    rx,
                                    event_tx,
                                    is_cancel,
                                );
                            });
                            ssh_thread_handle = Some(handle);
                        }
                        WsClientMessage::SshDisconnect => {
                            if let Some(old_tx) = to_ssh_tx.take() {
                                let _ = old_tx.send(SshCommand::Disconnect);
                            }
                        }
                        WsClientMessage::Data { data } => {
                            last_activity = std::time::Instant::now();
                            if let Some(ref tx) = to_ssh_tx {
                                let _ = tx.send(SshCommand::Data(data.into_bytes()));
                            }
                        }
                        WsClientMessage::Resize { cols, rows } => {
                            last_activity = std::time::Instant::now();
                            let safe_cols = cols.clamp(10, 500);
                            let safe_rows = rows.clamp(5, 200);
                            if let Some(ref tx) = to_ssh_tx {
                                let _ = tx.send(SshCommand::Resize { cols: safe_cols, rows: safe_rows });
                            }
                        }
                    }
                }
            }
        }
    }

    // Dọn dẹp phiên khi kết thúc
    is_cancelled.store(true, Ordering::Relaxed);
    if let Some(tx) = to_ssh_tx.take() {
        let _ = tx.send(SshCommand::Disconnect);
    }
    if let Some(handle) = ssh_thread_handle {
        let _ = handle.join();
    }
}

fn run_ssh_session(
    host: String,
    port: u16,
    user: String,
    pass: String,
    cols: u32,
    rows: u32,
    cmd_rx: mpsc::Receiver<SshCommand>,
    event_tx: tokio::sync::mpsc::Sender<SshEvent>,
    is_cancelled: Arc<AtomicBool>,
) {
    let addr_str = format!("{}:{}", host, port);
    let socket_addrs: Vec<SocketAddr> = match addr_str.to_socket_addrs() {
        Ok(addrs) => addrs.collect(),
        Err(e) => {
            let _ = event_tx.blocking_send(SshEvent::SshError(format!(
                "Không thể phân giải địa chỉ SSH {}: {}",
                addr_str, e
            )));
            let _ = event_tx.blocking_send(SshEvent::Disconnected);
            return;
        }
    };

    if socket_addrs.is_empty() {
        let _ = event_tx.blocking_send(SshEvent::SshError(format!(
            "Không tìm thấy địa chỉ IP cho {}",
            addr_str
        )));
        let _ = event_tx.blocking_send(SshEvent::Disconnected);
        return;
    }

    let tcp = match TcpStream::connect_timeout(&socket_addrs[0], Duration::from_secs(5)) {
        Ok(s) => s,
        Err(e) => {
            let _ = event_tx.blocking_send(SshEvent::SshError(format!(
                "Không thể kết nối tới SSH ({}:{}): {}",
                host, port, e
            )));
            let _ = event_tx.blocking_send(SshEvent::Disconnected);
            return;
        }
    };

    let mut sess = match Session::new() {
        Ok(s) => s,
        Err(e) => {
            let _ = event_tx.blocking_send(SshEvent::SshError(format!(
                "Lỗi khởi tạo phiên SSH: {}",
                e
            )));
            let _ = event_tx.blocking_send(SshEvent::Disconnected);
            return;
        }
    };

    sess.set_tcp_stream(tcp);
    sess.set_timeout(10000);

    if let Err(e) = sess.handshake() {
        let _ = event_tx.blocking_send(SshEvent::SshError(format!(
            "Bắt tay SSH thất bại: {}",
            e
        )));
        let _ = event_tx.blocking_send(SshEvent::Disconnected);
        return;
    }

    if let Err(_) = sess.userauth_password(&user, &pass) {
        let _ = event_tx.blocking_send(SshEvent::SshError(
            "Sai tên đăng nhập hoặc mật khẩu SSH (Lớp 2)!".to_string(),
        ));
        let _ = event_tx.blocking_send(SshEvent::Disconnected);
        return;
    }

    if !sess.authenticated() {
        let _ = event_tx.blocking_send(SshEvent::SshError(
            "Xác thực SSH không thành công.".to_string(),
        ));
        let _ = event_tx.blocking_send(SshEvent::Disconnected);
        return;
    }

    let mut channel = match sess.channel_session() {
        Ok(c) => c,
        Err(e) => {
            let _ = event_tx.blocking_send(SshEvent::SshError(format!(
                "Không thể mở SSH Channel: {}",
                e
            )));
            let _ = event_tx.blocking_send(SshEvent::Disconnected);
            return;
        }
    };

    if let Err(e) = channel.request_pty("xterm-256color", None, Some((cols, rows, 0, 0))) {
        let _ = event_tx.blocking_send(SshEvent::SshError(format!(
            "Không thể cấp phát PTY: {}",
            e
        )));
        let _ = event_tx.blocking_send(SshEvent::Disconnected);
        return;
    }

    // Đặt biến môi trường qua SSH channel request (hoàn toàn ngầm, không in lệnh ra màn hình)
    let _ = channel.setenv("WEBCONSOLE", "1");
    let _ = channel.setenv("WEBCONSOLE_SESSION", "1");
    let _ = channel.setenv("LC_WEBCONSOLE", "1");
    let _ = channel.setenv("LC_TERMINAL", "webconsole");

    if let Err(e) = channel.shell() {
        let _ = event_tx.blocking_send(SshEvent::SshError(format!(
            "Không thể khởi động Shell: {}",
            e
        )));
        let _ = event_tx.blocking_send(SshEvent::Disconnected);
        return;
    }

    // Gửi thông báo status để frontend tự động ẩn Modal Lớp 2!
    let _ = event_tx.blocking_send(SshEvent::Status(format!(
        "Đã kết nối SSH thành công tới {}@{}:{}",
        user, host, port
    )));

    // Tắt timeout cố định 10s để phiên terminal duy trì vô thời hạn
    sess.set_timeout(0);
    // Chuyển sang chế độ non-blocking để đọc/ghi mượt mà
    sess.set_blocking(false);
    let mut read_buf = [0u8; 4096];

    let write_channel_bytes = |chan: &mut ssh2::Channel, mut data: &[u8]| {
        while !data.is_empty() {
            match chan.write(data) {
                Ok(0) => break,
                Ok(n) => data = &data[n..],
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(_) => break,
            }
        }
        let _ = chan.flush();
    };

    loop {
        if is_cancelled.load(Ordering::Relaxed) {
            break;
        }

        // 1. Xử lý các lệnh từ WebSocket (bàn phím gõ / resize)
        while let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                SshCommand::Data(bytes) => {
                    write_channel_bytes(&mut channel, &bytes);
                }
                SshCommand::Resize { cols, rows } => {
                    let _ = channel.request_pty_size(cols, rows, None, None);
                }
                SshCommand::Disconnect => return,
            }
        }

        // 2. Đọc luồng dữ liệu từ SSH channel
        match channel.read(&mut read_buf) {
            Ok(0) => {
                if channel.eof() {
                    let _ = event_tx.blocking_send(SshEvent::Disconnected);
                    break;
                }
                // Nếu chưa EOF, chờ lệnh bàn phím với timeout 10ms (tránh quay CPU 100%)
                match cmd_rx.recv_timeout(Duration::from_millis(10)) {
                    Ok(SshCommand::Data(bytes)) => write_channel_bytes(&mut channel, &bytes),
                    Ok(SshCommand::Resize { cols, rows }) => {
                        let _ = channel.request_pty_size(cols, rows, None, None);
                    }
                    Ok(SshCommand::Disconnect) => return,
                    Err(_) => {}
                }
            }
            Ok(n) => {
                let text = String::from_utf8_lossy(&read_buf[..n]).to_string();
                if event_tx.blocking_send(SshEvent::Output(text)).is_err() {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                // Không có dữ liệu đọc ngay -> chờ lệnh từ phím gõ với timeout 10ms (tiết kiệm 100% CPU)
                match cmd_rx.recv_timeout(Duration::from_millis(10)) {
                    Ok(SshCommand::Data(bytes)) => write_channel_bytes(&mut channel, &bytes),
                    Ok(SshCommand::Resize { cols, rows }) => {
                        let _ = channel.request_pty_size(cols, rows, None, None);
                    }
                    Ok(SshCommand::Disconnect) => return,
                    Err(_) => {}
                }
            }
            Err(e) => {
                eprintln!("SSH Channel read error: {:?}, kind={:?}", e, e.kind());
                let _ = event_tx.blocking_send(SshEvent::Disconnected);
                break;
            }
        }
    }

    let _ = channel.close();
}

fn is_running_in_webconsole() -> bool {
    std::env::var("WEBCONSOLE").is_ok() || std::env::var("WEBCONSOLE_SESSION").is_ok()
}

fn handle_cli_command(args: &[String], jwt_secret: &str) {
    if is_running_in_webconsole() {
        eprintln!("================================================================================");
        eprintln!("[SECURITY ERROR] ACCESS DENIED: CANNOT EXECUTE INSIDE WEBCONSOLE");
        eprintln!("================================================================================");
        eprintln!("This administrative CLI command can only be executed directly on the host console.");
        eprintln!("Execution via the WebConsole terminal is strictly forbidden for security reasons!");
        eprintln!("================================================================================");
        std::process::exit(1);
    }

    let conn = match init_sqlite_db() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[ERROR] Failed to open SQLite database: {}", e);
            std::process::exit(1);
        }
    };

    let subcmd = if args.len() > 1 && (args[1] == "user" || args[1] == "cli") {
        if args.len() > 2 { args[2].as_str() } else { "help" }
    } else if args.len() > 1 {
        args[1].as_str()
    } else {
        "help"
    };

    let arg_offset = if args.len() > 1 && (args[1] == "user" || args[1] == "cli") { 3 } else { 2 };

    match subcmd {
        "list" | "ls" => {
            println!("+-----+-----------------+----------------------+--------------------------------+----------+----------+");
            println!("| No. | USERNAME        | DISPLAY NAME         | EMAIL                          | 2FA      | PASSKEYS |");
            println!("+-----+-----------------+----------------------+--------------------------------+----------+----------+");
            let passkeys = load_passkeys();
            let mut stmt = match conn.prepare("SELECT username, display_name, email, totp_enabled FROM user_security ORDER BY username ASC") {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[ERROR] Failed to query users: {}", e);
                    std::process::exit(1);
                }
            };
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                    r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    r.get::<_, i64>(3)? == 1,
                ))
            }).unwrap();

            let mut count = 0;
            for r in rows {
                if let Ok((u, name, mail, totp)) = r {
                    count += 1;
                    let pass_count = if u == "admin" { passkeys.len() } else { 0 };
                    let totp_str = if totp { "Enabled" } else { "Disabled" };
                    println!(
                        "| {:<3} | {:<15} | {:<20} | {:<30} | {:<8} | {:<8} |",
                        count, u, name, mail, totp_str, pass_count
                    );
                }
            }
            if count == 0 {
                println!("| (No users found in database)                                                                 |");
            }
            println!("+-----+-----------------+----------------------+--------------------------------+----------+----------+");
            println!("Total: {} user(s), {} stored passkey(s).", count, passkeys.len());
        }
        "add" => {
            if args.len() < arg_offset + 2 {
                eprintln!("[ERROR] Missing arguments. Usage: ./nexctl add <username> <password> [display_name] [email]");
                std::process::exit(1);
            }
            let u = &args[arg_offset];
            let p = &args[arg_offset + 1];
            let name = if args.len() > arg_offset + 2 { &args[arg_offset + 2] } else { u };
            let email = if args.len() > arg_offset + 3 { args[arg_offset + 3].clone() } else { format!("{}@nexspace.vn", u) };

            if p.len() < 6 {
                eprintln!("[ERROR] Password must be at least 6 characters long!");
                std::process::exit(1);
            }

            let hash = hash_password(p, jwt_secret);
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;

            match conn.execute(
                "INSERT INTO user_security (username, display_name, email, totp_secret, totp_enabled, totp_verified_at, password_hash, updated_at)
                 VALUES (?1, ?2, ?3, NULL, 0, NULL, ?4, ?5)
                 ON CONFLICT(username) DO UPDATE SET display_name = ?2, email = ?3, password_hash = ?4, updated_at = ?5",
                params![u, name, email, hash, now],
            ) {
                Ok(_) => println!("[SUCCESS] User '{}' added/updated successfully!", u),
                Err(e) => eprintln!("[ERROR] Failed to add user: {}", e),
            }
        }
        "passwd" => {
            if args.len() < arg_offset + 2 {
                eprintln!("[ERROR] Missing arguments. Usage: ./nexctl passwd <username> <new_password>");
                std::process::exit(1);
            }
            let u = &args[arg_offset];
            let p = &args[arg_offset + 1];
            if p.len() < 6 {
                eprintln!("[ERROR] Password must be at least 6 characters long!");
                std::process::exit(1);
            }
            let hash = hash_password(p, jwt_secret);
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
            let affected = conn.execute(
                "UPDATE user_security SET password_hash = ?1, updated_at = ?2 WHERE username = ?3",
                params![hash, now, u],
            ).unwrap_or(0);
            if affected > 0 {
                println!("[SUCCESS] Password changed successfully for user '{}'!", u);
            } else {
                eprintln!("[ERROR] User '{}' does not exist!", u);
            }
        }
        "email" => {
            if args.len() < arg_offset + 2 {
                eprintln!("[ERROR] Missing arguments. Usage: ./nexctl email <username> <new_email>");
                std::process::exit(1);
            }
            let u = &args[arg_offset];
            let mail = &args[arg_offset + 1];
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
            let affected = conn.execute(
                "UPDATE user_security SET email = ?1, updated_at = ?2 WHERE username = ?3",
                params![mail, now, u],
            ).unwrap_or(0);
            if affected > 0 {
                println!("[SUCCESS] Updated email to '{}' for user '{}'!", mail, u);
            } else {
                eprintln!("[ERROR] User '{}' does not exist!", u);
            }
        }
        "disable-2fa" => {
            if args.len() < arg_offset + 1 {
                eprintln!("[ERROR] Missing arguments. Usage: ./nexctl disable-2fa <username>");
                std::process::exit(1);
            }
            let u = &args[arg_offset];
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
            let affected = conn.execute(
                "UPDATE user_security SET totp_enabled = 0, totp_secret = NULL, totp_verified_at = NULL, updated_at = ?1 WHERE username = ?2",
                params![now, u],
            ).unwrap_or(0);
            if affected > 0 {
                println!("[SUCCESS] Disabled two-factor authentication (2FA) for user '{}'!", u);
            } else {
                eprintln!("[ERROR] User '{}' does not exist!", u);
            }
        }
        "clear-passkeys" => {
            if args.len() < arg_offset + 1 {
                eprintln!("[ERROR] Missing arguments. Usage: ./nexctl clear-passkeys <username>");
                std::process::exit(1);
            }
            let u = &args[arg_offset];
            save_passkeys(&[]);
            println!("[SUCCESS] Cleared all stored Passkeys for user '{}'!", u);
        }
        "delete" | "rm" => {
            if args.len() < arg_offset + 1 {
                eprintln!("[ERROR] Missing arguments. Usage: ./nexctl delete <username>");
                std::process::exit(1);
            }
            let u = &args[arg_offset];
            if u == "admin" {
                eprintln!("[WARNING] Cannot delete the default system 'admin' account!");
                std::process::exit(1);
            }
            let affected = conn.execute("DELETE FROM user_security WHERE username = ?1", params![u]).unwrap_or(0);
            if affected > 0 {
                println!("[SUCCESS] Deleted user '{}' from the system!", u);
            } else {
                eprintln!("[ERROR] User '{}' does not exist!", u);
            }
        }
        "random-admin" | "reset-admin" | "random-pass" | "init" => {
            let u = if args.len() > arg_offset { &args[arg_offset] } else { "admin" };
            let new_pass = generate_secure_password(16);
            let hash = hash_password(&new_pass, jwt_secret);
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;

            let _ = conn.execute(
                "INSERT INTO user_security (username, display_name, email, totp_secret, totp_enabled, totp_verified_at, password_hash, updated_at)
                 VALUES (?1, 'Administrator', 'admin@nexspace.vn', NULL, 0, NULL, ?2, ?3)
                 ON CONFLICT(username) DO UPDATE SET password_hash = ?2, updated_at = ?3",
                params![u, hash, now],
            );

            update_env_var("LAYER1_PASS", &new_pass);

            let port = std::env::var("PORT").unwrap_or_else(|_| "7681".to_string());

            println!("================================================================================");
            println!("       NEXCONSOLE LOGIN CREDENTIALS");
            println!("================================================================================");
            println!("  Url:       http://localhost:{}  (or http://<SERVER_IP>:{})", port, port);
            println!("  Username:  {}", u);
            println!("  Password:  {}", new_pass);
            println!("================================================================================");
            println!("Notice: Credentials encrypted and saved to SQLite + .env. Please save this!");
            println!("================================================================================");
        }
        _ => {
            println!("================================================================================");
            println!("       NEXCONSOLE - COMMAND LINE MANAGEMENT UTILITY (NEXCTL)");
            println!("================================================================================");
            println!("Notice: This command can only be executed directly on the host server console.");
            println!("        Execution inside the WebConsole terminal is forbidden for security.\n");
            println!("USAGE:");
            println!("  ./nexctl <command> [arguments...]");
            println!("  or: ./target/release/nexconsole user <command> [arguments...]\n");
            println!("AVAILABLE COMMANDS:");
            println!("  list                               Display all registered user accounts");
            println!("  add <user> <pass> [name] [email]   Add or update user account");
            println!("  passwd <user> <new_pass>           Change account password (min 6 chars)");
            println!("  random-admin [user]                Generate secure random password and print login card");
            println!("  email <user> <new_email>           Update user email address");
            println!("  disable-2fa <user>                 Disable two-factor authentication (TOTP)");
            println!("  clear-passkeys <user>              Clear all registered Touch ID / Passkeys");
            println!("  delete <user>                      Delete user account from system");
            println!("================================================================================");
        }
    }
    std::process::exit(0);
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let env_path = std::path::Path::new(".env");
    let mut first_run_creds: Option<(String, String)> = None;

    if !env_path.exists() {
        let random_jwt = generate_random_hex(24);
        let random_admin_pass = generate_secure_password(16);
        let env_content = format!(
            "# NexConsole Environment Configuration\nPORT=7681\nJWT_SECRET={}\nLAYER1_USER=admin\nLAYER1_PASS=\"{}\"\nSSH_HOST=127.0.0.1\nSSH_PORT=22\n",
            random_jwt, random_admin_pass
        );
        let _ = std::fs::write(env_path, env_content);
        first_run_creds = Some(("admin".to_string(), random_admin_pass));
    }

    let _ = dotenvy::dotenv();

    let jwt_secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "nexconsole_secret_jwt_key_999888_secure".to_string());

    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && (args[1] == "user" || args[1] == "cli" || args[1] == "help" || args[1] == "--help" || args[1] == "-h" || args[1] == "list" || args[1] == "add" || args[1] == "passwd" || args[1] == "email" || args[1] == "disable-2fa" || args[1] == "clear-passkeys" || args[1] == "delete" || args[1] == "random-admin" || args[1] == "reset-admin" || args[1] == "random-pass" || args[1] == "init") {
        handle_cli_command(&args, &jwt_secret);
        return;
    }

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(7681);

    let layer1_user = std::env::var("LAYER1_USER")
        .unwrap_or_else(|_| "admin".to_string());

    let layer1_pass = std::env::var("LAYER1_PASS")
        .unwrap_or_else(|_| "Quangtuong!@#123".to_string());

    let ssh_host = std::env::var("SSH_HOST")
        .unwrap_or_else(|_| "127.0.0.1".to_string());

    let ssh_port: u16 = std::env::var("SSH_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(2222);

    let config = Arc::new(AppConfig {
        port,
        jwt_secret: jwt_secret.clone(),
        layer1_user,
        layer1_pass,
        ssh_host: ssh_host.clone(),
        ssh_port,
    });

    // 1. Cấu hình WebAuthn cho Localhost
    let local_origin = Url::parse(&format!("http://localhost:{}", port))
        .expect("Invalid localhost URL");
    let webauthn_local = Arc::new(
        WebauthnBuilder::new("localhost", &local_origin)
            .expect("Invalid local Webauthn builder")
            .rp_name("NexConsole Local Gateway")
            .build()
            .expect("Failed to build local Webauthn"),
    );

    // 2. Cấu hình WebAuthn cho Domain Cloud (console.nexspace.vn & webconsole.nexspace.vn)
    let cloud_origin = Url::parse("https://console.nexspace.vn")
        .expect("Invalid cloud URL");
    let legacy_origin = Url::parse("https://webconsole.nexspace.vn")
        .expect("Invalid legacy cloud URL");
    let webauthn_cloud = Arc::new(
        WebauthnBuilder::new("nexspace.vn", &cloud_origin)
            .expect("Invalid cloud Webauthn builder")
            .append_allowed_origin(&legacy_origin)
            .rp_name("NexConsole Gateway")
            .build()
            .expect("Failed to build cloud Webauthn"),
    );

    let initial_passkeys = load_passkeys();
    println!("[Passkeys] Loaded {} passkey(s) from secure storage.", initial_passkeys.len());

    let sqlite_conn = init_sqlite_db().expect("Failed to initialize SQLite database");
    println!("[SQLite] Connected to server management SQLite database.");

    if let Some((ref u, ref pass)) = first_run_creds {
        let hash = hash_password(pass, &jwt_secret);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let _ = sqlite_conn.execute(
            "INSERT INTO user_security (username, display_name, email, totp_secret, totp_enabled, totp_verified_at, password_hash, updated_at)
             VALUES (?1, 'Administrator', 'admin@nexspace.vn', NULL, 0, NULL, ?2, ?3)
             ON CONFLICT(username) DO UPDATE SET password_hash = ?2, updated_at = ?3",
            params![u, hash, now],
        );
    }

    let state = AppState {
        config,
        webauthn_local,
        webauthn_cloud,
        passkeys: Arc::new(tokio::sync::RwLock::new(initial_passkeys)),
        reg_state: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        auth_state: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        db: Arc::new(tokio::sync::Mutex::new(sqlite_conn)),
        login_limiter: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        twofa_limiter: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        passkey_limiter: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        pwd_change_limiter: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
    };

    // Tìm thư mục public tĩnh
    let public_dir = if PathBuf::from("public").exists() {
        PathBuf::from("public")
    } else if PathBuf::from("../public").exists() {
        PathBuf::from("../public")
    } else {
        PathBuf::from("public")
    };

    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::predicate(|origin: &axum::http::HeaderValue, _| {
            if let Ok(s) = origin.to_str() {
                if let Ok(u) = url::Url::parse(s) {
                    if let Some(host) = u.host_str() {
                        return host == "localhost"
                            || host == "127.0.0.1"
                            || host == "::1"
                            || host == "nexspace.vn"
                            || host.ends_with(".nexspace.vn");
                    }
                }
            }
            false
        }))
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
            header::COOKIE,
            header::UPGRADE,
            header::CONNECTION,
            axum::http::HeaderName::from_static("x-requested-with"),
        ])
        .allow_credentials(true);

    let app = Router::new()
        // API Auth Lớp 1 (Mật khẩu & 2FA OTP)
        .route("/api/auth/login", post(login_handler))
        .route("/api/auth/me", get(me_handler))
        .route("/api/auth/logout", post(logout_handler))
        .route("/api/auth/2fa/login-verify", post(twofa_login_verify_handler))
        .route("/api/auth/2fa/status", get(twofa_status_handler))
        .route("/api/auth/2fa/setup", post(twofa_setup_handler))
        .route("/api/auth/2fa/enable", post(twofa_enable_handler))
        .route("/api/auth/2fa/disable", post(twofa_disable_handler))
        // API Hồ sơ cá nhân & Đổi mật khẩu
        .route("/api/auth/profile", get(profile_get_handler).post(profile_update_handler))
        .route("/api/auth/profile/password", post(profile_password_handler))
        .route("/api/auth/profile/quick-commands", post(profile_quick_commands_handler))
        // Trang Account & Security (hỗ trợ cả /account/ và /acount/)
        .route("/account", get(account_page_handler))
        .route("/account/", get(account_page_handler))
        .route("/acount", get(account_page_handler))
        .route("/acount/", get(account_page_handler))
        // API Passkey / WebAuthn (Touch ID, Face ID)
        .route("/api/auth/passkey/status", get(passkey_status_handler))
        .route("/api/auth/passkey/register-challenge", get(passkey_register_challenge_handler))
        .route("/api/auth/passkey/register-verify", post(passkey_register_verify_handler))
        .route("/api/auth/passkey/login-challenge", get(passkey_login_challenge_handler))
        .route("/api/auth/passkey/login-verify", post(passkey_login_verify_handler))
        // API Quản lý Máy chủ SSH (SQLite + AES-256)
        .route("/api/servers", get(list_servers_handler).post(create_server_handler))
        .route("/api/servers/:id", put(update_server_handler).delete(delete_server_handler))
        // API Stats & WebSocket SSH
        .route("/api/system/stats", get(stats_handler))
        .route("/ws/terminal", get(ws_terminal_handler))
        .fallback_service(ServeDir::new(public_dir))
        .layer(cors)
        .layer(axum::middleware::from_fn(security_headers_middleware))
        .with_state(state);

    let bind_host_str = std::env::var("BIND_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let bind_ip: std::net::IpAddr = bind_host_str
        .parse()
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
    let addr = SocketAddr::new(bind_ip, port);
    println!("=======================================================");
    println!("NexConsole - High Performance Rust Web Terminal");
    println!("Server Listening on: http://{}:{}", bind_ip, port);
    println!("Target SSH Server:   {}:{}", ssh_host, ssh_port);
    println!("Passkey Support:     WebAuthn / FIDO2 (Touch ID, Face ID)");
    println!("=======================================================");

    if let Some((ref u, ref pass)) = first_run_creds {
        println!("\n================================================================================");
        println!("       NEXCONSOLE LOGIN CREDENTIALS");
        println!("================================================================================");
        println!("  Url:       http://localhost:{}  (or http://<SERVER_IP>:{})", port, port);
        println!("  Username:  {}", u);
        println!("  Password:  {}", pass);
        println!("================================================================================");
        println!("Notice: Credentials encrypted and saved to SQLite + .env. Please save this!");
        println!("================================================================================\n");
    }

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
