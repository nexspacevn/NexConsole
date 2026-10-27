// State
let authToken = null;
let currentFontSize = 14;
let statsInterval = null;
let hasRegisteredPasskey = false;

// Multi-Tab Terminal State
const tabs = new Map(); // tabId -> { id, title, target, terminal, fitAddon, viewportEl, socket, isConnected }
let activeTabId = null;
let tabCounter = 0;
let savedServers = [];

// Auth Helper Functions
function getAuthToken() {
  if (authToken && authToken !== 'null' && authToken !== 'undefined') {
    return authToken;
  }
  const saved = localStorage.getItem('console_token');
  if (saved && saved !== 'null' && saved !== 'undefined') {
    authToken = saved;
    return saved;
  }
  return null;
}

function getAuthHeaders(includeJson = true) {
  const headers = {};
  if (includeJson) {
    headers['Content-Type'] = 'application/json';
  }
  const token = getAuthToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

function handleAuthExpired(message) {
  document.documentElement.classList.remove('has-auth');
  localStorage.removeItem('console_token');
  authToken = null;
  alert(message || 'Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại.');
  showLoginView();
}

// DOM Elements - Layer 1
const viewLogin = document.getElementById('viewLogin');
const viewTerminal = document.getElementById('viewTerminal');
const formLayer1 = document.getElementById('formLayer1');
const l1Username = document.getElementById('l1Username');
const l1Password = document.getElementById('l1Password');
const loginError = document.getElementById('loginError');

// DOM Elements - Passkey
const passkeySection = document.getElementById('passkeySection');
const btnPasskeyLogin = document.getElementById('btnPasskeyLogin');
const btnRegisterPasskey = document.getElementById('btnRegisterPasskey');
const passkeyBanner = document.getElementById('passkeyBanner');
const btnBannerSavePasskey = document.getElementById('btnBannerSavePasskey');
const btnBannerDismiss = document.getElementById('btnBannerDismiss');

// DOM Elements - Sidebar & Quick SSH
const btnOpenAddServerModal = document.getElementById('btnOpenAddServerModal');
const savedServersList = document.getElementById('savedServersList');
const savedServersCount = document.getElementById('savedServersCount');
const toggleQuickConnectHeader = document.getElementById('toggleQuickConnectHeader');
const quickConnectChevron = document.getElementById('quickConnectChevron');
const quickConnectBody = document.getElementById('quickConnectBody');
const quickSshHost = document.getElementById('quickSshHost');
const quickSshPort = document.getElementById('quickSshPort');
const quickSshUser = document.getElementById('quickSshUser');
const quickSshPass = document.getElementById('quickSshPass');
const btnQuickConnect = document.getElementById('btnQuickConnect');
const txtQuickConnect = document.getElementById('txtQuickConnect');
const btnToggleSidebar = document.getElementById('btnToggleSidebar');
const consoleSidebar = document.getElementById('consoleSidebar');

// DOM Elements - Tabs & Viewports
const tabsContainer = document.getElementById('tabsContainer');
const btnNewTab = document.getElementById('btnNewTab');
const terminalContainer = document.getElementById('terminalContainer');

// DOM Elements - Modal Server
const modalServer = document.getElementById('modalServer');
const modalBackdrop = document.getElementById('modalBackdrop');
const modalServerTitle = document.getElementById('modalServerTitle');
const btnModalClose = document.getElementById('btnModalClose');
const btnModalCancel = document.getElementById('btnModalCancel');
const formServerModal = document.getElementById('formServerModal');
const serverModalId = document.getElementById('serverModalId');
const serverModalName = document.getElementById('serverModalName');
const serverModalHost = document.getElementById('serverModalHost');
const serverModalPort = document.getElementById('serverModalPort');
const serverModalUser = document.getElementById('serverModalUser');
const serverModalPass = document.getElementById('serverModalPass');
const modalServerAlert = document.getElementById('modalServerAlert');

// Initialize
// Initialize
document.addEventListener('DOMContentLoaded', async () => {
  setupLayer1Form();
  setupQuickSSHForm();
  setupServerFleetManager();
  setupTabsManager();
  setupShortcuts();
  setupControls();
  setupPasskeyHandlers();
  setupUserMenu();
  await checkAuthStatus();
});

// Biến lưu thông tin người dùng đăng nhập & token 2FA tạm thời
let currentLoggedUser = null;
let pending2FAToken = null;

function updateUserNavbar(user) {
  if (!user) return;
  currentLoggedUser = user;
  const userNavAvatar = document.getElementById('userNavAvatar');
  const dropdownAvatarLg = document.getElementById('dropdownAvatarLg');
  const dropdownFullName = document.getElementById('dropdownFullName');
  const dropdownUserName = document.getElementById('dropdownUserName');

  const displayName = user.displayName || user.username || 'admin';
  const initials = displayName.substring(0, 2).toUpperCase();

  if (userNavAvatar) userNavAvatar.textContent = initials;
  if (dropdownAvatarLg) dropdownAvatarLg.textContent = initials;
  if (dropdownFullName) dropdownFullName.textContent = displayName;
  if (dropdownUserName) dropdownUserName.textContent = `@${user.username || 'admin'}`;

  if (user.quickCommands) {
    renderShortcutsBar(user.quickCommands);
  }
}

function setupUserMenu() {
  const trigger = document.getElementById('userProfileTrigger');
  const popover = document.getElementById('userDropdownPopover');

  if (!trigger || !popover) return;

  trigger.addEventListener('click', (e) => {
    e.stopPropagation();
    const isShown = popover.style.display !== 'none';
    popover.style.display = isShown ? 'none' : 'block';
    trigger.classList.toggle('active', !isShown);
  });

  // Đóng popover khi click ra ngoài
  document.addEventListener('click', (e) => {
    if (!popover.contains(e.target) && !trigger.contains(e.target)) {
      popover.style.display = 'none';
      trigger.classList.remove('active');
    }
  });

  // Đóng khi bấm phím Escape
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      popover.style.display = 'none';
      trigger.classList.remove('active');
    }
  });
}

// 1. Kiểm tra trạng thái Lớp 1 khi tải trang (Tự động ghi nhớ sau khi đã login)
async function checkAuthStatus() {
  getAuthToken();
  try {
    const headers = getAuthHeaders(false);
    const res = await fetch('/api/auth/me', { headers });
    const data = await res.json();
    if (data.loggedIn) {
      if (data.user) updateUserNavbar(data.user);
      showTerminalView();
    } else {
      localStorage.removeItem('console_token');
      authToken = null;
      showLoginView();
    }
  } catch {
    showLoginView();
  }
}

async function showLoginView() {
  document.documentElement.classList.remove('has-auth');
  viewLogin.style.display = 'flex';
  viewTerminal.style.display = 'none';
  if (statsInterval) clearInterval(statsInterval);

  // Khôi phục form mật khẩu nếu trước đó đang ở bước 2FA
  const formLayer1 = document.getElementById('formLayer1');
  const form2FA = document.getElementById('form2FA');
  if (formLayer1) formLayer1.style.display = 'block';
  if (form2FA) form2FA.style.display = 'none';
  pending2FAToken = null;

  // Đóng toàn bộ các tab terminal socket khi đăng xuất
  tabs.forEach((tab) => {
    if (tab.socket) {
      try { tab.socket.close(); } catch {}
    }
  });
  await checkPasskeyStatus();
}

async function showTerminalView() {
  document.documentElement.classList.add('has-auth');
  viewLogin.style.display = 'none';
  viewTerminal.style.display = 'flex';

  if (window.innerWidth <= 768 && consoleSidebar) {
    consoleSidebar.classList.add('collapsed');
    const backdrop = document.getElementById('sidebarBackdrop');
    if (backdrop) backdrop.classList.remove('active');
  }

  // Nạp danh sách máy chủ đã lưu từ SQLite
  await fetchSavedServers();

  // Khởi tạo tab đầu tiên nếu chưa có tab nào
  if (tabs.size === 0) {
    createTab({ title: 'Terminal 1' });
  } else {
    const currentTab = getActiveTab();
    if (currentTab && currentTab.fitAddon) {
      setTimeout(() => currentTab.fitAddon.fit(), 60);
    }
  }

  // Nạp lại Host, Port và User đã lưu lần trước cho Quick Connect (mặc định: localhost, 22, root)
  if (quickSshHost) {
    const savedHost = localStorage.getItem('ssh_last_host');
    quickSshHost.value = (savedHost && savedHost !== '192.168.1.200') ? savedHost : 'localhost';
  }
  if (quickSshPort) {
    const savedPort = localStorage.getItem('ssh_last_port');
    quickSshPort.value = (savedPort && savedPort !== '2222') ? savedPort : '22';
  }
  if (quickSshUser) {
    quickSshUser.value = localStorage.getItem('ssh_last_user') || 'root';
  }

  // Gợi ý đăng ký Passkey nếu thiết bị chưa lưu
  checkPasskeyPrompt();
}

// 2. Xử lý Đăng nhập Lớp 1 bằng Mật khẩu & Xác thực 2 bước (Google Authenticator)
function setupLayer1Form() {
  const formLayer1 = document.getElementById('formLayer1');
  const form2FA = document.getElementById('form2FA');
  const l1TotpCode = document.getElementById('l1TotpCode');
  const btnVerify2FALogin = document.getElementById('btnVerify2FALogin');
  const btnBackToPassword = document.getElementById('btnBackToPassword');
  const totpLoginError = document.getElementById('totpLoginError');

  if (formLayer1) {
    formLayer1.addEventListener('submit', async (e) => {
      e.preventDefault();
      loginError.style.display = 'none';
      const btn = document.getElementById('btnLayer1Login');
      btn.disabled = true;
      btn.querySelector('span').textContent = 'Đang xác thực...';

      try {
        const res = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: l1Username.value.trim(),
            password: l1Password.value
          })
        });
        const data = await res.json();

        // Nếu tài khoản yêu cầu bước 2 (Google Authenticator 2FA)
        if (data.require2fa && data.tempToken) {
          pending2FAToken = data.tempToken;
          formLayer1.style.display = 'none';
          if (form2FA) {
            form2FA.style.display = 'block';
            if (totpLoginError) totpLoginError.style.display = 'none';
            if (l1TotpCode) {
              l1TotpCode.value = '';
              setTimeout(() => l1TotpCode.focus(), 150);
            }
          }
          return;
        }

        if (data.success) {
          authToken = data.token;
          localStorage.setItem('console_token', data.token);
          if (data.user) updateUserNavbar(data.user);
          showTerminalView();
        } else {
          loginError.textContent = data.message || 'Xác thực Lớp 1 thất bại!';
          loginError.style.display = 'block';
        }
      } catch (err) {
        loginError.textContent = `Lỗi mạng: ${err.message}`;
        loginError.style.display = 'block';
      } finally {
        btn.disabled = false;
        btn.querySelector('span').textContent = 'Xác thực & Mở Cổng';
      }
    });
  }

  // Xử lý xác thực OTP 2FA
  if (form2FA) {
    form2FA.addEventListener('submit', async (e) => {
      e.preventDefault();
      await handleVerify2FALogin();
    });
  }

  // Tự động submit khi nhập đủ 6 chữ số
  if (l1TotpCode) {
    l1TotpCode.addEventListener('input', () => {
      const code = l1TotpCode.value.trim();
      if (code.length === 6) {
        handleVerify2FALogin();
      }
    });
  }

  if (btnBackToPassword) {
    btnBackToPassword.addEventListener('click', () => {
      pending2FAToken = null;
      if (form2FA) form2FA.style.display = 'none';
      if (formLayer1) {
        formLayer1.style.display = 'block';
        if (l1Password) l1Password.focus();
      }
    });
  }
}

async function handleVerify2FALogin() {
  const l1TotpCode = document.getElementById('l1TotpCode');
  const btnVerify2FALogin = document.getElementById('btnVerify2FALogin');
  const totpLoginError = document.getElementById('totpLoginError');

  if (!pending2FAToken || !l1TotpCode) return;

  const code = l1TotpCode.value.trim().replace(/\s+/g, '');
  if (code.length !== 6) {
    if (totpLoginError) {
      totpLoginError.textContent = 'Vui lòng nhập đủ 6 chữ số OTP!';
      totpLoginError.style.display = 'block';
    }
    return;
  }

  if (totpLoginError) totpLoginError.style.display = 'none';
  if (btnVerify2FALogin) {
    btnVerify2FALogin.disabled = true;
    btnVerify2FALogin.querySelector('span').textContent = 'Đang kiểm tra OTP...';
  }

  try {
    const res = await fetch('/api/auth/2fa/login-verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tempToken: pending2FAToken, code })
    });
    const data = await res.json();

    if (data.success) {
      authToken = data.token;
      localStorage.setItem('console_token', data.token);
      pending2FAToken = null;
      if (data.user) updateUserNavbar(data.user);
      showTerminalView();
    } else {
      if (totpLoginError) {
        totpLoginError.textContent = data.message || 'Mã xác thực 2 bước không chính xác!';
        totpLoginError.style.display = 'block';
      }
      l1TotpCode.select();
    }
  } catch (err) {
    if (totpLoginError) {
      totpLoginError.textContent = `Lỗi kết nối: ${err.message}`;
      totpLoginError.style.display = 'block';
    }
  } finally {
    if (btnVerify2FALogin) {
      btnVerify2FALogin.disabled = false;
      btnVerify2FALogin.querySelector('span').textContent = 'Xác thực mã OTP';
    }
  }
}

// ========================================================
// 3. PASSKEY (TOUCH ID / FACE ID / FIDO2) HANDLERS
// ========================================================
function setupPasskeyHandlers() {
  // Nút đăng nhập nhanh bằng Passkey ở trang login
  if (btnPasskeyLogin) {
    btnPasskeyLogin.addEventListener('click', handlePasskeyLogin);
  }

  // Nút thêm Passkey ở thanh điều khiển trên cùng
  if (btnRegisterPasskey) {
    btnRegisterPasskey.addEventListener('click', handlePasskeyRegistration);
  }

  // Nút lưu Passkey từ banner gợi ý
  if (btnBannerSavePasskey) {
    btnBannerSavePasskey.addEventListener('click', async () => {
      await handlePasskeyRegistration();
      passkeyBanner.style.display = 'none';
    });
  }

  if (btnBannerDismiss) {
    btnBannerDismiss.addEventListener('click', () => {
      passkeyBanner.style.display = 'none';
      sessionStorage.setItem('passkey_banner_dismissed', 'true');
    });
  }
}

// Kiểm tra xem server đã có Passkey nào chưa
async function checkPasskeyStatus() {
  if (!window.PublicKeyCredential) {
    if (passkeySection) passkeySection.style.display = 'none';
    return;
  }

  try {
    const res = await fetch('/api/auth/passkey/status');
    const data = await res.json();
    hasRegisteredPasskey = data.hasPasskey;

    if (passkeySection) {
      passkeySection.style.display = hasRegisteredPasskey ? 'block' : 'none';
    }
  } catch {
    if (passkeySection) passkeySection.style.display = 'none';
  }
}

// Gợi ý đăng ký Passkey sau khi đăng nhập
async function checkPasskeyPrompt() {
  if (!window.PublicKeyCredential || sessionStorage.getItem('passkey_banner_dismissed')) {
    return;
  }
  try {
    const res = await fetch('/api/auth/passkey/status');
    const data = await res.json();
    if (!data.hasPasskey && passkeyBanner) {
      passkeyBanner.style.display = 'flex';
    }
  } catch {}
}

// A. Đăng nhập nhanh bằng Passkey (Lớp 1)
async function handlePasskeyLogin() {
  loginError.style.display = 'none';
  const mainTextEl = btnPasskeyLogin.querySelector('.passkey-main-text');
  const originalText = mainTextEl ? mainTextEl.textContent : 'Đăng nhập nhanh';
  btnPasskeyLogin.disabled = true;
  if (mainTextEl) mainTextEl.textContent = 'Đang xác thực Touch ID / Passkey...';

  try {
    // 1. Nhận challenge từ server
    const challengeRes = await fetch('/api/auth/passkey/login-challenge');
    const challengeData = await challengeRes.json();
    if (!challengeRes.ok) {
      throw new Error(challengeData.message || 'Không thể tạo phiên đăng nhập Passkey');
    }

    // 2. Gọi API trình duyệt (Touch ID prompt)
    const options = parseRequestOptions(challengeData);
    const assertion = await navigator.credentials.get(options);
    if (!assertion) {
      throw new Error('Xác thực vân tay bị hủy');
    }

    // 3. Gửi chữ ký assertion về server kiểm tra
    const assertionJSON = credentialToJSON(assertion);
    const verifyRes = await fetch('/api/auth/passkey/login-verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(assertionJSON)
    });
    const verifyData = await verifyRes.json();

    if (verifyData.success) {
      authToken = verifyData.token;
      localStorage.setItem('console_token', verifyData.token);
      showTerminalView();
    } else {
      throw new Error(verifyData.message || 'Xác thực Passkey thất bại!');
    }
  } catch (err) {
    if (err.name !== 'NotAllowedError') {
      loginError.textContent = `Lỗi Passkey: ${err.message}`;
      loginError.style.display = 'block';
    }
  } finally {
    btnPasskeyLogin.disabled = false;
    if (mainTextEl) mainTextEl.textContent = originalText;
  }
}

// B. Đăng ký Passkey mới cho thiết bị
async function handlePasskeyRegistration() {
  try {
    // 1. Nhận challenge đăng ký từ server
    const headers = {};
    if (authToken) headers['Authorization'] = `Bearer ${authToken}`;

    const challengeRes = await fetch('/api/auth/passkey/register-challenge', {
      headers
    });
    const challengeData = await challengeRes.json();
    if (!challengeRes.ok) {
      throw new Error(challengeData.message || 'Không thể tạo challenge đăng ký');
    }

    // 2. Kích hoạt Touch ID tạo Passkey
    const options = parseCreationOptions(challengeData);
    const credential = await navigator.credentials.create(options);
    if (!credential) {
      throw new Error('Đăng ký bị hủy');
    }

    // 3. Gửi Public Key Credential lên server lưu trữ
    const credentialJSON = credentialToJSON(credential);
    const verifyHeaders = {
      'Content-Type': 'application/json',
      ...headers
    };
    const verifyRes = await fetch('/api/auth/passkey/register-verify', {
      method: 'POST',
      headers: verifyHeaders,
      body: JSON.stringify(credentialJSON)
    });
    const verifyData = await verifyRes.json();

    if (verifyData.success) {
      alert('Đã lưu Passkey thành công!\n\nLần sau khi mở WebConsole, bạn chỉ cần bấm "Đăng nhập nhanh bằng Passkey" và chạm vân tay Touch ID là vào thẳng.');
      hasRegisteredPasskey = true;
      if (passkeyBanner) passkeyBanner.style.display = 'none';
    } else {
      throw new Error(verifyData.message || 'Lưu Passkey thất bại!');
    }
  } catch (err) {
    if (err.name === 'InvalidStateError' || (err.message && err.message.includes('already registered'))) {
      alert('Thiết bị này đã được lưu Passkey từ trước rồi. Bạn có thể sử dụng Touch ID / Passkey để đăng nhập ngay!');
    } else if (err.name !== 'NotAllowedError') {
      alert(`Lỗi đăng ký Passkey: ${err.message}`);
    }
  }
}

// ========================================================
// 4. WEBAUTHN BINARY / BASE64URL HELPERS
// ========================================================
function base64urlToUint8Array(base64url) {
  const padding = '='.repeat((4 - (base64url.length % 4)) % 4);
  const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = window.atob(base64);
  const output = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; ++i) output[i] = raw.charCodeAt(i);
  return output;
}

function arrayBufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function parseCreationOptions(ccr) {
  const pkJSON = ccr.publicKey || ccr;
  if (window.PublicKeyCredential && PublicKeyCredential.parseCreationOptionsFromJSON) {
    try {
      const pkOptions = PublicKeyCredential.parseCreationOptionsFromJSON(pkJSON);
      return { publicKey: pkOptions };
    } catch (e) {
      console.warn('parseCreationOptionsFromJSON failed, falling back to manual decode:', e);
    }
  }
  const opts = { ...pkJSON };
  opts.challenge = base64urlToUint8Array(opts.challenge);
  opts.user = {
    ...opts.user,
    id: base64urlToUint8Array(opts.user.id)
  };
  if (opts.excludeCredentials) {
    opts.excludeCredentials = opts.excludeCredentials.map(c => ({
      ...c,
      id: base64urlToUint8Array(c.id)
    }));
  }
  return { publicKey: opts };
}

function parseRequestOptions(rcr) {
  const pkJSON = rcr.publicKey || rcr;
  if (window.PublicKeyCredential && PublicKeyCredential.parseRequestOptionsFromJSON) {
    try {
      const pkOptions = PublicKeyCredential.parseRequestOptionsFromJSON(pkJSON);
      return { publicKey: pkOptions };
    } catch (e) {
      console.warn('parseRequestOptionsFromJSON failed, falling back to manual decode:', e);
    }
  }
  const opts = { ...pkJSON };
  opts.challenge = base64urlToUint8Array(opts.challenge);
  if (opts.allowCredentials) {
    opts.allowCredentials = opts.allowCredentials.map(c => ({
      ...c,
      id: base64urlToUint8Array(c.id)
    }));
  }
  return { publicKey: opts };
}

function credentialToJSON(cred) {
  if (cred.toJSON) return cred.toJSON();
  const obj = {
    id: cred.id,
    rawId: arrayBufferToBase64url(cred.rawId),
    type: cred.type,
    response: {}
  };
  if (cred.response.clientDataJSON) {
    obj.response.clientDataJSON = arrayBufferToBase64url(cred.response.clientDataJSON);
  }
  if (cred.response.attestationObject) {
    obj.response.attestationObject = arrayBufferToBase64url(cred.response.attestationObject);
  }
  if (cred.response.authenticatorData) {
    obj.response.authenticatorData = arrayBufferToBase64url(cred.response.authenticatorData);
  }
  if (cred.response.signature) {
    obj.response.signature = arrayBufferToBase64url(cred.response.signature);
  }
  if (cred.response.userHandle) {
    obj.response.userHandle = arrayBufferToBase64url(cred.response.userHandle);
  }
  return obj;
}

// ========================================================
// 5. QUẢN LÝ ĐA TAB TERMINAL (MULTI-SESSION TABS)
// ========================================================
function getActiveTab() {
  return tabs.get(activeTabId);
}

function createTab({ title, serverId = null, host = null, port = null, username = null, password = null, autoConnect = false }) {
  tabCounter++;
  const tabId = `tab_${Date.now()}_${tabCounter}`;
  const defaultTitle = title || `Terminal ${tabCounter}`;

  // 1. Tạo Tab Item trên thanh Tab Bar
  const tabEl = document.createElement('div');
  tabEl.className = 'terminal-tab';
  tabEl.id = `tab_item_${tabId}`;
  tabEl.setAttribute('data-tab-id', tabId);
  tabEl.innerHTML = `
    <div class="tab-indicator" id="ind_${tabId}"></div>
    <span class="tab-title" id="title_${tabId}" title="${escapeHtml(defaultTitle)}">${escapeHtml(defaultTitle)}</span>
    <button class="tab-close-btn" title="Đóng tab này">×</button>
  `;

  tabEl.addEventListener('click', (e) => {
    if (e.target.closest('.tab-close-btn')) {
      e.stopPropagation();
      closeTab(tabId);
      return;
    }
    switchTab(tabId);
  });

  tabsContainer.appendChild(tabEl);

  // 2. Tạo Viewport Container cho Terminal của Tab
  const viewportEl = document.createElement('div');
  viewportEl.className = 'term-viewport';
  viewportEl.id = `viewport_${tabId}`;
  terminalContainer.appendChild(viewportEl);

  // 3. Khởi tạo xterm.js riêng cho tab
  const term = new Terminal({
    cursorBlink: true,
    fontFamily: '"Roboto Mono", monospace',
    fontSize: currentFontSize,
    lineHeight: 1.25,
    theme: {
      background: '#080b11',
      foreground: '#e2e8f0',
      cursor: '#06b6d4',
      cursorAccent: '#080b11',
      selectionBackground: 'rgba(99, 102, 241, 0.35)',
      black: '#1e293b',
      red: '#ef4444',
      green: '#10b981',
      yellow: '#f59e0b',
      blue: '#6366f1',
      magenta: '#d946ef',
      cyan: '#06b6d4',
      white: '#f8fafc',
      brightBlack: '#475569',
      brightRed: '#f87171',
      brightGreen: '#34d399',
      brightYellow: '#fbbf24',
      brightBlue: '#818cf8',
      brightMagenta: '#e879f9',
      brightCyan: '#22d3ee',
      brightWhite: '#ffffff'
    }
  });

  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.loadAddon(new WebLinksAddon.WebLinksAddon());
  term.open(viewportEl);

  // Data event từ phím gõ gửi sang socket riêng của tab
  term.onData((data) => {
    const tabObj = tabs.get(tabId);
    if (tabObj && tabObj.socket && tabObj.socket.readyState === WebSocket.OPEN) {
      tabObj.socket.send(JSON.stringify({ type: 'data', data }));
    }
  });

  const tabObj = {
    id: tabId,
    title: defaultTitle,
    target: { serverId, host, port, username },
    terminal: term,
    fitAddon: fit,
    viewportEl,
    tabEl,
    socket: null,
    status: 'disconnected'
  };

  tabs.set(tabId, tabObj);
  switchTab(tabId);

  if (autoConnect) {
    connectTabSSH(tabId, { serverId, host, port, username, password });
  }

  return tabId;
}

function switchTab(tabId) {
  if (!tabs.has(tabId)) return;
  activeTabId = tabId;

  // Cập nhật tab active
  document.querySelectorAll('.terminal-tab').forEach((el) => {
    el.classList.toggle('active', el.getAttribute('data-tab-id') === tabId);
  });

  // Cập nhật viewport active
  document.querySelectorAll('.term-viewport').forEach((el) => {
    el.classList.toggle('active', el.id === `viewport_${tabId}`);
  });

  const curTab = tabs.get(tabId);
  if (curTab) {
    setTimeout(() => {
      if (curTab.fitAddon) {
        curTab.fitAddon.fit();
        if (curTab.socket && curTab.socket.readyState === WebSocket.OPEN) {
          curTab.socket.send(JSON.stringify({
            type: 'resize',
            cols: curTab.terminal.cols,
            rows: curTab.terminal.rows
          }));
        }
      }
      curTab.terminal.focus();
    }, 40);

    updateQuickConnectButtonState(curTab.status);
    updateActiveServerState();
  }
}

function closeTab(tabId) {
  const tabObj = tabs.get(tabId);
  if (tabObj.pingInterval) {
    clearInterval(tabObj.pingInterval);
    tabObj.pingInterval = null;
  }

  if (tabObj.socket) {
    try {
      tabObj.socket.send(JSON.stringify({ type: 'ssh_disconnect' }));
      tabObj.socket.close();
    } catch {}
  }

  tabObj.terminal.dispose();
  tabObj.tabEl.remove();
  tabObj.viewportEl.remove();
  tabs.delete(tabId);

  if (activeTabId === tabId) {
    const remainingIds = Array.from(tabs.keys());
    if (remainingIds.length > 0) {
      switchTab(remainingIds[remainingIds.length - 1]);
    } else {
      createTab({ title: 'Terminal 1' });
    }
  }

  updateActiveServerState();
}

function setTabStatus(tabId, status, infoText) {
  const tabObj = tabs.get(tabId);
  if (!tabObj) return;
  tabObj.status = status;

  const ind = document.getElementById(`ind_${tabId}`);
  if (ind) {
    ind.className = 'tab-indicator ' + status;
  }

  updateActiveServerState();

  if (infoText) {
    const titleEl = document.getElementById(`title_${tabId}`);
    if (titleEl) {
      titleEl.textContent = infoText;
      titleEl.title = infoText;
    }
  }

  if (activeTabId === tabId) {
    updateQuickConnectButtonState(status);
  }
}

function updateQuickConnectButtonState(status) {
  if (!btnQuickConnect) return;
  btnQuickConnect.classList.remove('connected', 'connecting');

  if (status === 'connected') {
    btnQuickConnect.classList.add('connected');
    if (txtQuickConnect) txtQuickConnect.textContent = window.i18n ? window.i18n.t('btn_disconnect') : 'Disconnect';
  } else if (status === 'connecting') {
    btnQuickConnect.classList.add('connecting');
    if (txtQuickConnect) txtQuickConnect.textContent = window.i18n ? window.i18n.t('tab_connecting') : 'Connecting...';
  } else {
    if (txtQuickConnect) txtQuickConnect.textContent = window.i18n ? window.i18n.t('btn_connect') : 'Connect';
  }
}

function connectTabSSH(tabId, { serverId = null, host = null, port = null, username = null, password = null }) {
  const tabObj = tabs.get(tabId);
  if (!tabObj) return;

  if (tabObj.socket) {
    try { tabObj.socket.close(); } catch {}
  }

  setTabStatus(tabId, 'connecting');
  const handshakeMsg = window.i18n ? window.i18n.t('ssh_handshake') : '[SSH] Establishing secure connection...';
  tabObj.terminal.writeln(`\x1b[36m${handshakeMsg}\x1b[0m`);

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const token = getAuthToken() || '';
  const wsUrl = `${protocol}//${window.location.host}/ws/terminal?token=${encodeURIComponent(token)}`;
  const ws = new WebSocket(wsUrl);
  tabObj.socket = ws;

  ws.onopen = () => {
    tabObj.fitAddon.fit();

    if (tabObj.pingInterval) {
      clearInterval(tabObj.pingInterval);
    }
    tabObj.pingInterval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        try {
          ws.send(JSON.stringify({ type: 'ping' }));
        } catch {}
      }
    }, 20000);

    const payload = {
      type: 'ssh_connect',
      cols: tabObj.terminal.cols,
      rows: tabObj.terminal.rows
    };

    if (serverId) {
      payload.server_id = serverId;
    } else {
      payload.host = host;
      payload.port = parseInt(port, 10) || 22;
      payload.username = username || 'root';
      payload.password = password || '';
    }

    ws.send(JSON.stringify(payload));
  };

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      if (msg.type === 'pong' || msg.type === 'ping') {
        return;
      }
      if (msg.type === 'data') {
        tabObj.terminal.write(msg.data);
      } else if (msg.type === 'status') {
        setTabStatus(tabId, 'connected', tabObj.title);
        tabObj.terminal.focus();
        let displayMsg = msg.message;
        const prefix = window.i18n ? window.i18n.t('ssh_connected_prefix') : '[SSH] Successfully connected to';
        if (displayMsg.includes('Đã kết nối SSH thành công tới ')) {
          displayMsg = `${prefix} ${displayMsg.replace('Đã kết nối SSH thành công tới ', '')}`;
        }
        tabObj.terminal.writeln(`\x1b[32m${displayMsg}\x1b[0m`);
      } else if (msg.type === 'ssh_error') {
        setTabStatus(tabId, 'disconnected');
        tabObj.terminal.writeln(`\x1b[31m[SSH ERROR] ${msg.message}\x1b[0m`);
      }
    } catch {
      tabObj.terminal.write(event.data);
    }
  };

  ws.onclose = () => {
    if (tabObj.pingInterval) {
      clearInterval(tabObj.pingInterval);
      tabObj.pingInterval = null;
    }
    setTabStatus(tabId, 'disconnected');
    const wsClosedMsg = window.i18n ? window.i18n.t('ws_session_ended') : '[WebSocket] Work session has ended.';
    tabObj.terminal.writeln(`\r\n\x1b[33m${wsClosedMsg}\x1b[0m`);
  };

  ws.onerror = () => {
    if (tabObj.pingInterval) {
      clearInterval(tabObj.pingInterval);
      tabObj.pingInterval = null;
    }
    setTabStatus(tabId, 'disconnected');
    const wsErrMsg = window.i18n ? window.i18n.t('ws_error') : '[WebSocket] Connection error!';
    tabObj.terminal.writeln(`\r\n\x1b[31m${wsErrMsg}\x1b[0m\r\n`);
  };
}

function disconnectTabSSH(tabId) {
  const tabObj = tabs.get(tabId);
  if (!tabObj) return;

  if (tabObj.pingInterval) {
    clearInterval(tabObj.pingInterval);
    tabObj.pingInterval = null;
  }

  if (tabObj.socket && tabObj.socket.readyState === WebSocket.OPEN) {
    try {
      tabObj.socket.send(JSON.stringify({ type: 'ssh_disconnect' }));
      tabObj.socket.close();
    } catch {}
  }
  setTabStatus(tabId, 'disconnected');
}

function setupTabsManager() {
  if (btnNewTab) {
    btnNewTab.addEventListener('click', () => {
      createTab({ title: `Terminal ${tabCounter + 1}` });
    });
  }

  window.addEventListener('resize', () => {
    const curTab = getActiveTab();
    if (curTab && curTab.fitAddon && viewTerminal.style.display !== 'none') {
      curTab.fitAddon.fit();
      if (curTab.socket && curTab.socket.readyState === WebSocket.OPEN) {
        curTab.socket.send(JSON.stringify({
          type: 'resize',
          cols: curTab.terminal.cols,
          rows: curTab.terminal.rows
        }));
      }
    }
  });
}

// ========================================================
// 6. QUẢN LÝ DANH BẠ MÁY CHỦ (SQLITE + AES-256)
// ========================================================
function setupServerFleetManager() {
  if (btnOpenAddServerModal) {
    btnOpenAddServerModal.addEventListener('click', () => openServerModal());
  }

  if (btnModalClose) {
    btnModalClose.addEventListener('click', closeServerModal);
  }

  if (btnModalCancel) {
    btnModalCancel.addEventListener('click', closeServerModal);
  }

  if (modalBackdrop) {
    modalBackdrop.addEventListener('click', closeServerModal);
  }

  if (formServerModal) {
    formServerModal.addEventListener('submit', handleSaveServer);
  }

  // Delete modal bindings
  const btnDeleteModalCancel = document.getElementById('btnDeleteModalCancel');
  const btnDeleteModalClose = document.getElementById('btnDeleteModalClose');
  const deleteModalBackdrop = document.getElementById('deleteModalBackdrop');
  const btnDeleteModalConfirm = document.getElementById('btnDeleteModalConfirm');

  if (btnDeleteModalCancel) btnDeleteModalCancel.addEventListener('click', closeDeleteModal);
  if (btnDeleteModalClose) btnDeleteModalClose.addEventListener('click', closeDeleteModal);
  if (deleteModalBackdrop) deleteModalBackdrop.addEventListener('click', closeDeleteModal);
  if (btnDeleteModalConfirm) btnDeleteModalConfirm.addEventListener('click', executeDeleteServer);

  // Nhấn ESC để đóng modal
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      const modalDelete = document.getElementById('modalConfirmDelete');
      if (modalDelete && modalDelete.style.display !== 'none') {
        closeDeleteModal();
        return;
      }
      if (modalServer && modalServer.style.display !== 'none') {
        closeServerModal();
        return;
      }
    }
  });

  // Toggle Accordion kết nối nhanh
  if (toggleQuickConnectHeader && quickConnectBody) {
    toggleQuickConnectHeader.addEventListener('click', () => {
      const isCollapsed = quickConnectBody.classList.toggle('collapsed');
      if (quickConnectChevron) {
        quickConnectChevron.classList.toggle('collapsed', isCollapsed);
      }
    });
  }
}

async function fetchSavedServers() {
  try {
    const res = await fetch('/api/servers', {
      headers: getAuthHeaders(true)
    });
    if (res.status === 401) {
      handleAuthExpired('Phiên làm việc đã hết hạn. Vui lòng đăng nhập lại.');
      return;
    }
    const data = await res.json();
    if (data.success && Array.isArray(data.servers)) {
      savedServers = data.servers;
      renderSavedServersList();
    }
  } catch (err) {
    console.error('Lỗi tải danh sách máy chủ:', err);
  }
}

function renderSavedServersList() {
  if (!savedServersList) return;
  if (savedServersCount) savedServersCount.textContent = savedServers.length;

  if (savedServers.length === 0) {
    const emptyMsg = window.i18n ? window.i18n.t('sidebar_empty_servers') : 'No servers added yet. Click "+" to connect.';
    savedServersList.innerHTML = `
      <div class="empty-servers-msg">${emptyMsg}</div>
    `;
    return;
  }

  const connectTitle = window.i18n ? window.i18n.t('btn_connect') : 'Connect';
  const editTitle = window.i18n ? window.i18n.t('btn_edit') : 'Edit';
  const deleteTitle = window.i18n ? window.i18n.t('btn_delete') : 'Delete';

  savedServersList.innerHTML = savedServers.map((srv) => {
    return `
      <div class="server-card" data-server-id="${escapeHtml(srv.id)}">
        <div class="server-card-main" data-action="connect" data-server-id="${escapeHtml(srv.id)}">
          <div class="server-card-name" title="${escapeHtml(srv.name)}">
            <span class="server-live-dot"></span>
            <span class="server-name-txt">${escapeHtml(srv.name)}</span>
          </div>
          <div class="server-card-info">${escapeHtml(srv.username)}@${escapeHtml(srv.host)}:${srv.port}</div>
        </div>
        <div class="server-card-actions">
          <button class="btn-server-action action-connect" title="${connectTitle}" data-action="connect" data-server-id="${escapeHtml(srv.id)}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="5 3 19 12 5 21 5 3"/></svg>
          </button>
          <button class="btn-server-action" title="${editTitle}" data-action="edit" data-server-id="${escapeHtml(srv.id)}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
          </button>
          <button class="btn-server-action action-delete" title="${deleteTitle}" data-action="delete" data-server-id="${escapeHtml(srv.id)}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
          </button>
        </div>
      </div>
    `;
  }).join('');

  if (!savedServersList.dataset.listenerBound) {
    savedServersList.addEventListener('click', (e) => {
      const actionEl = e.target.closest('[data-action]');
      if (!actionEl) return;
      const action = actionEl.getAttribute('data-action');
      const sId = actionEl.getAttribute('data-server-id');
      if (!sId) return;
      if (action === 'connect') {
        connectToServer(sId);
      } else if (action === 'edit') {
        editServer(sId);
      } else if (action === 'delete') {
        const srv = savedServers.find(s => s.id === sId);
        promptDeleteServer(sId, srv ? srv.name : '');
      }
    });
    savedServersList.dataset.listenerBound = 'true';
  }

  updateActiveServerState();
}

function updateActiveServerState() {
  const curTab = getActiveTab();
  let activeServerId = (curTab && curTab.target) ? curTab.target.serverId : null;

  // Nếu tab chưa gán serverId nhưng target trùng IP + Port + User của máy chủ đã lưu
  if (!activeServerId && curTab && curTab.target && curTab.target.host) {
    const matched = savedServers.find(s => 
      s.host.toLowerCase() === curTab.target.host.toLowerCase() &&
      s.port == curTab.target.port &&
      s.username.toLowerCase() === (curTab.target.username || 'root').toLowerCase()
    );
    if (matched) {
      activeServerId = matched.id;
      curTab.target.serverId = matched.id;
    }
  }

  // Tập hợp các server đang có tab kết nối ngầm
  const connectedServerIds = new Set();
  tabs.forEach((tab) => {
    if (tab.target) {
      let sId = tab.target.serverId;
      if (!sId && tab.target.host) {
        const m = savedServers.find(s => 
          s.host.toLowerCase() === tab.target.host.toLowerCase() &&
          s.port == tab.target.port &&
          s.username.toLowerCase() === (tab.target.username || 'root').toLowerCase()
        );
        if (m) { sId = m.id; tab.target.serverId = m.id; }
      }
      if (sId && (tab.status === 'connected' || tab.status === 'connecting')) {
        connectedServerIds.add(sId);
      }
    }
  });

  document.querySelectorAll('.server-card').forEach((card) => {
    const sId = card.getAttribute('data-server-id');
    card.classList.remove('is-active-tab', 'is-connected-bg');

    if (sId === activeServerId) {
      card.classList.add('is-active-tab');
    } else if (connectedServerIds.has(sId)) {
      card.classList.add('is-connected-bg');
    }
  });
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/[&<>'"]/g, 
    tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
  );
}

window.connectToServer = function(serverId) {
  const srv = savedServers.find(s => s.id === serverId);
  if (!srv) return;

  // 1. Kiểm tra xem đã có tab nào mở máy chủ này chưa
  for (const [tId, tObj] of tabs.entries()) {
    if (tObj.target && tObj.target.serverId === serverId) {
      switchTab(tId);
      // Nếu tab này đang ngắt kết nối (vừa disconnect), kết nối lại ngay!
      if (tObj.status === 'disconnected') {
        connectTabSSH(tId, { serverId: srv.id });
      }
      return;
    }
  }

  // 2. Nếu tab hiện tại đang ngắt kết nối, tái sử dụng luôn tab hiện tại
  const curTab = getActiveTab();
  if (curTab && curTab.status === 'disconnected') {
    curTab.title = srv.name;
    curTab.target = { serverId: srv.id, host: srv.host, port: srv.port, username: srv.username };
    const titleEl = document.getElementById(`title_${curTab.id}`);
    if (titleEl) titleEl.textContent = srv.name;
    connectTabSSH(curTab.id, { serverId: srv.id });
    return;
  }

  // 3. Mở tab mới
  createTab({
    title: srv.name,
    serverId: srv.id,
    host: srv.host,
    port: srv.port,
    username: srv.username,
    autoConnect: true
  });
};

window.editServer = function(serverId) {
  const srv = savedServers.find(s => s.id === serverId);
  if (srv) {
    openServerModal(srv);
  }
};

// ========================================================
// QUẢN LÝ MODAL XÁC NHẬN XÓA MÁY CHỦ (CYBER POPUP)
// ========================================================
let pendingDeleteServerId = null;

function promptDeleteServer(serverId, serverName) {
  const srv = savedServers.find(s => s.id === serverId);
  pendingDeleteServerId = serverId;

  const modal = document.getElementById('modalConfirmDelete');
  const targetName = document.getElementById('deleteServerTargetName');
  const targetDetail = document.getElementById('deleteServerTargetDetail');
  const alertEl = document.getElementById('deleteModalAlert');
  const btnConfirm = document.getElementById('btnDeleteModalConfirm');
  const btnCancel = document.getElementById('btnDeleteModalCancel');
  const txtConfirm = document.getElementById('btnDeleteModalConfirmText');

  const displayName = (srv && srv.name) ? srv.name : (serverName || 'Máy chủ này');
  if (targetName) targetName.textContent = displayName;

  if (targetDetail) {
    if (srv) {
      targetDetail.textContent = `${srv.username || 'root'}@${srv.host}:${srv.port || 22}`;
      targetDetail.style.display = 'block';
    } else {
      targetDetail.style.display = 'none';
    }
  }

  if (alertEl) {
    alertEl.textContent = '';
    alertEl.style.display = 'none';
  }

  if (btnConfirm) btnConfirm.disabled = false;
  if (txtConfirm) txtConfirm.textContent = 'Xóa máy chủ';

  if (modal) {
    modal.style.display = 'flex';
    // Đặt focus vào nút Hủy bỏ để bảo vệ an toàn nếu bấm phím Space/Enter
    setTimeout(() => {
      if (btnCancel) btnCancel.focus();
    }, 50);
  }
}

function closeDeleteModal() {
  const modal = document.getElementById('modalConfirmDelete');
  if (modal) modal.style.display = 'none';
  pendingDeleteServerId = null;
}

async function executeDeleteServer() {
  if (!pendingDeleteServerId) return;

  const srv = savedServers.find(s => s.id === pendingDeleteServerId);
  const serverName = srv ? srv.name : 'Máy chủ';

  const btnConfirm = document.getElementById('btnDeleteModalConfirm');
  const txtConfirm = document.getElementById('btnDeleteModalConfirmText');
  const alertEl = document.getElementById('deleteModalAlert');

  if (btnConfirm) btnConfirm.disabled = true;
  if (txtConfirm) txtConfirm.textContent = 'Đang xóa...';
  if (alertEl) alertEl.style.display = 'none';

  try {
    const res = await fetch(`/api/servers/${pendingDeleteServerId}`, {
      method: 'DELETE',
      headers: getAuthHeaders(true)
    });

    if (res.status === 401) {
      handleAuthExpired('Phiên làm việc đã hết hạn. Vui lòng đăng nhập lại.');
      closeDeleteModal();
      return;
    }

    const data = await res.json();
    if (data.success) {
      closeDeleteModal();
      await fetchSavedServers();
      showToast(`Đã xóa "${serverName}" khỏi danh sách máy chủ`, 'success');
    } else {
      if (alertEl) {
        alertEl.textContent = `Lỗi: ${data.message || data.error || 'Không thể xóa máy chủ'}`;
        alertEl.style.display = 'block';
      }
      if (btnConfirm) btnConfirm.disabled = false;
      if (txtConfirm) txtConfirm.textContent = 'Xóa Máy Chủ';
    }
  } catch (err) {
    if (alertEl) {
      alertEl.textContent = `Lỗi kết nối: ${err.message}`;
      alertEl.style.display = 'block';
    }
    if (btnConfirm) btnConfirm.disabled = false;
    if (txtConfirm) txtConfirm.textContent = 'Xóa Máy Chủ';
  }
}

function showToast(message, type = 'info') {
  let container = document.getElementById('toastContainer');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toastContainer';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = `cyber-toast toast-${type}`;
  
  const iconSvg = type === 'success' 
    ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>'
    : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';

  toast.innerHTML = `
    <div class="toast-icon">${iconSvg}</div>
    <div class="toast-message">${escapeHtml(message)}</div>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add('toast-show');
  }, 10);

  setTimeout(() => {
    toast.classList.remove('toast-show');
    toast.classList.add('toast-hide');
    setTimeout(() => {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, 300);
  }, 3200);
}

window.promptDeleteServer = promptDeleteServer;
window.closeDeleteModal = closeDeleteModal;
window.executeDeleteServer = executeDeleteServer;
window.deleteServer = promptDeleteServer;
window.showToast = showToast;

function openServerModal(server = null) {
  if (!modalServer) return;
  modalServerAlert.style.display = 'none';

  if (server) {
    modalServerTitle.textContent = window.i18n ? window.i18n.t('modal_server_edit_title') : 'Edit Server';
    serverModalId.value = server.id;
    serverModalName.value = server.name;
    serverModalHost.value = server.host;
    serverModalPort.value = server.port;
    serverModalUser.value = server.username;
    serverModalPass.value = '';
    const passSavedHolder = window.i18n && window.i18n.getLanguage() === 'vi' 
      ? '(Đã lưu mật khẩu - để trống nếu không đổi)' 
      : '(Password saved - leave blank to keep)';
    const enterPassHolder = window.i18n ? window.i18n.t('placeholder_server_pass') : 'Enter server password...';
    serverModalPass.placeholder = server.hasPassword ? passSavedHolder : enterPassHolder;
  } else {
    modalServerTitle.textContent = window.i18n ? window.i18n.t('modal_server_add_title') : 'Add New Server';
    serverModalId.value = '';
    serverModalName.value = '';
    serverModalHost.value = '';
    serverModalPort.value = '22';
    serverModalUser.value = 'root';
    serverModalPass.value = '';
    serverModalPass.placeholder = window.i18n ? window.i18n.t('placeholder_server_pass') : 'Enter server password...';
  }

  modalServer.style.display = 'flex';
  setTimeout(() => serverModalName.focus(), 50);
}

function closeServerModal() {
  if (modalServer) modalServer.style.display = 'none';
}

async function handleSaveServer(e) {
  e.preventDefault();
  modalServerAlert.style.display = 'none';

  const id = serverModalId.value.trim();
  const name = serverModalName.value.trim();
  const host = serverModalHost.value.trim();
  const port = parseInt(serverModalPort.value, 10) || 22;
  const username = serverModalUser.value.trim() || 'root';
  const password = serverModalPass.value;

  if (!name || !host) {
    modalServerAlert.textContent = 'Vui lòng nhập Tên gợi nhớ và Địa chỉ IP / Host';
    modalServerAlert.style.display = 'block';
    return;
  }

  const btnSave = document.getElementById('btnModalSave');
  btnSave.disabled = true;

  try {
    const isEdit = !!id;
    const url = isEdit ? `/api/servers/${id}` : '/api/servers';
    const method = isEdit ? 'PUT' : 'POST';

    const payload = { name, host, port, username };
    if (password) {
      payload.password = password;
    }

    let res = await fetch(url, {
      method,
      headers: getAuthHeaders(true),
      body: JSON.stringify(payload)
    });

    if (res.status === 401) {
      handleAuthExpired('Phiên làm việc đã hết hạn. Vui lòng đăng nhập lại.');
      return;
    }

    let data = await res.json();

    // Xử lý khi phát hiện trùng lặp (HTTP 409 Conflict)
    if (res.status === 409 && data.duplicate) {
      if (data.duplicateField === 'target') {
        const confirmOverwrite = confirm(
          `${data.message}\n\nBạn có muốn cập nhật lại thông tin (tên/mật khẩu) cho máy chủ này không?`
        );
        if (confirmOverwrite) {
          const retryRes = await fetch(url, {
            method,
            headers: getAuthHeaders(true),
            body: JSON.stringify({ ...payload, overwrite: true })
          });
          const retryData = await retryRes.json();
          if (retryData.success) {
            closeServerModal();
            await fetchSavedServers();
            return;
          } else {
            modalServerAlert.textContent = retryData.message || 'Cập nhật thất bại';
            modalServerAlert.style.display = 'block';
            return;
          }
        } else {
          modalServerAlert.textContent = data.message;
          modalServerAlert.style.display = 'block';
          return;
        }
      } else {
        modalServerAlert.textContent = data.message;
        modalServerAlert.style.display = 'block';
        serverModalName.focus();
        return;
      }
    }

    if (data.success) {
      closeServerModal();
      await fetchSavedServers();
    } else {
      modalServerAlert.textContent = data.message || data.error || 'Lưu thất bại';
      modalServerAlert.style.display = 'block';
    }
  } catch (err) {
    modalServerAlert.textContent = `Lỗi mạng: ${err.message}`;
    modalServerAlert.style.display = 'block';
  } finally {
    btnSave.disabled = false;
  }
}

// ========================================================
// 7. XỬ LÝ KẾT NỐI NHANH (QUICK CONNECT) & LƯU MÁY CHỦ SIDEBAR
// ========================================================
function setupQuickSSHForm() {
  const quickSshName = document.getElementById('quickSshName');
  const btnQuickSave = document.getElementById('btnQuickSave');
  const enterInputs = [quickSshName, quickSshHost, quickSshPort, quickSshUser, quickSshPass];
  
  enterInputs.forEach((input) => {
    if (input) {
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          triggerQuickConnect();
        }
      });
    }
  });

  if (btnQuickSave) {
    btnQuickSave.addEventListener('click', handleQuickSaveServer);
  }

  if (btnQuickConnect) {
    btnQuickConnect.addEventListener('click', triggerQuickConnect);
  }
}

async function handleQuickSaveServer() {
  const host = (quickSshHost ? quickSshHost.value : '').trim();
  const port = parseInt((quickSshPort ? quickSshPort.value : '').trim(), 10) || 22;
  const username = (quickSshUser ? quickSshUser.value : '').trim() || 'root';
  const password = quickSshPass ? quickSshPass.value : '';
  const quickSshName = document.getElementById('quickSshName');
  const name = (quickSshName ? quickSshName.value.trim() : '') || host;

  if (!host) {
    alert('Vui lòng nhập IP / Host máy chủ trước khi lưu!');
    if (quickSshHost) quickSshHost.focus();
    return;
  }

  const btnQuickSave = document.getElementById('btnQuickSave');
  const txtQuickSave = document.getElementById('txtQuickSave');
  const originalText = txtQuickSave ? txtQuickSave.textContent : 'Lưu';

  if (btnQuickSave) btnQuickSave.disabled = true;
  if (txtQuickSave) txtQuickSave.textContent = 'Đang lưu...';

  try {
    let res = await fetch('/api/servers', {
      method: 'POST',
      headers: getAuthHeaders(true),
      body: JSON.stringify({ name, host, port, username, password })
    });

    if (res.status === 401) {
      handleAuthExpired('Phiên làm việc đã hết hạn. Vui lòng đăng nhập lại.');
      return;
    }

    let data = await res.json();

    // Xử lý khi phát hiện trùng lặp
    if (res.status === 409 && data.duplicate) {
      if (data.duplicateField === 'target') {
        const confirmUpdate = confirm(
          `${data.message}\n\nBạn có muốn cập nhật thông tin / mật khẩu mới cho máy chủ này?`
        );
        if (confirmUpdate) {
          const retryRes = await fetch('/api/servers', {
            method: 'POST',
            headers: getAuthHeaders(true),
            body: JSON.stringify({ name, host, port, username, password, overwrite: true })
          });
          const retryData = await retryRes.json();
          if (retryData.success) {
            await fetchSavedServers();
            if (btnQuickSave) btnQuickSave.classList.add('saved');
            if (txtQuickSave) txtQuickSave.textContent = 'Đã cập nhật';
            setTimeout(() => {
              if (btnQuickSave) btnQuickSave.classList.remove('saved');
              if (txtQuickSave) txtQuickSave.textContent = originalText;
            }, 2500);
            return;
          } else {
            alert(`Cập nhật thất bại: ${retryData.message || retryData.error}`);
            return;
          }
        } else {
          return;
        }
      } else {
        alert(data.message);
        if (quickSshName) quickSshName.focus();
        return;
      }
    }

    if (data.success) {
      await fetchSavedServers();
      if (btnQuickSave) btnQuickSave.classList.add('saved');
      if (txtQuickSave) txtQuickSave.textContent = data.updated ? 'Đã cập nhật' : 'Đã lưu';
      setTimeout(() => {
        if (btnQuickSave) btnQuickSave.classList.remove('saved');
        if (txtQuickSave) txtQuickSave.textContent = originalText;
      }, 2500);
    } else {
      alert(`Lưu thất bại: ${data.message || data.error || 'Lỗi không xác định'}`);
    }
  } catch (err) {
    alert(`Lỗi mạng khi lưu máy chủ: ${err.message}`);
  } finally {
    if (btnQuickSave) btnQuickSave.disabled = false;
  }
}

function triggerQuickConnect() {
  const curTab = getActiveTab();
  if (curTab && curTab.status === 'connected') {
    disconnectTabSSH(curTab.id);
    return;
  }

  const host = (quickSshHost ? quickSshHost.value : '').trim();
  const port = (quickSshPort ? quickSshPort.value : '').trim() || '22';
  const user = (quickSshUser ? quickSshUser.value : '').trim() || 'root';
  const pass = quickSshPass ? quickSshPass.value : '';

  if (!host) {
    alert('Vui lòng nhập IP / Host máy chủ');
    if (quickSshHost) quickSshHost.focus();
    return;
  }

  localStorage.setItem('ssh_last_host', host);
  localStorage.setItem('ssh_last_port', port);
  localStorage.setItem('ssh_last_user', user);

  const quickSshName = document.getElementById('quickSshName');
  const customName = quickSshName ? quickSshName.value.trim() : '';
  const tabTitle = customName || `${user}@${host}:${port}`;

  // Nếu tab hiện tại chưa kết nối, sử dụng luôn tab hiện tại
  if (curTab && curTab.status === 'disconnected') {
    curTab.title = tabTitle;
    curTab.target = { host, port, username: user };
    const titleEl = document.getElementById(`title_${curTab.id}`);
    if (titleEl) titleEl.textContent = curTab.title;
    connectTabSSH(curTab.id, { host, port, username: user, password: pass });
  } else {
    // Mở tab mới
    createTab({
      title: tabTitle,
      host,
      port,
      username: user,
      password: pass,
      autoConnect: true
    });
  }
}

const DEFAULT_TERMINAL_COMMANDS = [
  { label: 'clear', command: 'clear' },
  { label: 'htop', command: 'htop' },
  { label: 'pm2 list', command: 'pm2 list' },
  { label: 'free -h', command: 'free -h' },
  { label: 'df -h /', command: 'df -h /' },
  { label: 'status postgresql', command: 'systemctl status postgresql' },
  { label: 'status nginx', command: 'systemctl status nginx' },
  { label: 'open ports', command: 'ss -tulpn' }
];

function renderShortcutsBar(customCommands) {
  const footer = document.querySelector('.shortcuts-bar');
  if (!footer) return;

  let list = customCommands;
  if (!list || !Array.isArray(list) || list.length === 0) {
    const cached = localStorage.getItem('user_quick_commands');
    if (cached) {
      try { list = JSON.parse(cached); } catch {}
    }
  }
  if (!list || !Array.isArray(list) || list.length === 0) {
    if (currentLoggedUser && Array.isArray(currentLoggedUser.quickCommands) && currentLoggedUser.quickCommands.length > 0) {
      list = currentLoggedUser.quickCommands;
    } else {
      list = DEFAULT_TERMINAL_COMMANDS;
    }
  }

  const shortcutsLabel = window.i18n ? window.i18n.t('shortcuts_label') : 'Quick Commands:';
  footer.innerHTML = `
    <span class="shortcuts-label" data-i18n="shortcuts_label">${shortcutsLabel}</span>
    ${list.map(c => `
      <button type="button" class="cmd-chip" data-cmd="${escapeHtml(c.command || c.label)}">${escapeHtml(c.label || c.command)}</button>
    `).join('')}
  `;

  footer.querySelectorAll('.cmd-chip').forEach((chip) => {
    chip.addEventListener('click', () => {
      const cmd = chip.getAttribute('data-cmd');
      const curTab = getActiveTab();
      if (cmd && curTab && curTab.socket && curTab.socket.readyState === WebSocket.OPEN) {
        curTab.socket.send(JSON.stringify({ type: 'data', data: cmd + '\n' }));
        curTab.terminal.focus();
      }
    });
  });
}

// 8. Phím tắt nhanh
function setupShortcuts() {
  renderShortcutsBar();
}

// 9. Các nút điều khiển
function setupControls() {
  // Sidebar Toggle
  if (btnToggleSidebar && consoleSidebar) {
    btnToggleSidebar.addEventListener('click', () => {
      consoleSidebar.classList.toggle('collapsed');
      setTimeout(() => {
        const curTab = getActiveTab();
        if (curTab && curTab.fitAddon) curTab.fitAddon.fit();
      }, 280);
    });
  }

  // Font Size
  const btnPlus = document.getElementById('btnFontSizePlus');
  if (btnPlus) {
    btnPlus.addEventListener('click', () => {
      if (currentFontSize < 24) {
        currentFontSize += 1;
        tabs.forEach((t) => {
          t.terminal.options.fontSize = currentFontSize;
          t.fitAddon.fit();
        });
      }
    });
  }

  const btnMinus = document.getElementById('btnFontSizeMinus');
  if (btnMinus) {
    btnMinus.addEventListener('click', () => {
      if (currentFontSize > 11) {
        currentFontSize -= 1;
        tabs.forEach((t) => {
          t.terminal.options.fontSize = currentFontSize;
          t.fitAddon.fit();
        });
      }
    });
  }

  // Fullscreen
  const btnFs = document.getElementById('btnFullscreen');
  if (btnFs) {
    btnFs.addEventListener('click', () => {
      if (!document.fullscreenElement) {
        document.documentElement.requestFullscreen().catch(() => {});
      } else {
        document.exitFullscreen().catch(() => {});
      }
    });
  }

  // Modal xác nhận Đăng xuất (Cyber Modal)
  const modalConfirmLogout = document.getElementById('modalConfirmLogout');
  const btnLogoutModalClose = document.getElementById('btnLogoutModalClose');
  const btnLogoutModalCancel = document.getElementById('btnLogoutModalCancel');
  const btnLogoutModalConfirm = document.getElementById('btnLogoutModalConfirm');
  const logoutModalBackdrop = document.getElementById('logoutModalBackdrop');

  function openLogoutModal() {
    if (modalConfirmLogout) modalConfirmLogout.style.display = 'flex';
  }

  function closeLogoutModal() {
    if (modalConfirmLogout) modalConfirmLogout.style.display = 'none';
  }

  if (btnLogoutModalClose) btnLogoutModalClose.addEventListener('click', closeLogoutModal);
  if (btnLogoutModalCancel) btnLogoutModalCancel.addEventListener('click', closeLogoutModal);
  if (logoutModalBackdrop) logoutModalBackdrop.addEventListener('click', closeLogoutModal);

  if (btnLogoutModalConfirm) {
    btnLogoutModalConfirm.addEventListener('click', async () => {
      closeLogoutModal();
      document.documentElement.classList.remove('has-auth');
      localStorage.removeItem('console_token');
      authToken = null;
      tabs.forEach((t) => {
        if (t.socket) {
          try { t.socket.close(); } catch {}
        }
      });
      await fetch('/api/auth/logout', { method: 'POST' });
      showLoginView();
    });
  }

  // Logout Lớp 1
  const btnLogout = document.getElementById('btnLogoutLayer1');
  if (btnLogout) {
    btnLogout.addEventListener('click', openLogoutModal);
  }
}

// Lắng nghe sự kiện chuyển đổi ngôn ngữ để cập nhật lại toàn bộ giao diện động
window.addEventListener('languageChanged', () => {
  renderSavedServersList();
  renderShortcutsBar();
  const curTab = getActiveTab();
  if (curTab) {
    updateQuickConnectButtonState(curTab.status);
  }
});

