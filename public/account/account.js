// ========================================================
// NexConsole - Account & Security Management Logic
// ========================================================

let currentUser = null;
let current2FAStatus = null;
let currentSecretRaw = '';

const DEFAULT_QUICK_COMMANDS = [
  { label: 'clear', command: 'clear' },
  { label: 'htop', command: 'htop' },
  { label: 'pm2 list', command: 'pm2 list' },
  { label: 'free -h', command: 'free -h' },
  { label: 'df -h /', command: 'df -h /' },
  { label: 'status postgresql', command: 'systemctl status postgresql' },
  { label: 'status nginx', command: 'systemctl status nginx' },
  { label: 'open ports', command: 'ss -tulpn' }
];

let userQuickCommands = JSON.parse(JSON.stringify(DEFAULT_QUICK_COMMANDS));

function getAuthHeaders(isJson = false) {
  const token = localStorage.getItem('console_token');
  const headers = {};
  if (token && token !== 'null' && token !== 'undefined') {
    headers['Authorization'] = `Bearer ${token}`;
  }
  if (isJson) {
    headers['Content-Type'] = 'application/json';
  }
  return headers;
}

// Khởi chạy khi tài liệu sẵn sàng
document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initQueryParams();
  setupUserMenu();
  setupPasswordToggles();
  loadAccountData();
  bindEventHandlers();
});

// 1. Quản lý Tabs
function initTabs() {
  const tabButtons = document.querySelectorAll('.nav-tab-btn');
  tabButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');
      switchTab(targetTab);
    });
  });
}

function switchTab(tabName) {
  document.querySelectorAll('.nav-tab-btn').forEach((b) => {
    b.classList.toggle('active', b.getAttribute('data-tab') === tabName);
  });
  document.querySelectorAll('.account-tab-panel').forEach((panel) => {
    panel.classList.remove('active');
  });

  let panelId = 'panelProfile';
  if (tabName === 'security') panelId = 'panelSecurity';
  else if (tabName === 'commands') panelId = 'panelCommands';

  const activePanel = document.getElementById(panelId);
  if (activePanel) {
    activePanel.classList.add('active');
  }

  // Cập nhật URL mà không reload trang
  const url = new URL(window.location);
  url.searchParams.set('tab', tabName);
  window.history.replaceState({}, '', url);
}

function initQueryParams() {
  const params = new URLSearchParams(window.location.search);
  const requestedTab = params.get('tab');
  if (requestedTab === 'security') {
    switchTab('security');
  } else if (requestedTab === 'commands') {
    switchTab('commands');
  } else {
    switchTab('profile');
  }
}

// 2. Tải dữ liệu tài khoản & 2FA
async function loadAccountData() {
  try {
    const [resProfile, res2FA] = await Promise.all([
      fetch('/api/auth/profile', { headers: getAuthHeaders(true) }),
      fetch('/api/auth/2fa/status', { headers: getAuthHeaders(true) })
    ]);

    if (resProfile.status === 401 || res2FA.status === 401) {
      window.location.href = '/';
      return;
    }

    const dataProfile = await resProfile.json();
    const data2FA = await res2FA.json();

    if (dataProfile.success && dataProfile.profile) {
      currentUser = dataProfile.profile;
      renderProfileUI(currentUser);

      if (Array.isArray(currentUser.quickCommands) && currentUser.quickCommands.length > 0) {
        userQuickCommands = JSON.parse(JSON.stringify(currentUser.quickCommands));
      } else {
        userQuickCommands = JSON.parse(JSON.stringify(DEFAULT_QUICK_COMMANDS));
      }
      renderQuickCommandsList();
    }

    if (data2FA.success) {
      current2FAStatus = data2FA;
      render2FAUI(data2FA.enabled, data2FA.verifiedAt);
    }
  } catch (err) {
    console.error('Lỗi tải dữ liệu tài khoản:', err);
  }
}

function renderProfileUI(user) {
  const headerAvatar = document.getElementById('headerAvatar');
  const headerDisplayName = document.getElementById('headerDisplayName');
  const profileCardAvatar = document.getElementById('profileCardAvatar');
  const profileSummaryName = document.getElementById('profileSummaryName');
  const profileSummaryUsername = document.getElementById('profileSummaryUsername');
  const profUsername = document.getElementById('profUsername');
  const profDisplayName = document.getElementById('profDisplayName');
  const profEmail = document.getElementById('profEmail');

  const initials = (user.displayName || user.username || 'AD').substring(0, 2).toUpperCase();

  const userNavAvatar = document.getElementById('userNavAvatar');
  const dropdownAvatarLg = document.getElementById('dropdownAvatarLg');
  const dropdownFullName = document.getElementById('dropdownFullName');
  const dropdownUserName = document.getElementById('dropdownUserName');

  if (userNavAvatar) userNavAvatar.textContent = initials;
  if (dropdownAvatarLg) dropdownAvatarLg.textContent = initials;
  if (dropdownFullName) dropdownFullName.textContent = user.displayName || user.username;
  if (dropdownUserName) dropdownUserName.textContent = `@${user.username}`;

  if (headerAvatar) headerAvatar.textContent = initials;
  if (profileCardAvatar) profileCardAvatar.textContent = initials;
  if (headerDisplayName) headerDisplayName.textContent = user.displayName || user.username;
  if (profileSummaryName) profileSummaryName.textContent = user.displayName || user.username;
  if (profileSummaryUsername) profileSummaryUsername.textContent = `@${user.username}`;
  if (profUsername) profUsername.value = user.username;
  if (profDisplayName) profDisplayName.value = user.displayName || '';
  if (profEmail) profEmail.value = user.email || '';
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

  document.addEventListener('click', (e) => {
    if (!popover.contains(e.target) && !trigger.contains(e.target)) {
      popover.style.display = 'none';
      trigger.classList.remove('active');
    }
  });

  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      popover.style.display = 'none';
      trigger.classList.remove('active');
    }
  });
}

function setupPasswordToggles() {
  document.querySelectorAll('.btn-toggle-pass').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      const wrap = btn.closest('.input-wrap') || btn.parentElement;
      const input = wrap ? wrap.querySelector('input') : null;
      if (!input) return;

      const isPassword = input.type === 'password';
      input.type = isPassword ? 'text' : 'password';

      const eyeShow = btn.querySelector('.eye-show');
      const eyeHide = btn.querySelector('.eye-hide');
      if (eyeShow && eyeHide) {
        eyeShow.style.display = isPassword ? 'none' : 'block';
        eyeHide.style.display = isPassword ? 'block' : 'none';
      }
      btn.setAttribute('title', isPassword ? 'Ẩn mật khẩu' : 'Hiện mật khẩu');
      btn.setAttribute('aria-label', isPassword ? 'Ẩn mật khẩu' : 'Hiện mật khẩu');
    });
  });
}

function render2FAUI(isEnabled, verifiedAt) {
  const badge2faState = document.getElementById('badge2faState');
  const profile2faBadge = document.getElementById('profile2faBadge');
  const tabSecurityDot = document.getElementById('tabSecurityDot');
  const totpDisabledView = document.getElementById('totpDisabledView');
  const totpEnabledView = document.getElementById('totpEnabledView');
  const totpVerifiedTime = document.getElementById('totpVerifiedTime');
  const totpSetupSection = document.getElementById('totpSetupSection');

  const isVi = window.i18n && window.i18n.getLanguage() === 'vi';

  if (isEnabled) {
    if (badge2faState) {
      badge2faState.textContent = window.i18n ? window.i18n.t('totp_status_active') : (isVi ? 'ĐÃ BẬT' : 'ACTIVE');
      badge2faState.className = 'badge-2fa-state active';
    }
    if (profile2faBadge) {
      profile2faBadge.textContent = isVi ? '2FA: Đã bật' : '2FA: Active';
      profile2faBadge.className = 'badge-cyber badge-status active';
    }
    if (tabSecurityDot) {
      tabSecurityDot.className = 'tab-status-dot active';
      tabSecurityDot.title = isVi ? '2FA đang hoạt động an toàn' : '2FA is active and protecting';
    }
    if (totpDisabledView) totpDisabledView.style.display = 'none';
    if (totpEnabledView) totpEnabledView.style.display = 'flex';
    if (totpSetupSection) totpSetupSection.style.display = 'none';

    if (totpVerifiedTime) {
      if (verifiedAt) {
        const d = new Date(verifiedAt * 1000);
        const prefix = window.i18n ? window.i18n.t('totp_verified_time_prefix') : (isVi ? 'Kích hoạt lúc:' : 'Activated at:');
        const locale = isVi ? 'vi-VN' : 'en-US';
        totpVerifiedTime.textContent = `${prefix} ${d.toLocaleString(locale)}`;
      } else {
        totpVerifiedTime.textContent = window.i18n ? window.i18n.t('totp_protecting_msg') : (isVi ? 'Trạng thái: Đang bảo vệ bằng 2FA' : 'Status: Protected with 2FA');
      }
    }
  } else {
    if (badge2faState) {
      badge2faState.textContent = window.i18n ? window.i18n.t('totp_status_inactive') : (isVi ? 'CHƯA BẬT' : 'DISABLED');
      badge2faState.className = 'badge-2fa-state';
    }
    if (profile2faBadge) {
      profile2faBadge.textContent = isVi ? '2FA: Chưa bật' : '2FA: Disabled';
      profile2faBadge.className = 'badge-cyber badge-status';
    }
    if (tabSecurityDot) {
      tabSecurityDot.className = 'tab-status-dot';
      tabSecurityDot.title = isVi ? 'Khuyến nghị bật xác thực 2 bước' : 'Recommended to enable 2-Factor Authentication';
    }
    if (totpDisabledView) totpDisabledView.style.display = 'flex';
    if (totpEnabledView) totpEnabledView.style.display = 'none';
  }
}

// 3. Gán sự kiện Form & Buttons
function bindEventHandlers() {
  // Đăng xuất từ dropdown hoặc navbar
  const btnLogoutLayer1 = document.getElementById('btnLogoutLayer1');
  if (btnLogoutLayer1) {
    btnLogoutLayer1.addEventListener('click', openLogoutModal);
  }
  const btnLogout = document.getElementById('btnAccountLogout');
  if (btnLogout) {
    btnLogout.addEventListener('click', openLogoutModal);
  }

  // Modal Đăng xuất
  const btnLogoutModalClose = document.getElementById('btnLogoutModalClose');
  const btnLogoutModalCancel = document.getElementById('btnLogoutModalCancel');
  const btnLogoutModalConfirm = document.getElementById('btnLogoutModalConfirm');
  const logoutModalBackdrop = document.getElementById('logoutModalBackdrop');
  if (btnLogoutModalClose) btnLogoutModalClose.addEventListener('click', closeLogoutModal);
  if (btnLogoutModalCancel) btnLogoutModalCancel.addEventListener('click', closeLogoutModal);
  if (logoutModalBackdrop) logoutModalBackdrop.addEventListener('click', closeLogoutModal);
  if (btnLogoutModalConfirm) btnLogoutModalConfirm.addEventListener('click', doLogout);

  // Nút quản lý lệnh nhanh (Quick Commands)
  const btnAddQuickCmd = document.getElementById('btnAddQuickCmd');
  if (btnAddQuickCmd) {
    btnAddQuickCmd.addEventListener('click', addQuickCommandRow);
  }
  const btnResetDefaultCmds = document.getElementById('btnResetDefaultCmds');
  if (btnResetDefaultCmds) {
    btnResetDefaultCmds.addEventListener('click', resetDefaultQuickCommands);
  }
  const btnSaveQuickCmds = document.getElementById('btnSaveQuickCmds');
  if (btnSaveQuickCmds) {
    btnSaveQuickCmds.addEventListener('click', saveQuickCommands);
  }

  // Nút ẩn hiện sidebar
  const btnToggleSidebar = document.getElementById('btnToggleSidebar');
  const accountSidebar = document.querySelector('.account-sidebar');
  if (btnToggleSidebar && accountSidebar) {
    btnToggleSidebar.addEventListener('click', () => {
      const isHidden = accountSidebar.style.display === 'none';
      accountSidebar.style.display = isHidden ? 'flex' : 'none';
      const mainLayout = document.querySelector('.account-main-layout');
      if (mainLayout) {
        mainLayout.style.gridTemplateColumns = isHidden ? '280px 1fr' : '1fr';
      }
    });
  }

  // Toàn màn hình
  const btnFullscreen = document.getElementById('btnFullscreen');
  if (btnFullscreen) {
    btnFullscreen.addEventListener('click', () => {
      if (!document.fullscreenElement) {
        document.documentElement.requestFullscreen().catch(() => {});
      } else {
        document.exitFullscreen().catch(() => {});
      }
    });
  }

  // Nút Passkey ở navbar
  const btnRegisterPasskey = document.getElementById('btnRegisterPasskey');
  if (btnRegisterPasskey) {
    btnRegisterPasskey.addEventListener('click', handleRegisterPasskey);
  }

  // Lưu thông tin hồ sơ
  const formProfile = document.getElementById('formProfile');
  if (formProfile) {
    formProfile.addEventListener('submit', handleUpdateProfile);
  }

  // Đổi mật khẩu
  const formPassword = document.getElementById('formPassword');
  if (formPassword) {
    formPassword.addEventListener('submit', handleChangePassword);
  }

  // Bắt đầu thiết lập 2FA
  const btnStart2FASetup = document.getElementById('btnStart2FASetup');
  if (btnStart2FASetup) {
    btnStart2FASetup.addEventListener('click', handleStart2FASetup);
  }

  // Sao chép khóa bí mật
  const btnCopySecret = document.getElementById('btnCopySecret');
  if (btnCopySecret) {
    btnCopySecret.addEventListener('click', handleCopySecret);
  }

  // Xác nhận mã OTP kích hoạt 2FA
  const formConfirm2FA = document.getElementById('formConfirm2FA');
  if (formConfirm2FA) {
    formConfirm2FA.addEventListener('submit', handleConfirm2FA);
  }

  // Tắt 2FA Modal
  const btnOpenDisable2FAModal = document.getElementById('btnOpenDisable2FAModal');
  const btnCloseDisableModal = document.getElementById('btnCloseDisableModal');
  const btnCancelDisable2FA = document.getElementById('btnCancelDisable2FA');
  const backdropDisable2FA = document.getElementById('backdropDisable2FA');
  const formDisable2FA = document.getElementById('formDisable2FA');

  if (btnOpenDisable2FAModal) btnOpenDisable2FAModal.addEventListener('click', openDisableModal);
  if (btnCloseDisableModal) btnCloseDisableModal.addEventListener('click', closeDisableModal);
  if (btnCancelDisable2FA) btnCancelDisable2FA.addEventListener('click', closeDisableModal);
  if (backdropDisable2FA) backdropDisable2FA.addEventListener('click', closeDisableModal);
  if (formDisable2FA) formDisable2FA.addEventListener('submit', handleDisable2FA);

  // Thêm Passkey
  const btnRegisterNewPasskey = document.getElementById('btnRegisterNewPasskey');
  if (btnRegisterNewPasskey) {
    btnRegisterNewPasskey.addEventListener('click', handleRegisterPasskey);
  }

  // Phím Escape đóng modal
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeDisableModal();
    }
  });
}

// 4. Xử lý Cập nhật hồ sơ
async function handleUpdateProfile(e) {
  e.preventDefault();
  const btn = document.getElementById('btnSaveProfile');
  const profDisplayName = document.getElementById('profDisplayName');
  const profEmail = document.getElementById('profEmail');

  const displayName = profDisplayName.value.trim();

  btn.disabled = true;
  btn.textContent = window.i18n && window.i18n.getLanguage() === 'vi' ? 'Đang lưu...' : 'Saving...';

  try {
    const res = await fetch('/api/auth/profile', {
      method: 'POST',
      headers: getAuthHeaders(true),
      body: JSON.stringify({ displayName })
    });
    const data = await res.json();
    if (data.success) {
      showToast(window.i18n ? window.i18n.t('toast_update_profile_success') : 'Profile updated successfully!', 'success');
      loadAccountData();
    } else {
      showToast(data.message || 'Error updating profile', 'error');
    }
  } catch (err) {
    showToast(`Network error: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = window.i18n ? window.i18n.t('btn_save_profile') : 'Save Changes';
  }
}

// 5. Xử lý Đổi mật khẩu
async function handleChangePassword(e) {
  e.preventDefault();
  const passCurrent = document.getElementById('passCurrent');
  const passNew = document.getElementById('passNew');
  const passConfirm = document.getElementById('passConfirm');
  const alertEl = document.getElementById('passwordAlert');
  const btn = document.getElementById('btnSavePassword');

  alertEl.style.display = 'none';

  if (passNew.value !== passConfirm.value) {
    alertEl.textContent = window.i18n && window.i18n.getLanguage() === 'vi' 
      ? 'Mật khẩu xác nhận không khớp với mật khẩu mới!' 
      : 'Password confirmation does not match new password!';
    alertEl.className = 'alert-box error-alert';
    alertEl.style.display = 'block';
    return;
  }

  if (passNew.value.length < 6) {
    alertEl.textContent = window.i18n && window.i18n.getLanguage() === 'vi' 
      ? 'Mật khẩu mới phải có ít nhất 6 ký tự!' 
      : 'New password must be at least 6 characters!';
    alertEl.className = 'alert-box error-alert';
    alertEl.style.display = 'block';
    return;
  }

  btn.disabled = true;
  btn.textContent = window.i18n && window.i18n.getLanguage() === 'vi' ? 'Đang cập nhật...' : 'Updating...';

  try {
    const res = await fetch('/api/auth/profile/password', {
      method: 'POST',
      headers: getAuthHeaders(true),
      body: JSON.stringify({
        currentPassword: passCurrent.value,
        newPassword: passNew.value
      })
    });
    const data = await res.json();
    if (data.success) {
      passCurrent.value = '';
      passNew.value = '';
      passConfirm.value = '';
      const successMsg = window.i18n ? window.i18n.t('toast_change_pass_success') : 'Password changed successfully!';
      alertEl.textContent = successMsg;
      alertEl.className = 'alert-box success-alert';
      alertEl.style.display = 'block';
      showToast(successMsg, 'success');
    } else {
      alertEl.textContent = data.message || 'Cannot change password';
      alertEl.className = 'alert-box error-alert';
      alertEl.style.display = 'block';
    }
  } catch (err) {
    alertEl.textContent = `Error: ${err.message}`;
    alertEl.className = 'alert-box error-alert';
    alertEl.style.display = 'block';
  } finally {
    btn.disabled = false;
    btn.textContent = window.i18n ? window.i18n.t('btn_change_password') : 'Change Password';
  }
}

// 6. Xử lý Bật 2FA (Google Authenticator)
async function handleStart2FASetup() {
  const btn = document.getElementById('btnStart2FASetup');
  const setupSection = document.getElementById('totpSetupSection');
  const secretDisplay = document.getElementById('secretKeyDisplay');
  const qrContainer = document.getElementById('qrCanvasContainer');
  const otpInput = document.getElementById('otpCodeInput');

  btn.disabled = true;
  btn.innerHTML = `<span>${window.i18n ? window.i18n.t('generating_secret') : 'Generating security key...'}</span>`;

  try {
    const res = await fetch('/api/auth/2fa/setup', {
      method: 'POST',
      headers: getAuthHeaders(true)
    });
    const data = await res.json();

    if (data.success && data.secret && data.otpauthUrl) {
      currentSecretRaw = data.secret;
      
      // Chia cụm 4 chữ số cho dễ đọc (ví dụ: JBSW Y3DP EHPK ...)
      const formattedSecret = data.secret.match(/.{1,4}/g)?.join(' ') || data.secret;
      secretDisplay.textContent = formattedSecret;

      // Xóa QR code cũ nếu có
      qrContainer.innerHTML = '';

      // Sinh mã QR bằng thư viện QRCode.js
      if (typeof QRCode !== 'undefined') {
        new QRCode(qrContainer, {
          text: data.otpauthUrl,
          width: 170,
          height: 170,
          colorDark: '#000000',
          colorLight: '#ffffff',
          correctLevel: QRCode.CorrectLevel.L
        });
      } else {
        qrContainer.innerHTML = `<span style="color:#ef4444;font-size:0.75rem;">Cannot find QRCode renderer</span>`;
      }

      setupSection.style.display = 'flex';
      setupSection.scrollIntoView({ behavior: 'smooth' });
      if (otpInput) {
        otpInput.value = '';
        setTimeout(() => otpInput.focus(), 300);
      }
    } else {
      showToast(data.message || (window.i18n ? window.i18n.t('error_create_2fa') : 'Cannot generate 2FA key'), 'error');
    }
  } catch (err) {
    showToast(`Network error: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    const btnLabel = window.i18n ? window.i18n.t('btn_get_new_qr') : 'Generate New QR Code';
    btn.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      <span>${btnLabel}</span>
    `;
  }
}

function handleCopySecret() {
  if (!currentSecretRaw) return;
  navigator.clipboard.writeText(currentSecretRaw).then(() => {
    const txt = document.getElementById('txtCopySecret');
    if (txt) {
      txt.textContent = window.i18n ? window.i18n.t('btn_copied_secret') : 'Copied';
      setTimeout(() => {
        txt.textContent = window.i18n ? window.i18n.t('btn_copy_secret') : 'Copy';
      }, 2000);
    }
    showToast(window.i18n ? window.i18n.t('toast_copy_secret_success') : 'Secret key copied to clipboard!', 'success');
  }).catch(() => {
    prompt('Secret Key:', currentSecretRaw);
  });
}

async function handleConfirm2FA(e) {
  e.preventDefault();
  const otpInput = document.getElementById('otpCodeInput');
  const alertEl = document.getElementById('setupAlert');
  const btn = document.getElementById('btnConfirm2FA');

  const code = otpInput.value.trim().replace(/\s+/g, '');
  if (code.length !== 6 || !/^\d+$/.test(code)) {
    alertEl.textContent = window.i18n && window.i18n.getLanguage() === 'vi' 
      ? 'Vui lòng nhập đúng 6 chữ số OTP từ ứng dụng Google Authenticator!' 
      : 'Please enter the valid 6-digit OTP code from Google Authenticator!';
    alertEl.className = 'alert-box error-alert';
    alertEl.style.display = 'block';
    return;
  }

  alertEl.style.display = 'none';
  btn.disabled = true;
  btn.textContent = window.i18n && window.i18n.getLanguage() === 'vi' ? 'Đang xác thực...' : 'Verifying...';

  try {
    const res = await fetch('/api/auth/2fa/enable', {
      method: 'POST',
      headers: getAuthHeaders(true),
      body: JSON.stringify({ code })
    });
    const data = await res.json();

    if (data.success) {
      showToast(window.i18n ? window.i18n.t('toast_2fa_enabled_success') : 'Two-factor authentication enabled successfully!', 'success');
      loadAccountData();
    } else {
      alertEl.textContent = data.message || 'Invalid verification code. Please try again.';
      alertEl.className = 'alert-box error-alert';
      alertEl.style.display = 'block';
    }
  } catch (err) {
    alertEl.textContent = `Error: ${err.message}`;
    alertEl.className = 'alert-box error-alert';
    alertEl.style.display = 'block';
  } finally {
    btn.disabled = false;
    btn.textContent = window.i18n ? window.i18n.t('btn_confirm_enable_2fa') : 'Verify & Enable 2FA';
  }
}

// 7. Xử lý Tắt 2FA
function openDisableModal() {
  const modal = document.getElementById('modalDisable2FA');
  const passInput = document.getElementById('disableConfirmPassword');
  const alertEl = document.getElementById('disableAlert');
  if (alertEl) alertEl.style.display = 'none';
  if (passInput) passInput.value = '';
  if (modal) {
    modal.style.display = 'flex';
    setTimeout(() => { if (passInput) passInput.focus(); }, 100);
  }
}

function closeDisableModal() {
  const modal = document.getElementById('modalDisable2FA');
  if (modal) modal.style.display = 'none';
}

async function handleDisable2FA(e) {
  e.preventDefault();
  const passInput = document.getElementById('disableConfirmPassword');
  const alertEl = document.getElementById('disableAlert');
  const btn = document.getElementById('btnConfirmDisable2FA');

  const val = passInput.value.trim().replace(/\s+/g, '');
  if (!val) return;

  if (!/^\d{6}$/.test(val)) {
    alertEl.textContent = window.i18n ? window.i18n.t('invalid_otp_code') : 'Please enter the valid 6-digit OTP code from Google Authenticator!';
    alertEl.className = 'alert-box error-alert';
    alertEl.style.display = 'block';
    return;
  }

  btn.disabled = true;
  btn.textContent = window.i18n ? window.i18n.t('btn_processing') : 'Processing...';
  alertEl.style.display = 'none';

  const payload = { code: val };

  try {
    const res = await fetch('/api/auth/2fa/disable', {
      method: 'POST',
      headers: getAuthHeaders(true),
      body: JSON.stringify(payload)
    });
    const data = await res.json();

    if (data.success) {
      currentSecretRaw = '';
      const setupSection = document.getElementById('totpSetupSection');
      if (setupSection) setupSection.style.display = 'none';
      const qrContainer = document.getElementById('qrCanvasContainer');
      if (qrContainer) qrContainer.innerHTML = '';
      passInput.value = '';
      closeDisableModal();
      showToast(window.i18n ? window.i18n.t('toast_2fa_disabled_success') : 'Two-factor authentication disabled successfully!', 'success');
      loadAccountData();
    } else {
      alertEl.textContent = data.message || (window.i18n && window.i18n.getLanguage() === 'vi' ? 'Mã xác thực 6 số không chính xác!' : 'Invalid 6-digit verification code!');
      alertEl.className = 'alert-box error-alert';
      alertEl.style.display = 'block';
    }
  } catch (err) {
    alertEl.textContent = `Error: ${err.message}`;
    alertEl.className = 'alert-box error-alert';
    alertEl.style.display = 'block';
  } finally {
    btn.disabled = false;
    btn.textContent = window.i18n ? window.i18n.t('btn_confirm_disable_2fa') : 'Confirm Disable 2FA';
  }
}

// 8. Đăng ký Passkey cho thiết bị
async function handleRegisterPasskey() {
  if (!window.PublicKeyCredential) {
    alert(window.i18n && window.i18n.getLanguage() === 'vi' 
      ? 'Trình duyệt hoặc thiết bị của bạn không hỗ trợ Passkey / WebAuthn.' 
      : 'Your browser or device does not support Passkey / WebAuthn.');
    return;
  }

  const btn = document.getElementById('btnRegisterNewPasskey');
  btn.disabled = true;
  btn.textContent = window.i18n ? window.i18n.t('connecting_biometrics') : 'Connecting biometric authentication...';

  try {
    const challengeRes = await fetch('/api/auth/passkey/register-challenge');
    const options = await challengeRes.json();
    if (!options.publicKey) throw new Error('Challenge fetch failed');

    options.publicKey.challenge = bufferDecode(options.publicKey.challenge);
    options.publicKey.user.id = bufferDecode(options.publicKey.user.id);
    if (options.publicKey.excludeCredentials) {
      options.publicKey.excludeCredentials.forEach(cred => {
        cred.id = bufferDecode(cred.id);
      });
    }

    const credential = await navigator.credentials.create({ publicKey: options.publicKey });
    const verifyPayload = {
      id: credential.id,
      rawId: bufferEncode(credential.rawId),
      response: {
        attestationObject: bufferEncode(credential.response.attestationObject),
        clientDataJSON: bufferEncode(credential.response.clientDataJSON),
      },
      type: credential.type,
    };

    const verifyRes = await fetch('/api/auth/passkey/register-verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(verifyPayload),
    });

    const verifyResult = await verifyRes.json();
    if (verifyResult.success) {
      showToast(window.i18n ? window.i18n.t('toast_passkey_success') : 'Passkey registered successfully!', 'success');
    } else {
      showToast(`Error: ${verifyResult.error}`, 'error');
    }
  } catch (err) {
    const isVi = window.i18n && window.i18n.getLanguage() === 'vi';
    if (err.name === 'InvalidStateError' || (err.message && err.message.includes('already registered'))) {
      showToast(isVi ? 'Thiết bị này đã được lưu Passkey từ trước. Bạn có thể sử dụng để đăng nhập ngay!' : 'This device already has a registered Passkey. You can use it to log in!', 'info');
    } else if (err.name === 'NotAllowedError') {
      showToast(isVi ? 'Đã hủy thao tác xác thực Passkey.' : 'Passkey verification cancelled.', 'info');
    } else {
      showToast(`Passkey Error: ${err.message}`, 'error');
    }
  } finally {
    btn.disabled = false;
    const btnLabel = window.i18n ? window.i18n.t('btn_add_passkey') : 'Add Passkey';
    btn.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 004.07 9m5.93 11a10.038 10.038 0 003.568-1.785"/>
      </svg>
      <span>${btnLabel}</span>
    `;
  }
}

// 9. Quản lý Đăng xuất (Custom Modal)
function openLogoutModal() {
  const modal = document.getElementById('modalConfirmLogout');
  if (modal) modal.style.display = 'flex';
}

function closeLogoutModal() {
  const modal = document.getElementById('modalConfirmLogout');
  if (modal) modal.style.display = 'none';
}

async function doLogout() {
  try {
    await fetch('/api/auth/logout', { method: 'POST' });
  } catch {}
  localStorage.removeItem('console_token');
  window.location.href = '/';
}

// 10. Quản lý danh sách Lệnh Nhanh (Repeater)
function renderQuickCommandsList() {
  const container = document.getElementById('quickCommandsList');
  if (!container) return;

  if (userQuickCommands.length === 0) {
    const emptyMsg = window.i18n ? window.i18n.t('empty_cmds_msg') : 'No quick commands configured yet. Click "Add Command" above to create shortcuts.';
    container.innerHTML = `
      <div style="padding: 24px; text-align: center; color: var(--text-dim); font-size: 0.88rem; background: rgba(255,255,255,0.01); border: 1px dashed var(--border-subtle); border-radius: var(--radius-sm);">
        ${emptyMsg}
      </div>
    `;
    return;
  }

  const labelPlaceholder = window.i18n ? window.i18n.t('placeholder_cmd_label') : 'Button label (e.g. htop)';
  const valPlaceholder = window.i18n ? window.i18n.t('placeholder_cmd_val') : 'Command to run (e.g. htop)';
  const removeTitle = window.i18n ? window.i18n.t('btn_remove_cmd_title') : 'Delete this command';

  container.innerHTML = userQuickCommands.map((item, index) => `
    <div class="repeater-item" data-index="${index}">
      <span class="repeater-drag-handle">${index + 1}</span>
      <div class="input-wrap">
        <input type="text" class="cmd-label-input" placeholder="${labelPlaceholder}" value="${escapeHtml(item.label || '')}" data-index="${index}">
      </div>
      <div class="input-wrap input-val-wrap">
        <input type="text" class="cmd-value-input" placeholder="${valPlaceholder}" value="${escapeHtml(item.command || '')}" data-index="${index}">
      </div>
      <button type="button" class="btn-remove-cmd" data-index="${index}" title="${removeTitle}">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
      </button>
    </div>
  `).join('');

  // Lắng nghe sự kiện chỉnh sửa input
  container.querySelectorAll('.cmd-label-input').forEach(input => {
    input.addEventListener('input', (e) => {
      const idx = parseInt(e.target.dataset.index, 10);
      if (userQuickCommands[idx]) {
        userQuickCommands[idx].label = e.target.value;
      }
    });
  });

  container.querySelectorAll('.cmd-value-input').forEach(input => {
    input.addEventListener('input', (e) => {
      const idx = parseInt(e.target.dataset.index, 10);
      if (userQuickCommands[idx]) {
        userQuickCommands[idx].command = e.target.value;
      }
    });
  });

  // Lắng nghe nút xóa dòng
  container.querySelectorAll('.btn-remove-cmd').forEach(btn => {
    btn.addEventListener('click', () => {
      const idx = parseInt(btn.dataset.index, 10);
      userQuickCommands.splice(idx, 1);
      renderQuickCommandsList();
    });
  });
}

function addQuickCommandRow() {
  userQuickCommands.push({ label: '', command: '' });
  renderQuickCommandsList();
  const container = document.getElementById('quickCommandsList');
  if (container) {
    const inputs = container.querySelectorAll('.cmd-label-input');
    if (inputs.length > 0) {
      inputs[inputs.length - 1].focus();
    }
  }
}

function resetDefaultQuickCommands() {
  userQuickCommands = JSON.parse(JSON.stringify(DEFAULT_QUICK_COMMANDS));
  renderQuickCommandsList();
  showToast(window.i18n ? window.i18n.t('toast_reset_cmds_info') : 'Restored 8 default commands. Click "Save Commands" to apply.', 'info');
}

async function saveQuickCommands() {
  const btnSave = document.getElementById('btnSaveQuickCmds');

  // Đồng bộ lại từ DOM inputs
  const container = document.getElementById('quickCommandsList');
  if (container) {
    const items = container.querySelectorAll('.repeater-item');
    const updated = [];
    items.forEach(row => {
      const labelInput = row.querySelector('.cmd-label-input');
      const valInput = row.querySelector('.cmd-value-input');
      const label = (labelInput ? labelInput.value : '').trim();
      const command = (valInput ? valInput.value : '').trim();
      if (label || command) {
        updated.push({
          label: label || command,
          command: command || label
        });
      }
    });
    userQuickCommands = updated;
  }

  try {
    if (btnSave) {
      btnSave.disabled = true;
      btnSave.innerHTML = `<span>${window.i18n ? window.i18n.t('saving') : 'Saving...'}</span>`;
    }

    const res = await fetch('/api/auth/profile/quick-commands', {
      method: 'POST',
      headers: {
        ...getAuthHeaders(true),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ commands: userQuickCommands })
    });

    const data = await res.json();
    if (data.success) {
      showToast(window.i18n ? window.i18n.t('toast_save_cmds_success') : 'Quick commands configuration saved successfully!', 'success');
      localStorage.setItem('user_quick_commands', JSON.stringify(userQuickCommands));
      renderQuickCommandsList();
    } else {
      showToast(data.message || (window.i18n && window.i18n.getLanguage() === 'vi' ? 'Lỗi lưu danh sách lệnh' : 'Failed to save quick commands'), 'error');
    }
  } catch (err) {
    showToast(`Network error: ${err.message}`, 'error');
  } finally {
    if (btnSave) {
      btnSave.disabled = false;
      btnSave.innerHTML = `<span>${window.i18n ? window.i18n.t('btn_save_cmds') : 'Save Commands'}</span>`;
    }
  }
}

// Toast Helpers
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
  toast.innerHTML = `
    <div style="flex:1;">${escapeHtml(message)}</div>
  `;
  container.appendChild(toast);

  setTimeout(() => toast.classList.add('toast-show'), 10);
  setTimeout(() => {
    toast.classList.remove('toast-show');
    toast.classList.add('toast-hide');
    setTimeout(() => {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, 300);
  }, 3500);
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/[&<>'"]/g, 
    tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
  );
}

// Base64 WebAuthn Helpers
function bufferDecode(value) {
  return Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
}

function bufferEncode(value) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

// 11. Lắng nghe sự kiện chuyển đổi ngôn ngữ
window.addEventListener('languageChanged', (e) => {
  renderQuickCommandsList();
  if (current2FAStatus) {
    render2FAUI(current2FAStatus.enabled, current2FAStatus.verifiedAt);
  }
});

