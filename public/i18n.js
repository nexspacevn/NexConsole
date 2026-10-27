// ========================================================
// NexSpace WebConsole - Internationalization (i18n) Module
// Supported: English ('en' - Default), Vietnamese ('vi')
// ========================================================

const translations = {
  en: {
    // Page Title
    app_title: "NexConsole | Secure Terminal Gateway",
    account_page_title: "NexConsole | Account & Security",

    // Login Screen
    passkey_quick_login: "Quick Login",
    passkey_quick_sub: "Fast access into the system with Passkey",
    or_access_account: "Or access with account",
    username_placeholder: "Access account [root / user]...",
    password_placeholder: "Security Key...",
    login_btn: "Authenticate & Open Gateway",
    totp_title: "Two-Factor Authentication (2FA)",
    totp_desc: "Open Google Authenticator on your phone and enter the 6-digit code:",
    verify_otp_btn: "Verify OTP Code",
    back_to_password: "← Back to password login",
    login_authenticating: "Authenticating Touch ID / Passkey...",
    login_error_touchid_cancelled: "Biometric authentication cancelled",
    login_error_passkey_fail: "Passkey authentication failed!",

    // Top Bar & Controls
    passkey_nav_btn: "Passkey",
    passkey_nav_title: "Add Touch ID / Passkey for this device",
    font_minus_title: "Decrease font size",
    font_plus_title: "Increase font size",
    fullscreen_title: "Fullscreen",
    toggle_sidebar_title: "Toggle sidebar",
    user_profile_title: "User Account",
    nav_profile: "Profile",
    nav_security: "Security",
    nav_settings: "Settings",
    nav_logout: "Logout",

    // Terminal View & Tabs
    tab_connecting: "Connecting...",
    tab_connected: "Connected",
    tab_disconnected: "Disconnected",
    ssh_handshake: "[SSH] Establishing secure connection...",
    ssh_connected_prefix: "[SSH] Successfully connected to",
    ssh_session_ended: "[SSH] Session ended.",
    ws_session_ended: "[WebSocket] Work session has ended.",
    ws_error: "[WebSocket] Connection error!",

    // Sidebar & Server Management
    sidebar_servers_title: "Server List",
    sidebar_search_placeholder: "Search server...",
    sidebar_add_server_btn: "Add Server",
    sidebar_empty_servers: "No servers added yet. Click \"Add Server\" to connect.",
    btn_connect: "Connect",
    btn_disconnect: "Disconnect",
    btn_edit: "Edit",
    btn_delete: "Delete",
    server_online: "ONLINE",
    server_offline: "OFFLINE",

    // Shortcuts Bar
    shortcuts_label: "Quick Commands:",

    // Modals
    modal_server_add_title: "Add New Server",
    modal_server_edit_title: "Edit Server",
    label_server_name: "Server Name",
    placeholder_server_name: "e.g. Production Cluster #01",
    label_server_host: "IP Address / Hostname",
    placeholder_server_host: "192.168.1.100 or server.domain.com",
    label_server_port: "SSH Port",
    label_server_user: "SSH Username",
    label_server_pass: "SSH Password",
    placeholder_server_pass: "Enter server password...",
    btn_save_server: "Save Server",
    btn_cancel: "Cancel",

    // Delete Server Modal
    modal_delete_server_title: "Delete Server",
    modal_delete_server_desc: "Are you sure you want to delete server",
    modal_delete_server_warning: "This action cannot be undone. Saved credentials will be permanently erased.",
    btn_confirm_delete: "Delete Server",

    // Logout Modal
    logout_modal_title: "Logout WebConsole",
    logout_modal_desc: "Are you sure you want to log out of WebConsole? Open terminal sessions will be closed safely.",
    logout_modal_cancel: "Cancel",
    logout_modal_confirm: "Logout",

    // Account Navigation Tabs
    tab_btn_profile: "Profile",
    tab_btn_profile_desc: "Linked account info",
    tab_btn_security: "Security",
    tab_btn_security_desc: "Password, 2FA & Passkey",
    tab_btn_commands: "Quick Commands",
    tab_btn_commands_desc: "Terminal shortcuts",

    // Account Profile Panel
    panel_profile_title: "Profile",
    panel_profile_sub: "Manage your display name and contact credentials.",
    card_basic_info: "Basic Information",
    label_username: "Login Username",
    label_display_name: "Display Name",
    placeholder_display_name: "Enter display name...",
    label_email: "Contact Email",
    btn_save_profile: "Save Changes",
    badge_admin: "Administrator",

    // Account Security Panel
    panel_security_title: "Security",
    panel_security_sub: "Manage password, two-factor authentication, and biometric login.",
    card_change_password: "Change Password",
    label_current_password: "Current Password",
    label_new_password: "New Password",
    placeholder_new_password: "At least 6 characters...",
    label_confirm_password: "Confirm New Password",
    placeholder_confirm_password: "Re-enter new password...",
    btn_change_password: "Change Password",

    card_2fa_title: "Two-Factor Authentication (2FA)",
    card_2fa_desc: "Protect your account with Google Authenticator time-based OTP codes.",
    totp_status_active: "ACTIVE",
    totp_status_inactive: "DISABLED",
    totp_verified_time_prefix: "Activated at:",
    totp_protecting_msg: "Status: Protected with 2FA",
    btn_start_2fa: "Enable 2FA",
    btn_disable_2fa: "Disable 2FA",
    modal_disable_2fa_title: "Disable 2-Factor Authentication",
    modal_disable_2fa_desc: "Enter the 6-digit code from Google Authenticator to confirm disabling:",
    label_disable_2fa_code: "6-digit code",
    btn_confirm_disable_2fa: "Confirm Disable 2FA",

    card_passkey_title: "Biometric Login",
    card_passkey_desc: "Use Touch ID, Face ID, or security key to log straight into WebConsole in 1 second.",
    btn_add_passkey: "Add Passkey",

    // Account Quick Commands Panel
    panel_commands_title: "Custom Quick Commands",
    panel_commands_sub: "Configure shortcut buttons on the Terminal toolbar for personal workflow.",
    card_commands_title: "Shortcut Command List",
    card_commands_desc: "Clicking a command button on the Terminal toolbar will automatically execute the command in your SSH session.",
    btn_add_cmd: "Add Command",
    col_num: "#",
    col_label: "Display Label",
    col_cmd: "Execution Command",
    col_action: "Action",
    placeholder_cmd_label: "Button label (e.g. htop)",
    placeholder_cmd_val: "Command to run (e.g. htop)",
    btn_remove_cmd_title: "Delete this command",
    btn_reset_default_cmds: "Reset to Default",
    btn_save_cmds: "Save Commands",
    empty_cmds_msg: "No quick commands configured yet. Click \"Add Command\" above to create shortcuts.",

    // Passkey Banner
    passkey_banner_title: "Fast login with Passkey (Touch ID)",
    passkey_banner_desc: "Save your device biometrics to log directly into Layer 1 in 1 second next time.",
    btn_banner_save: "Save Passkey Now",
    btn_banner_dismiss: "Later",

    // Quick Connect Sidebar
    sidebar_quick_connect_title: "Quick Connect",
    placeholder_quick_name: "Server alias...",
    placeholder_quick_host: "Server IP / Host...",
    placeholder_quick_port: "Port",
    placeholder_quick_user: "Username (root)",
    placeholder_quick_pass: "Password...",
    btn_quick_save: "Save",
    btn_quick_connect: "Connect",
    btn_new_tab_title: "Open new SSH tab",

    // 2FA Setup
    totp_step_1: "Install Google Authenticator app on your phone.",
    totp_step_2: "Click setup button to get QR code and scan with your phone camera.",
    totp_step_3: "Enter the 6-digit code displayed on your app to confirm activation.",
    totp_scan_qr_title: "Scan QR Code with Google Authenticator",
    totp_secret_label: "Secret Key (enter manually if camera scan is not available):",
    btn_copy_secret: "Copy",
    btn_copied_secret: "Copied",
    label_enter_otp: "Enter 6-digit verification code from Google Authenticator:",
    btn_confirm_enable_2fa: "Verify & Enable 2FA",
    totp_active_headline: "Account is protected with Google Authenticator",
    totp_active_desc: "Every time you sign in to WebConsole, a 6-digit OTP code from your phone app is required.",
    title_show_password: "Show password",
    title_hide_password: "Hide password",

    // Toasts & Messages
    toast_save_cmds_success: "Quick commands configuration saved successfully!",
    toast_reset_cmds_info: "Restored 8 default commands. Click \"Save Commands\" to apply.",
    toast_update_profile_success: "Profile updated successfully!",
    toast_change_pass_success: "Password changed successfully!",
    toast_passkey_success: "Passkey registered successfully! You can now use Touch ID to log in quickly.",
    toast_2fa_enabled_success: "Two-factor authentication (Google Authenticator) enabled successfully!",
    toast_2fa_disabled_success: "Two-factor authentication disabled successfully!",
    toast_copy_secret_success: "Secret key copied to clipboard!",
    generating_secret: "Generating security key...",
    btn_get_new_qr: "Generate New QR Code",
    connecting_biometrics: "Connecting biometric authentication...",
    btn_processing: "Processing...",
    saving: "Saving...",
    error_create_2fa: "Cannot generate 2FA key",
    invalid_otp_code: "Please enter the valid 6-digit OTP code from Google Authenticator!"
  },

  vi: {
    // Page Title
    app_title: "NexConsole | Cổng Terminal Bảo Mật",
    account_page_title: "NexConsole | Quản lý Tài khoản & Bảo mật",

    // Login Screen
    passkey_quick_login: "Đăng nhập nhanh",
    passkey_quick_sub: "Đăng nhập nhanh vào hệ thống với Passkey",
    or_access_account: "Hoặc truy cập bằng tài khoản",
    username_placeholder: "Tài khoản truy cập [root / user]...",
    password_placeholder: "Khóa bảo mật [Security Key]...",
    login_btn: "Xác thực & mở cổng",
    totp_title: "Xác minh hai bước (2FA)",
    totp_desc: "Mở ứng dụng Google Authenticator trên điện thoại và nhập mã xác thực 6 số:",
    verify_otp_btn: "Xác thực mã OTP",
    back_to_password: "← Quay lại đăng nhập bằng mật khẩu",
    login_authenticating: "Đang xác thực Touch ID / Passkey...",
    login_error_touchid_cancelled: "Xác thực vân tay bị hủy",
    login_error_passkey_fail: "Xác thực Passkey thất bại!",

    // Top Bar & Controls
    passkey_nav_btn: "Passkey",
    passkey_nav_title: "Thêm Touch ID / Passkey thiết bị này",
    font_minus_title: "Thu nhỏ chữ",
    font_plus_title: "Phóng to chữ",
    fullscreen_title: "Toàn màn hình",
    toggle_sidebar_title: "Ẩn / hiện thanh bên",
    user_profile_title: "Tài khoản người dùng",
    nav_profile: "Hồ sơ cá nhân",
    nav_security: "Bảo mật",
    nav_settings: "Cài đặt",
    nav_logout: "Thoát",

    // Terminal View & Tabs
    tab_connecting: "Đang kết nối...",
    tab_connected: "Đã kết nối",
    tab_disconnected: "Đã ngắt",
    ssh_handshake: "[SSH] Đang bắt tay kết nối bảo mật...",
    ssh_connected_prefix: "[SSH] Đã kết nối SSH thành công tới",
    ssh_session_ended: "[SSH] Phiên SSH đã kết thúc.",
    ws_session_ended: "[WebSocket] Đã kết thúc phiên làm việc.",
    ws_error: "[WebSocket] Lỗi kết nối WebSocket!",

    // Sidebar & Server Management
    sidebar_servers_title: "Danh sách máy chủ",
    sidebar_search_placeholder: "Tìm máy chủ...",
    sidebar_add_server_btn: "Thêm máy chủ",
    sidebar_empty_servers: "Chưa có máy chủ nào. Bấm \"Thêm máy chủ\" để kết nối.",
    btn_connect: "Kết nối",
    btn_disconnect: "Ngắt kết nối",
    btn_edit: "Sửa",
    btn_delete: "Xóa",
    server_online: "ONLINE",
    server_offline: "OFFLINE",

    // Shortcuts Bar
    shortcuts_label: "Lệnh nhanh:",

    // Modals
    modal_server_add_title: "Thêm máy chủ mới",
    modal_server_edit_title: "Chỉnh sửa máy chủ",
    label_server_name: "Tên gợi nhớ",
    placeholder_server_name: "vd: Cluster Sản Xuất #01",
    label_server_host: "Địa chỉ IP / Host",
    placeholder_server_host: "192.168.1.100 hoặc server.domain.com",
    label_server_port: "Cổng SSH",
    label_server_user: "Tài khoản SSH",
    label_server_pass: "Mật khẩu SSH",
    placeholder_server_pass: "Nhập mật khẩu SSH máy chủ...",
    btn_save_server: "Lưu máy chủ",
    btn_cancel: "Hủy bỏ",

    // Delete Server Modal
    modal_delete_server_title: "Xác nhận xóa máy chủ",
    modal_delete_server_desc: "Bạn có chắc chắn muốn xóa máy chủ",
    modal_delete_server_warning: "Hành động này không thể hoàn tác. Mật khẩu đã lưu sẽ bị xóa vĩnh viễn.",
    btn_confirm_delete: "Xóa máy chủ",

    // Logout Modal
    logout_modal_title: "Đăng xuất WebConsole",
    logout_modal_desc: "Bạn có chắc chắn muốn đăng xuất khỏi WebConsole? Các phiên terminal đang mở sẽ được đóng an toàn.",
    logout_modal_cancel: "Hủy bỏ",
    logout_modal_confirm: "Đăng xuất",

    // Account Navigation Tabs
    tab_btn_profile: "Hồ sơ cá nhân",
    tab_btn_profile_desc: "Thông tin tài khoản liên kết",
    tab_btn_security: "Bảo mật",
    tab_btn_security_desc: "Mật khẩu, 2FA & Passkey",
    tab_btn_commands: "Lệnh nhanh",
    tab_btn_commands_desc: "Phím tắt lệnh trên Terminal",

    // Account Profile Panel
    panel_profile_title: "Thông tin tài khoản",
    panel_profile_sub: "Quản lý tên hiển thị và thông tin liên hệ của bạn.",
    card_basic_info: "Thông tin cơ bản",
    label_username: "Tên tài khoản đăng nhập",
    label_display_name: "Tên hiển thị",
    placeholder_display_name: "Nhập tên hiển thị...",
    label_email: "Địa chỉ email liên hệ",
    btn_save_profile: "Lưu thay đổi",
    badge_admin: "Quản trị viên",

    // Account Security Panel
    panel_security_title: "Bảo mật",
    panel_security_sub: "Quản lý mật khẩu, xác thực 2 bước và đăng nhập sinh trắc học.",
    card_change_password: "Đổi mật khẩu",
    label_current_password: "Mật khẩu hiện tại",
    label_new_password: "Mật khẩu mới",
    placeholder_new_password: "Tối thiểu 6 ký tự...",
    label_confirm_password: "Xác nhận mật khẩu mới",
    placeholder_confirm_password: "Nhập lại mật khẩu mới...",
    btn_change_password: "Đổi mật khẩu",

    card_2fa_title: "Xác thực 2 bước (Google Authenticator)",
    card_2fa_desc: "Bảo vệ tài khoản bằng mã xác thực 6 số dùng một lần từ điện thoại của bạn.",
    totp_status_active: "ĐÃ BẬT",
    totp_status_inactive: "CHƯA BẬT",
    totp_verified_time_prefix: "Kích hoạt lúc:",
    totp_protecting_msg: "Trạng thái: Đang bảo vệ bằng 2FA",
    btn_start_2fa: "Bật xác thực 2 bước",
    btn_disable_2fa: "Tắt xác thực 2 bước",
    modal_disable_2fa_title: "Tắt xác thực 2 bước",
    modal_disable_2fa_desc: "Nhập mã xác thực 6 số từ Google Authenticator để xác nhận tắt tính năng này.",
    label_disable_2fa_code: "Mã xác thực 6 số",
    btn_confirm_disable_2fa: "Xác nhận tắt 2FA",

    card_passkey_title: "Đăng nhập sinh trắc học",
    card_passkey_desc: "Sử dụng Touch ID, Face ID hoặc khóa bảo mật để vào thẳng WebConsole trong 1 giây.",
    btn_add_passkey: "Thêm Passkey",

    // Account Quick Commands Panel
    panel_commands_title: "Tùy chỉnh lệnh nhanh",
    panel_commands_sub: "Cấu hình danh sách các nút lệnh tắt trên thanh công cụ Terminal theo nhu cầu cá nhân.",
    card_commands_title: "Danh sách phím tắt lệnh",
    card_commands_desc: "Bấm vào nút lệnh trên thanh công cụ Terminal sẽ tự động gửi lệnh tương ứng vào phiên SSH.",
    btn_add_cmd: "Thêm lệnh",
    col_num: "#",
    col_label: "Tên hiển thị",
    col_cmd: "Lệnh thực thi",
    col_action: "Thao tác",
    placeholder_cmd_label: "Tên nút (vd: htop)",
    placeholder_cmd_val: "Lệnh thực thi (vd: htop)",
    btn_remove_cmd_title: "Xóa lệnh này",
    btn_reset_default_cmds: "Khôi phục mặc định",
    btn_save_cmds: "Lưu danh sách lệnh",
    empty_cmds_msg: "Chưa có lệnh nhanh nào. Bấm Thêm lệnh phía trên để tạo phím tắt mới.",

    // Passkey Banner
    passkey_banner_title: "Đăng nhập nhanh hơn với Passkey (Touch ID)",
    passkey_banner_desc: "Lưu vân tay của thiết bị này để lần sau chỉ cần chạm ngón tay là vào thẳng Lớp 1 trong 1 giây.",
    btn_banner_save: "Lưu Passkey ngay",
    btn_banner_dismiss: "Để sau",

    // Quick Connect Sidebar
    sidebar_quick_connect_title: "Kết nối nhanh",
    placeholder_quick_name: "Tên gợi nhớ...",
    placeholder_quick_host: "IP / Host máy chủ...",
    placeholder_quick_port: "Port",
    placeholder_quick_user: "Username (root)",
    placeholder_quick_pass: "Password...",
    btn_quick_save: "Lưu",
    btn_quick_connect: "Connect",
    btn_new_tab_title: "Mở tab SSH mới",

    // 2FA Setup
    totp_step_1: "Cài đặt ứng dụng Google Authenticator trên điện thoại.",
    totp_step_2: "Bấm nút thiết lập để nhận mã QR và quét bằng camera điện thoại.",
    totp_step_3: "Nhập mã 6 chữ số đang hiển thị trên ứng dụng để xác nhận kích hoạt.",
    totp_scan_qr_title: "Quét mã QR bằng Google Authenticator",
    totp_secret_label: "Khóa bí mật (nhập thủ công nếu không quét được mã QR):",
    btn_copy_secret: "Sao chép",
    btn_copied_secret: "Đã chép",
    label_enter_otp: "Nhập mã xác thực 6 số từ Google Authenticator:",
    btn_confirm_enable_2fa: "Xác nhận & bật 2FA",
    totp_active_headline: "Tài khoản đang được bảo vệ bởi Google Authenticator",
    totp_active_desc: "Mỗi lần đăng nhập vào WebConsole, hệ thống sẽ yêu cầu mã OTP 6 chữ số từ ứng dụng trên điện thoại của bạn.",
    title_show_password: "Hiện mật khẩu",
    title_hide_password: "Ẩn mật khẩu",

    // Toasts & Messages
    toast_save_cmds_success: "Đã lưu cấu hình danh sách lệnh nhanh thành công!",
    toast_reset_cmds_info: "Đã khôi phục danh sách 8 lệnh mặc định ban đầu.",
    toast_update_profile_success: "Đã cập nhật thông tin hồ sơ thành công!",
    toast_change_pass_success: "Đã đổi mật khẩu thành công!",
    toast_passkey_success: "Đã lưu Passkey thiết bị thành công! Lần sau bạn có thể chạm vân tay để đăng nhập nhanh.",
    toast_2fa_enabled_success: "Đã kích hoạt bảo mật 2 bước (Google Authenticator) thành công!",
    toast_2fa_disabled_success: "Đã tắt xác thực 2 bước thành công!",
    toast_copy_secret_success: "Đã sao chép khóa bí mật vào bộ nhớ tạm!",
    generating_secret: "Đang tạo khóa bảo mật...",
    btn_get_new_qr: "Lấy Mã QR Mới",
    connecting_biometrics: "Đang kết nối xác thực sinh trắc...",
    btn_processing: "Đang xử lý...",
    saving: "Đang lưu...",
    error_create_2fa: "Không thể tạo khóa 2FA",
    invalid_otp_code: "Vui lòng nhập đúng 6 chữ số từ ứng dụng Google Authenticator!"
  }
};

class I18nManager {
  constructor() {
    // MẶC ĐỊNH LÀ TIẾNG ANH THEO YÊU CẦU CỦA NGƯỜI DÙNG
    this.currentLang = localStorage.getItem('app_lang') || 'en';
  }

  getLanguage() {
    return this.currentLang;
  }

  setLanguage(lang) {
    if (lang !== 'en' && lang !== 'vi') {
      lang = 'en';
    }
    this.currentLang = lang;
    localStorage.setItem('app_lang', lang);
    this.applyTranslations();

    // Cập nhật trạng thái hiển thị của các nút chuyển đổi ngôn ngữ
    document.querySelectorAll('.lang-btn').forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-lang') === lang);
    });

    // Phát sự kiện để các file script khác (app.js, account.js) tự re-render nội dung động
    window.dispatchEvent(new CustomEvent('languageChanged', { detail: { lang } }));
  }

  t(key, fallback = '') {
    const dict = translations[this.currentLang] || translations.en;
    if (dict && dict[key] !== undefined) {
      return dict[key];
    }
    // Fallback sang tiếng Anh nếu thiếu
    if (translations.en && translations.en[key] !== undefined) {
      return translations.en[key];
    }
    return fallback || key;
  }

  applyTranslations() {
    // 1. Cập nhật thẻ title trang
    if (document.querySelector('meta[name="page-type"][content="account"]')) {
      document.title = this.t('account_page_title');
    } else {
      document.title = this.t('app_title');
    }

    // 2. data-i18n: Cập nhật textContent
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      const val = this.t(key);
      if (val) el.textContent = val;
    });

    // 3. data-i18n-html: Cập nhật innerHTML
    document.querySelectorAll('[data-i18n-html]').forEach(el => {
      const key = el.getAttribute('data-i18n-html');
      const val = this.t(key);
      if (val) el.innerHTML = val;
    });

    // 4. data-i18n-placeholder: Cập nhật placeholder
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
      const key = el.getAttribute('data-i18n-placeholder');
      const val = this.t(key);
      if (val) el.setAttribute('placeholder', val);
    });

    // 5. data-i18n-title: Cập nhật title
    document.querySelectorAll('[data-i18n-title]').forEach(el => {
      const key = el.getAttribute('data-i18n-title');
      const val = this.t(key);
      if (val) el.setAttribute('title', val);
    });
  }

  init() {
    // Áp dụng ngôn ngữ hiện tại
    this.applyTranslations();

    // Gán sự kiện click cho các nút ngôn ngữ
    document.querySelectorAll('.lang-btn').forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-lang') === this.currentLang);
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const targetLang = btn.getAttribute('data-lang');
        this.setLanguage(targetLang);
      });
    });
  }
}

// Khởi tạo đối tượng toàn cục
window.i18n = new I18nManager();

// Tự động khởi chạy khi DOM sẵn sàng
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => window.i18n.init());
} else {
  window.i18n.init();
}
