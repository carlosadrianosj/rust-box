/* ═══════════════════════════════════════════════════════════════════
   RustBox - Main Application Controller
   Wires up screens, events, drag-drop, and navigation
   ═══════════════════════════════════════════════════════════════════ */

// ── Logs Panel (simple helper, used across modules) ─────────────────

const Logs = (() => {
    let _entriesEl = null;

    function _getEl() {
        if (!_entriesEl) {
            _entriesEl = document.getElementById('logs-entries');
        }
        return _entriesEl;
    }

    /**
     * Add a log entry.
     * @param {string} message
     * @param {'info'|'error'|'success'} [type='info']
     */
    function add(message, type = 'info') {
        const el = _getEl();
        if (!el) return;

        const entry = document.createElement('div');
        entry.className = `log-entry log-${type}`;

        const now = new Date();
        const time = [
            String(now.getHours()).padStart(2, '0'),
            String(now.getMinutes()).padStart(2, '0'),
            String(now.getSeconds()).padStart(2, '0'),
        ].join(':');

        entry.innerHTML =
            `<span class="log-time">${time}</span>` +
            `<span class="log-msg">${_escapeHtml(message)}</span>`;

        el.appendChild(entry);

        // Auto-scroll to bottom
        el.scrollTop = el.scrollHeight;

        // Also log to console for debugging
        const prefix = type === 'error' ? '[ERR]' : type === 'success' ? '[OK]' : '[LOG]';
        console.log(`${prefix} ${message}`);
    }

    function _escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    return { add };
})();


// ── App Controller ──────────────────────────────────────────────────

const App = (() => {
    // ── DOM refs ────────────────────────────────────────────────────
    let screenLogin = null;
    let screenFiles = null;
    let formLogin = null;
    let inputServer = null;
    let inputLogin = null;
    let inputPassword = null;
    let btnLogin = null;
    let btnUpload = null;
    let fileInput = null;
    let btnSync = null;
    let btnLogout = null;
    let dropzoneOverlay = null;
    let logsPanel = null;
    let logsToggle = null;

    let _dragCounter = 0;

    // ── Initialization ──────────────────────────────────────────────

    async function init() {
        _cacheDom();
        _bindEvents();

        // Detect runtime environment
        const mode = backend.detect();
        Logs.add(`RustBox UI initialized (${mode} mode)`);

        // Set server address automatically (hidden from user)
        inputServer.value = backend.getServer();

        // Initialize FileManager and Database
        FileManager.init();
        if (typeof Database !== 'undefined') Database.init();

        // Tab switching
        _initTabs();

        // Check if vault is already unlocked (e.g., after page refresh)
        const alreadyUnlocked = await Auth.checkStatus();
        if (alreadyUnlocked) {
            const user = Auth.getUsername();
            Logs.add(`Vault already unlocked, resuming session${user ? ` as '${user}'` : ''}`);
            if (user) Toast.show(`Session resumed as ${user}`, 'success');
            await _showFileManager();
        } else {
            _showLogin();
        }
    }

    // ── DOM Cache ───────────────────────────────────────────────────

    function _cacheDom() {
        screenLogin     = document.getElementById('screen-login');
        screenFiles     = document.getElementById('screen-files');
        formLogin       = document.getElementById('form-login');
        inputServer     = document.getElementById('input-server');
        inputLogin      = document.getElementById('input-login');
        inputPassword   = document.getElementById('input-password');
        btnLogin        = document.getElementById('btn-login');
        btnUpload       = document.getElementById('btn-upload');
        fileInput       = document.getElementById('file-input');
        btnSync         = document.getElementById('btn-sync');
        btnLogout       = document.getElementById('btn-logout');
        dropzoneOverlay = document.getElementById('dropzone-overlay');
        logsPanel       = document.getElementById('logs-panel');
        logsToggle      = document.getElementById('logs-toggle');
    }

    // ── Event Binding ───────────────────────────────────────────────

    function _bindEvents() {
        // Login form
        formLogin.addEventListener('submit', _handleLogin);

        // Upload button + hidden file input
        btnUpload.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', _handleFileSelect);

        // Sync button
        btnSync.addEventListener('click', _handleSync);

        // Logout button
        btnLogout.addEventListener('click', _handleLogout);

        // Logs panel toggle
        logsToggle.addEventListener('click', _toggleLogs);

        // Drag & Drop on the file manager screen
        screenFiles.addEventListener('dragenter', _handleDragEnter);
        screenFiles.addEventListener('dragover', _handleDragOver);
        screenFiles.addEventListener('dragleave', _handleDragLeave);
        screenFiles.addEventListener('drop', _handleDrop);

        // Keyboard shortcuts
        document.addEventListener('keydown', _handleKeyboard);
    }

    // ── Screen Navigation ───────────────────────────────────────────

    function _showLogin() {
        screenFiles.classList.remove('screen-active');
        screenLogin.classList.add('screen-active', 'screen-fade-in');
        screenLogin.addEventListener('animationend', () => {
            screenLogin.classList.remove('screen-fade-in');
        }, { once: true });

        // Focus login field
        setTimeout(() => inputLogin.focus(), 100);
    }

    async function _showFileManager() {
        screenLogin.classList.remove('screen-active');
        screenFiles.classList.add('screen-active', 'screen-fade-in');
        screenFiles.addEventListener('animationend', () => {
            screenFiles.classList.remove('screen-fade-in');
        }, { once: true });

        // Load files and start auto-sync
        await FileManager.refresh();
        if (typeof AutoSync !== 'undefined') {
            AutoSync.start();
        }
    }

    // ── Login Handler ───────────────────────────────────────────────

    async function _handleLogin(e) {
        e.preventDefault();

        const server = inputServer.value;
        const login = inputLogin.value.trim();
        const password = inputPassword.value;

        // Clear previous errors
        inputLogin.classList.remove('input-error');
        inputPassword.classList.remove('input-error');

        if (!login) {
            Toast.show('Login is required', 'error');
            inputLogin.classList.add('input-error');
            inputLogin.focus();
            return;
        }

        if (!password) {
            Toast.show('Password is required', 'error');
            inputPassword.classList.add('input-error');
            inputPassword.focus();
            return;
        }

        // Disable button, show spinner
        _setLoginLoading(true);

        const result = await Auth.login(server, login, password);

        if (result.ok) {
            Toast.show('Signed in successfully', 'success');
            inputPassword.value = ''; // Clear password from DOM
            await _showFileManager();
        } else {
            Toast.show(result.error || 'Login failed', 'error');
            inputPassword.classList.add('input-error');
            inputPassword.focus();
            inputPassword.select();
        }

        _setLoginLoading(false);
    }

    function _setLoginLoading(loading) {
        btnLogin.disabled = loading;
        const text = btnLogin.querySelector('.btn-text');
        const spinner = btnLogin.querySelector('.btn-spinner');

        if (loading) {
            text.textContent = 'Signing in...';
            spinner.classList.remove('hidden');
        } else {
            text.textContent = 'Sign In';
            spinner.classList.add('hidden');
        }
    }

    // ── File Select Handler ─────────────────────────────────────────

    async function _handleFileSelect(e) {
        const files = e.target.files;
        if (!files || files.length === 0) return;

        await FileManager.uploadFiles(files);

        // Reset input so the same file can be selected again
        fileInput.value = '';
    }

    // ── Sync Handler ────────────────────────────────────────────────

    async function _handleSync() {
        if (btnSync.classList.contains('syncing')) return;

        btnSync.classList.add('syncing');
        const toastId = Toast.showProgress('Syncing with server...', 'sync');

        Logs.add('Sync started', 'info');

        try {
            const server = Auth.getServer();
            const result = await backend.syncFiles(server, (progress) => {
                if (progress.message) {
                    Toast.update(toastId, progress.message);
                }
            });

            if (result.ok) {
                const downloaded = result.downloaded || 0;
                const uploaded = result.uploaded || 0;
                const msg = `Sync complete: ${downloaded} downloaded, ${uploaded} uploaded`;
                Toast.update(toastId, msg, 'success', 3000);
                Logs.add(msg, 'success');
                await FileManager.refresh();
            } else {
                Toast.update(toastId, `Sync failed: ${result.error}`, 'error', 5000);
                Logs.add(`Sync failed: ${result.error}`, 'error');
            }
        } catch (e) {
            Toast.update(toastId, `Sync error: ${e}`, 'error', 5000);
            Logs.add(`Sync error: ${e}`, 'error');
        } finally {
            btnSync.classList.remove('syncing');
        }
    }

    // ── Logout Handler ─────────────────────────────────────────────

    async function _handleLogout() {
        if (typeof AutoSync !== 'undefined') {
            AutoSync.stop();
        }
        await Auth.logout();
        FileManager.clear();
        Toast.show('Logged out', 'info');
        Toast.dismissAll();
        _showLogin();
    }

    // ── Drag & Drop ─────────────────────────────────────────────────

    function _handleDragEnter(e) {
        e.preventDefault();
        e.stopPropagation();
        _dragCounter++;

        if (_dragCounter === 1) {
            dropzoneOverlay.classList.remove('hidden');
        }
    }

    function _handleDragOver(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    function _handleDragLeave(e) {
        e.preventDefault();
        e.stopPropagation();
        _dragCounter--;

        if (_dragCounter <= 0) {
            _dragCounter = 0;
            dropzoneOverlay.classList.add('hidden');
        }
    }

    async function _handleDrop(e) {
        e.preventDefault();
        e.stopPropagation();
        _dragCounter = 0;
        dropzoneOverlay.classList.add('hidden');

        const files = e.dataTransfer?.files;
        if (!files || files.length === 0) return;

        Logs.add(`Dropped ${files.length} file(s)`, 'info');
        await FileManager.uploadFiles(files);
    }

    // ── Logs Panel Toggle ───────────────────────────────────────────

    function _toggleLogs() {
        if (logsPanel.classList.contains('collapsed')) {
            logsPanel.classList.remove('collapsed');
            logsPanel.classList.add('expanded');
        } else {
            logsPanel.classList.remove('expanded');
            logsPanel.classList.add('collapsed');
        }
    }

    // ── Tab Switching ─────────────────────────────────────────────

    function _initTabs() {
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const tabName = btn.dataset.tab;
                _switchTab(tabName);
            });
        });
    }

    function _switchTab(tabName) {
        // Update tab buttons
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.toggle('tab-active', btn.dataset.tab === tabName);
        });

        // Update tab content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.toggle('tab-visible', content.id === `tab-${tabName}`);
        });

        // Refresh database when switching to it
        if (tabName === 'database' && typeof Database !== 'undefined') {
            Database.refresh();
        }
    }

    // ── Keyboard Shortcuts ──────────────────────────────────────────

    function _handleKeyboard(e) {
        // Cmd/Ctrl+U => Upload
        if ((e.metaKey || e.ctrlKey) && e.key === 'u') {
            e.preventDefault();
            if (Auth.isLoggedIn()) {
                fileInput.click();
            }
        }

        // Cmd/Ctrl+Shift+S => Sync
        if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key === 'S') {
            e.preventDefault();
            if (Auth.isLoggedIn()) {
                _handleSync();
            }
        }

        // Cmd/Ctrl+L => Logout
        if ((e.metaKey || e.ctrlKey) && e.key === 'l') {
            e.preventDefault();
            if (Auth.isLoggedIn()) {
                _handleLogout();
            }
        }

        // Escape => close dropzone if open
        if (e.key === 'Escape') {
            _dragCounter = 0;
            dropzoneOverlay.classList.add('hidden');
        }
    }

    return { init };
})();


// ── Boot ────────────────────────────────────────────────────────────

// In standalone mode (index.html), boot on DOMContentLoaded.
// In WASM mode (serve.html), boot on 'rustbox-ready' event after WASM init.
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        // Only auto-init if NOT loaded by serve.html (which fires rustbox-ready)
        if (!window.__RUSTBOX_WASM_BOOT__) {
            App.init();
        }
    });
}

window.addEventListener('rustbox-ready', () => {
    App.init();
});
