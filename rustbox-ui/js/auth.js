/* ═══════════════════════════════════════════════════════════════════
   RustBox - Authentication Controller
   Handles login, vault unlock, and session state
   ═══════════════════════════════════════════════════════════════════ */

const Auth = (() => {
    let _isLoggedIn = false;
    let _server = null;

    /**
     * Attempt login: fetch salt, unlock vault, and connect to server.
     * @param {string} server - Server address (host:port)
     * @param {string} username - Username for cross-client identity
     * @param {string} password - Vault password
     * @returns {Promise<{ ok: boolean, error?: string }>}
     */
    async function login(server, username, password) {
        if (!username || !username.trim()) {
            return { ok: false, error: 'Username is required' };
        }
        if (!password || !password.trim()) {
            return { ok: false, error: 'Password is required' };
        }

        const trimmedServer = server || backend.getServer();

        Logs.add(`Connecting to ${trimmedServer} as '${username}'...`, 'info');

        // For WASM: login() handles salt fetch + vault init + register in one call
        // For Tauri: login() handles salt fetch + vault init + register via QUIC
        const loginResult = await backend.login(trimmedServer, username, password);
        if (!loginResult.ok) {
            Logs.add(`Login failed: ${loginResult.error}`, 'error');
            return {
                ok: false,
                error: loginResult.error || 'Failed to connect to server',
            };
        }

        // Success
        _isLoggedIn = true;
        _server = trimmedServer;
        backend.saveServer(trimmedServer);

        // Persist session so F5 refresh doesn't require re-login
        localStorage.setItem('rustbox_username', username);
        localStorage.setItem('rustbox_session', 'true');

        Logs.add(`Connected to ${trimmedServer} as '${username}'`, 'success');
        return { ok: true };
    }

    /**
     * Logout: lock the vault and clear session.
     * @returns {Promise<{ ok: boolean }>}
     */
    async function logout() {
        const result = await backend.lockVault();
        _isLoggedIn = false;

        // Clear persisted session so F5 stays on login
        localStorage.removeItem('rustbox_session');
        localStorage.removeItem('rustbox_username');

        Logs.add('Logged out', 'info');
        return result;
    }

    /**
     * Check if user is currently logged in.
     * @returns {boolean}
     */
    function isLoggedIn() {
        return _isLoggedIn;
    }

    /**
     * Get the current server address.
     * @returns {string|null}
     */
    function getServer() {
        return _server || backend.getServer();
    }

    /**
     * Check vault status on startup (was it previously unlocked?).
     * @returns {Promise<boolean>} true if vault is already unlocked
     */
    async function checkStatus() {
        const status = await backend.getStatus();
        if (status.ok && status.vault_unlocked) {
            _isLoggedIn = true;
            _server = backend.getServer();
            return true;
        }
        // Vault not unlocked -- clear any stale session flag
        localStorage.removeItem('rustbox_session');
        return false;
    }

    // ── Helpers ─────────────────────────────────────────────────────

    function _isValidAddress(addr) {
        // Accept http(s)://host:port or host:port formats
        if (addr.startsWith('http://') || addr.startsWith('https://')) {
            try {
                const url = new URL(addr);
                return url.hostname.length > 0;
            } catch {
                return false;
            }
        }

        // Accept host:port or IP:port format
        const parts = addr.split(':');
        if (parts.length !== 2) return false;

        const port = parseInt(parts[1], 10);
        if (isNaN(port) || port < 1 || port > 65535) return false;

        const host = parts[0];
        if (!host || host.length === 0) return false;

        return true;
    }

    /**
     * Get the current username (from localStorage).
     * @returns {string|null}
     */
    function getUsername() {
        return localStorage.getItem('rustbox_username');
    }

    return {
        login,
        logout,
        isLoggedIn,
        getServer,
        getUsername,
        checkStatus,
    };
})();
