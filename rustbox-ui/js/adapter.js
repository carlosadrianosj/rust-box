/* ═══════════════════════════════════════════════════════════════════
   RustBox - WASM Backend Adapter
   Unified API for the WebAssembly backend
   ═══════════════════════════════════════════════════════════════════ */

const backend = (() => {
    let _wasm = null;
    let _mode = 'wasm';

    // ── Environment Detection ───────────────────────────────────────

    /**
     * Detect the runtime environment.
     * @returns {'wasm'}
     */
    function detect() {
        return _mode;
    }

    /**
     * Initialize the WASM module.
     * @param {object} wasmModule - The initialized wasm-bindgen module
     */
    async function init(wasmModule) {
        if (wasmModule) {
            _wasm = wasmModule;
            _log('WASM module initialized');
        }
    }

    // ── Logging ─────────────────────────────────────────────────────

    function _log(msg) {
        if (typeof Logs !== 'undefined' && Logs.add) {
            Logs.add(msg, 'info');
        }
    }

    function _logError(msg) {
        if (typeof Logs !== 'undefined' && Logs.add) {
            Logs.add(msg, 'error');
        }
    }

    // ── Progress Message Helper ─────────────────────────────────────

    /**
     * Generate a human-readable progress message from WASM step/current/total.
     * @param {string} step - Step name from WASM (encrypting, splitting, uploading, manifest, downloading, complete)
     * @param {number} current - Current index
     * @param {number} total - Total count
     * @param {string} [filename] - Optional filename for context
     * @returns {string}
     */
    function _progressMessage(step, current, total, filename) {
        switch (step) {
            case 'encrypting':
                return `Deriving file encryption key (HKDF-SHA256)...`;
            case 'splitting':
                return `Encrypting chunk ${current}/${total} with XChaCha20-Poly1305...`;
            case 'uploading':
                return `Uploading encrypted chunk ${current}/${total}...`;
            case 'manifest':
                return `Encrypting and uploading manifest...`;
            case 'downloading':
                return `Downloading & decrypting chunk ${current}/${total}...`;
            case 'complete':
                return filename ? `Transfer complete: ${filename}` : `Transfer complete`;
            default:
                return `${step} ${current}/${total}`;
        }
    }

    // ── Unified API ─────────────────────────────────────────────────

    /**
     * Initialize/unlock the vault with a username, password, and optional salt.
     * @param {string} username
     * @param {string} password
     * @param {string} [saltHex=''] - Hex-encoded salt from server (empty for new user)
     * @returns {Promise<{ ok: boolean, new_salt?: boolean, salt_hex?: string, error?: string }>}
     */
    async function initVault(username, password, saltHex = '') {
        try {
            if (!_wasm) {
                return { ok: false, error: 'WASM module not loaded' };
            }
            try {
                const result = await _wasm.init_vault(username, password, saltHex);
                return { ok: true, ...(result || {}) };
            } catch (e) {
                const msg = String(e);
                if (msg.includes('wrong password') || msg.includes('decryption failed')) {
                    _log('Different credentials detected, resetting local vault...');
                    await new Promise((resolve, reject) => {
                        const req = indexedDB.deleteDatabase('rustbox');
                        req.onsuccess = () => resolve();
                        req.onerror = () => reject(req.error);
                    });
                    const result = await _wasm.init_vault(username, password, saltHex);
                    return { ok: true, ...(result || {}) };
                }
                throw e;
            }
        } catch (e) {
            _logError(`initVault failed: ${e}`);
            return { ok: false, error: String(e) };
        }
    }

    /**
     * Login to server and unlock vault.
     * @param {string} server - Server address (host:port)
     * @param {string} username - Username for cross-client identity
     * @param {string} password - Vault password
     * @returns {Promise<{ ok: boolean, error?: string }>}
     */
    async function login(server, username, password) {
        try {
            if (!_wasm) {
                return { ok: false, error: 'WASM module not loaded' };
            }
            const result = await _wasm.login(username, password, server);
            return { ok: true, ...(result || {}) };
        } catch (e) {
            _logError(`Login failed: ${e}`);
            return { ok: false, error: String(e) };
        }
    }

    /**
     * Upload a file (encrypt and send).
     * @param {Uint8Array} bytes - Raw file bytes
     * @param {string} filename - Original filename
     * @param {string} server - Server address
     * @param {function} [onProgress] - Progress callback: ({ progress, total, message }) => void
     * @returns {Promise<{ ok: boolean, manifest_id?: string, error?: string }>}
     */
    async function uploadFile(bytes, filename, server, onProgress) {
        try {
            let result;
            if (onProgress) {
                const wrappedProgress = (step, current, total) => {
                    const message = _progressMessage(step, current, total, filename);
                    onProgress({ progress: current, total, step, message });
                };
                result = await _wasm.upload_file_with_progress(
                    bytes, filename, server, wrappedProgress
                );
            } else {
                result = await _wasm.upload_file(bytes, filename, server);
            }
            return { ok: true, ...(result || {}) };
        } catch (e) {
            _logError(`Upload failed: ${e}`);
            return { ok: false, error: String(e) };
        }
    }

    /**
     * Download a file (fetch and decrypt).
     * @param {string} manifestId - Manifest ID
     * @param {string} server - Server address
     * @param {function} [onProgress] - Progress callback
     * @returns {Promise<{ ok: boolean, bytes?: Uint8Array, filename?: string, error?: string }>}
     */
    async function downloadFile(manifestId, server, onProgress) {
        if (!manifestId) {
            _logError('downloadFile called with empty manifestId');
            return { ok: false, error: 'No manifest ID' };
        }
        try {
            let result;
            if (onProgress) {
                const wrappedProgress = (step, current, total) => {
                    const message = _progressMessage(step, current, total);
                    onProgress({ progress: current, total, step, message });
                };
                result = await _wasm.download_file_with_progress(
                    manifestId, server, wrappedProgress
                );
            } else {
                result = await _wasm.download_file(manifestId, server);
            }
            return {
                ok: true,
                bytes: result.bytes,
                filename: result.filename,
                mimeType: result.mime_type || null,
            };
        } catch (e) {
            _logError(`Download failed: ${e}`);
            return { ok: false, error: String(e) };
        }
    }

    /**
     * Sync local file index with server.
     * @param {string} server - Server address
     * @param {function} [onProgress] - Progress callback
     * @returns {Promise<{ ok: boolean, added?: number, updated?: number, error?: string }>}
     */
    async function syncFiles(server, onProgress) {
        try {
            const result = await _wasm.sync_files(server);
            return { ok: true, ...(result || {}) };
        } catch (e) {
            _logError(`Sync failed: ${e}`);
            return { ok: false, error: String(e) };
        }
    }

    /**
     * Get vault status (locked/unlocked, file count, etc.).
     * @returns {Promise<{ ok: boolean, unlocked?: boolean, fileCount?: number, error?: string }>}
     */
    async function getStatus() {
        try {
            const result = await _wasm.get_status();
            return { ok: true, ...(result || {}) };
        } catch (e) {
            return { ok: false, error: String(e) };
        }
    }

    /**
     * List all files in the vault.
     * @returns {Promise<{ ok: boolean, files?: Array, error?: string }>}
     * Each file: { manifest_id, filename, size, created_at, chunk_count }
     */
    async function listFiles() {
        try {
            const files = await _wasm.list_files();
            return { ok: true, files: files || [] };
        } catch (e) {
            _logError(`listFiles failed: ${e}`);
            return { ok: false, files: [], error: String(e) };
        }
    }

    /**
     * Lock the vault (clear keys from memory).
     * @returns {Promise<{ ok: boolean, error?: string }>}
     */
    async function lockVault() {
        try {
            await _wasm.lock_vault();
            return { ok: true };
        } catch (e) {
            _logError(`lockVault failed: ${e}`);
            return { ok: false, error: String(e) };
        }
    }

    /**
     * Get the saved server address (if any).
     * @returns {string|null}
     */
    function getSavedServer() {
        try {
            return localStorage.getItem('rustbox_server') || null;
        } catch {
            return null;
        }
    }

    /**
     * Save the server address for next session.
     * @param {string} server
     */
    function saveServer(server) {
        try {
            localStorage.setItem('rustbox_server', server);
        } catch { /* ignore */ }
    }

    /**
     * Get the current server address.
     * @returns {string}
     */
    function getServer() {
        if (getSavedServer()) return getSavedServer();
        return 'http://localhost:8443';
    }

    /**
     * List manifests from the server (with decrypted metadata).
     * @param {string} server
     * @returns {Promise<{ ok: boolean, files?: Array, error?: string }>}
     */
    async function listServerManifests(server) {
        try {
            if (!_wasm) return { ok: false, error: 'WASM not loaded' };
            const files = await _wasm.list_server_manifests(server);
            return { ok: true, files: files || [] };
        } catch (e) {
            _logError(`listServerManifests failed: ${e}`);
            return { ok: false, files: [], error: String(e) };
        }
    }

    /**
     * Delete a file from the server by manifest ID.
     * @param {string} manifestId
     * @param {string} server
     * @returns {Promise<{ ok: boolean, error?: string }>}
     */
    async function deleteFile(manifestId, server) {
        try {
            if (!_wasm) return { ok: false, error: 'WASM not loaded' };
            await _wasm.delete_file(manifestId, server);
            return { ok: true };
        } catch (e) {
            _logError(`deleteFile failed: ${e}`);
            return { ok: false, error: String(e) };
        }
    }

    /**
     * Get database overview from the server.
     * @param {string} server
     * @returns {Promise<{ ok: boolean, data?: object, error?: string }>}
     */
    async function getDbOverview(server) {
        try {
            if (!_wasm) return { ok: false, error: 'WASM not loaded' };
            const result = await _wasm.get_db_overview(server);
            return { ok: true, data: result };
        } catch (e) {
            _logError(`getDbOverview failed: ${e}`);
            return { ok: false, error: String(e) };
        }
    }

    const api = {
        detect,
        init,
        initVault,
        login,
        uploadFile,
        downloadFile,
        syncFiles,
        getStatus,
        listFiles,
        lockVault,
        listServerManifests,
        deleteFile,
        getDbOverview,
        getSavedServer,
        saveServer,
        getServer,
    };

    // Expose globally so module scripts (serve.html) can access it
    if (typeof window !== 'undefined') window.backend = api;

    return api;
})();
