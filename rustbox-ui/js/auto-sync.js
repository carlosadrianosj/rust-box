/* ═══════════════════════════════════════════════════════════════════
   RustBox - Auto Sync
   Periodically refreshes the manifest list from the server.
   ═══════════════════════════════════════════════════════════════════ */

const AutoSync = (() => {
    let _interval = null;
    let _syncing = false;
    const SYNC_INTERVAL_MS = 4000;

    /**
     * Start auto-sync. Runs an immediate cycle, then repeats every 4 seconds.
     */
    function start() {
        if (_interval) return;
        _doSyncCycle();
        _interval = setInterval(_doSyncCycle, SYNC_INTERVAL_MS);
        _setStatus('synced');
    }

    /**
     * Stop auto-sync.
     */
    function stop() {
        if (_interval) {
            clearInterval(_interval);
            _interval = null;
        }
        _setStatus('idle');
    }

    /**
     * Trigger an immediate sync cycle (e.g. after upload/delete).
     */
    function trigger() {
        _doSyncCycle();
    }

    async function _doSyncCycle() {
        if (_syncing) return;
        _syncing = true;
        _setStatus('checking');

        try {
            const server = Auth.getServer();
            if (!server) {
                _syncing = false;
                _setStatus('idle');
                return;
            }

            const result = await backend.listServerManifests(server);

            if (result.ok) {
                const serverFiles = result.files || [];

                // Compare with current file manager list
                if (typeof FileManager !== 'undefined' && FileManager._setFiles) {
                    FileManager._setFiles(serverFiles);
                }
                _setStatus('synced');
            } else {
                _setStatus('error');
            }
        } catch (e) {
            if (typeof Logs !== 'undefined') {
                Logs.add(`Auto-sync error: ${e}`, 'error');
            }
            _setStatus('error');
        } finally {
            _syncing = false;
        }
    }

    function _setStatus(status) {
        const el = document.getElementById('sync-status');
        if (!el) return;
        el.className = 'sync-indicator sync-' + status;
        const labels = {
            idle: 'Sync idle',
            checking: 'Syncing...',
            synced: 'Synced',
            error: 'Sync error',
        };
        el.textContent = labels[status] || status;
        el.title = labels[status] || status;
    }

    return { start, stop, trigger };
})();
