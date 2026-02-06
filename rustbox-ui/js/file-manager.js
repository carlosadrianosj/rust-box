/* ═══════════════════════════════════════════════════════════════════
   RustBox - File Manager
   Handles file listing, upload, download, and table rendering
   ═══════════════════════════════════════════════════════════════════ */

const FileManager = (() => {
    let _files = [];
    let _tableBody = null;
    let _emptyState = null;
    let _statsEl = null;
    let _isUploading = false;

    // ── Initialization ──────────────────────────────────────────────

    function init() {
        _tableBody = document.getElementById('file-table-body');
        _emptyState = document.getElementById('empty-state');
        _statsEl = document.getElementById('file-stats');
    }

    // ── Refresh File List ───────────────────────────────────────────

    /**
     * Fetch file list from backend and re-render the table.
     */
    async function refresh() {
        const result = await backend.listFiles();

        if (result.ok) {
            _files = result.files || [];
        } else {
            _files = [];
            Logs.add(`Failed to list files: ${result.error}`, 'error');
        }

        _render();
        _updateStats();
    }

    // ── Upload ──────────────────────────────────────────────────────

    /**
     * Upload a single file.
     * @param {File} file - File object from input or drop
     */
    async function uploadFile(file) {
        if (_isUploading) {
            Toast.show('Upload already in progress', 'info');
            return;
        }

        const maxSize = 500 * 1024 * 1024; // 500 MB
        if (file.size > maxSize) {
            Toast.show(`File too large: ${formatBytes(file.size)} (max 500 MB)`, 'error');
            return;
        }

        _isUploading = true;
        const toastId = Toast.showProgress(
            `Encrypting & uploading ${file.name}...`,
            `upload-${file.name}`
        );

        Logs.add(`Upload started: ${file.name} (${formatBytes(file.size)})`, 'info');

        try {
            // Read file as ArrayBuffer
            const buffer = await file.arrayBuffer();
            const bytes = new Uint8Array(buffer);

            const server = Auth.getServer();

            const result = await backend.uploadFile(bytes, file.name, server, (progress) => {
                if (progress.message) {
                    Logs.add(progress.message, 'info');
                }
                if (progress.total > 0) {
                    const pct = Math.round((progress.progress / progress.total) * 100);
                    Toast.setProgress(toastId, pct);
                    Toast.update(toastId, progress.message || `Uploading ${file.name}... ${pct}%`);
                } else if (progress.message) {
                    Toast.update(toastId, progress.message);
                }
            });

            if (result.ok) {
                Toast.update(toastId, `${file.name} uploaded successfully`, 'success', 3000);
                Logs.add(`Upload complete: ${file.name}`, 'success');
                await refresh();
            } else {
                Toast.update(toastId, `Upload failed: ${result.error}`, 'error', 5000);
                Logs.add(`Upload failed: ${file.name} - ${result.error}`, 'error');
            }
        } catch (e) {
            Toast.update(toastId, `Upload error: ${e}`, 'error', 5000);
            Logs.add(`Upload error: ${file.name} - ${e}`, 'error');
        } finally {
            _isUploading = false;
        }
    }

    /**
     * Upload multiple files sequentially.
     * @param {FileList|File[]} files
     */
    async function uploadFiles(files) {
        for (const file of files) {
            await uploadFile(file);
        }
    }

    // ── Download ────────────────────────────────────────────────────

    /**
     * Download and decrypt a file.
     * @param {{ manifest_id: string, filename: string, size: number }} entry
     */
    async function downloadFile(entry) {
        const toastId = Toast.showProgress(
            `Downloading ${entry.filename}...`,
            `download-${entry.manifest_id}`
        );

        Logs.add(`Download started: ${entry.filename}`, 'info');

        try {
            const server = Auth.getServer();

            const result = await backend.downloadFile(entry.manifest_id, server, (progress) => {
                if (progress.message) {
                    Logs.add(progress.message, 'info');
                }
                if (progress.total > 0) {
                    const pct = Math.round((progress.progress / progress.total) * 100);
                    Toast.setProgress(toastId, pct);
                    Toast.update(toastId, progress.message || `Downloading ${entry.filename}... ${pct}%`);
                } else if (progress.message) {
                    Toast.update(toastId, progress.message);
                }
            });

            if (result.ok && result.bytes) {
                // Create download via Blob URL with correct MIME type
                const mimeType = result.mimeType || _guessMimeType(result.filename || entry.filename);
                const blobOpts = mimeType ? { type: mimeType } : {};
                const blob = new Blob([result.bytes], blobOpts);
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = result.filename || entry.filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);

                // Revoke after a short delay
                setTimeout(() => URL.revokeObjectURL(url), 5000);

                Toast.update(toastId, `${entry.filename} downloaded`, 'success', 3000);
                Logs.add(`Download complete: ${entry.filename}`, 'success');
            } else {
                Toast.update(toastId, `Download failed: ${result.error}`, 'error', 5000);
                Logs.add(`Download failed: ${entry.filename} - ${result.error}`, 'error');
            }
        } catch (e) {
            Toast.update(toastId, `Download error: ${e}`, 'error', 5000);
            Logs.add(`Download error: ${entry.filename} - ${e}`, 'error');
        }
    }

    // ── Rendering ───────────────────────────────────────────────────

    function _render() {
        if (!_tableBody) return;

        _tableBody.innerHTML = '';

        if (_files.length === 0) {
            _emptyState.classList.remove('hidden');
            return;
        }

        _emptyState.classList.add('hidden');

        // Sort by date descending (newest first)
        const sorted = [..._files].sort((a, b) =>
            (b.created_at || 0) - (a.created_at || 0)
        );

        for (const file of sorted) {
            const row = _createRow(file);
            _tableBody.appendChild(row);
        }
    }

    function _createRow(file) {
        const tr = document.createElement('tr');
        const icon = getFileIcon(file.filename);

        // Icon cell
        const tdIcon = document.createElement('td');
        tdIcon.className = 'col-icon';
        const iconSpan = document.createElement('span');
        iconSpan.className = icon.class;
        iconSpan.innerHTML = icon.svg;
        iconSpan.title = icon.label;
        tdIcon.appendChild(iconSpan);

        // Name cell
        const tdName = document.createElement('td');
        tdName.className = 'col-name';
        const nameSpan = document.createElement('span');
        nameSpan.className = 'file-name';
        nameSpan.textContent = file.filename || 'unknown';
        nameSpan.title = file.filename || '';
        tdName.appendChild(nameSpan);

        // Size cell
        const tdSize = document.createElement('td');
        tdSize.className = 'col-size file-size';
        tdSize.textContent = formatBytes(file.size || 0);

        // Date cell
        const tdDate = document.createElement('td');
        tdDate.className = 'col-date file-date';
        tdDate.textContent = formatDate(file.created_at);

        // Chunks cell
        const tdChunks = document.createElement('td');
        tdChunks.className = 'col-chunks file-chunks';
        tdChunks.textContent = file.chunk_count != null ? file.chunk_count : '--';

        // Actions cell
        const tdActions = document.createElement('td');
        tdActions.className = 'col-actions';
        const dlBtn = document.createElement('button');
        dlBtn.className = 'btn-download';
        dlBtn.innerHTML = `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
            <polyline points="7 10 12 15 17 10"/>
            <line x1="12" y1="15" x2="12" y2="3"/>
        </svg>Download`;
        dlBtn.addEventListener('click', () => downloadFile(file));
        tdActions.appendChild(dlBtn);

        const delBtn = document.createElement('button');
        delBtn.className = 'btn-delete';
        delBtn.innerHTML = `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="3 6 5 6 21 6"/>
            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
        </svg>`;
        delBtn.title = 'Delete';
        delBtn.addEventListener('click', () => deleteFileEntry(file));
        tdActions.appendChild(delBtn);

        tr.appendChild(tdIcon);
        tr.appendChild(tdName);
        tr.appendChild(tdSize);
        tr.appendChild(tdDate);
        tr.appendChild(tdChunks);
        tr.appendChild(tdActions);

        return tr;
    }

    function _updateStats() {
        if (!_statsEl) return;

        const count = _files.length;
        const totalSize = _files.reduce((sum, f) => sum + (f.size || 0), 0);

        _statsEl.textContent = `${count} file${count !== 1 ? 's' : ''} \u00B7 ${formatBytes(totalSize)}`;
    }

    // ── Helpers ───────────────────────────────────────────────────

    function _guessMimeType(filename) {
        if (!filename) return null;
        const ext = filename.split('.').pop().toLowerCase();
        const map = {
            png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg',
            gif: 'image/gif', webp: 'image/webp', svg: 'image/svg+xml',
            pdf: 'application/pdf', zip: 'application/zip',
            gz: 'application/gzip', tar: 'application/x-tar',
            mp3: 'audio/mpeg', wav: 'audio/wav', mp4: 'video/mp4',
            webm: 'video/webm', json: 'application/json',
            txt: 'text/plain', html: 'text/html', css: 'text/css',
            js: 'text/javascript', xml: 'text/xml', csv: 'text/csv',
            doc: 'application/msword', xls: 'application/vnd.ms-excel',
            ppt: 'application/vnd.ms-powerpoint',
        };
        return map[ext] || null;
    }

    // ── Delete ────────────────────────────────────────────────────

    let _isDeleting = false;

    /**
     * Delete a file from the server.
     * @param {{ manifest_id: string, filename: string }} entry
     */
    async function deleteFileEntry(entry) {
        if (_isDeleting) return;

        if (!confirm(`Delete "${entry.filename}"? This cannot be undone.`)) {
            return;
        }

        _isDeleting = true;
        Logs.add(`Deleting ${entry.filename}...`, 'info');

        try {
            const server = Auth.getServer();
            const result = await backend.deleteFile(entry.manifest_id, server);

            if (result.ok) {
                Logs.add(`Deleted: ${entry.filename}`, 'success');
                Toast.show(`${entry.filename} deleted`, 'success', 2000);
                // Trigger auto-sync for immediate refresh
                if (typeof AutoSync !== 'undefined') {
                    AutoSync.trigger();
                } else {
                    await refresh();
                }
            } else {
                Logs.add(`Delete failed: ${result.error}`, 'error');
                Toast.show(`Delete failed: ${result.error}`, 'error', 4000);
            }
        } catch (e) {
            Logs.add(`Delete error: ${e}`, 'error');
            Toast.show(`Delete error: ${e}`, 'error', 4000);
        } finally {
            _isDeleting = false;
        }
    }

    /**
     * Set files from auto-sync (external update).
     * @param {Array} files
     */
    function _setFiles(files) {
        _files = files || [];
        _render();
        _updateStats();
    }

    // ── Clear (for logout) ─────────────────────────────────────────

    /**
     * Clear all displayed files and reset stats.
     * Used on logout so a different user never sees stale data.
     */
    function clear() {
        _files = [];
        _render();
        _updateStats();
    }

    // ── Public API ──────────────────────────────────────────────────

    return {
        init,
        refresh,
        uploadFile,
        uploadFiles,
        downloadFile,
        deleteFileEntry,
        clear,
        _setFiles,
    };
})();
