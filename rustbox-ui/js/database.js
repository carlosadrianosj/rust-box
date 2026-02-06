/* ═══════════════════════════════════════════════════════════════════
   RustBox - Database Tab
   Shows server-side storage: manifests, blobs, totals
   ═══════════════════════════════════════════════════════════════════ */

const Database = (() => {
    let _container = null;
    let _data = null;

    function init() {
        _container = document.getElementById('tab-database');
    }

    async function refresh() {
        if (!_container) return;

        _container.innerHTML = '<p class="db-loading">Loading database overview...</p>';

        try {
            const server = Auth.getServer();
            const result = await backend.getDbOverview(server);

            if (result.ok && result.data) {
                _data = result.data;
                _render();
            } else {
                _container.innerHTML =
                    `<p class="db-error">Failed to load: ${result.error || 'Unknown error'}</p>`;
            }
        } catch (e) {
            _container.innerHTML = `<p class="db-error">Error: ${e}</p>`;
        }
    }

    function _render() {
        if (!_container || !_data) return;

        const totalManifests = _data.total_manifests || 0;
        const totalBlobs = _data.total_blobs || 0;
        const totalBlobBytes = _data.total_blob_bytes || 0;
        const manifests = _data.manifests || [];
        const blobs = _data.blobs || [];

        let html = '';

        // Summary stats
        html += '<div class="db-stats">';
        html += `<div class="db-stat"><span class="db-stat-value">${totalManifests}</span><span class="db-stat-label">Manifests</span></div>`;
        html += `<div class="db-stat"><span class="db-stat-value">${totalBlobs}</span><span class="db-stat-label">Blobs</span></div>`;
        html += `<div class="db-stat"><span class="db-stat-value">${formatBytes(totalBlobBytes)}</span><span class="db-stat-label">Total Storage</span></div>`;
        html += '</div>';

        // Manifests table
        html += '<h3 class="db-section-title">Manifests</h3>';
        if (manifests.length === 0) {
            html += '<p class="db-empty">No manifests found</p>';
        } else {
            html += '<table class="db-table"><thead><tr>';
            html += '<th>File</th><th>Size</th><th>Chunks</th><th>Data (Encrypted)</th><th>Created</th><th>ID</th>';
            html += '</tr></thead><tbody>';

            for (const m of manifests) {
                const filename = m.filename || `encrypted_${(m.id || '').substring(0, 8)}`;
                const size = m.original_size != null ? formatBytes(m.original_size) : '--';
                const chunks = m.chunk_count != null ? m.chunk_count : '--';
                const dataSize = formatBytes(m.data_size || 0);
                const created = m.created_at ? _formatDate(m.created_at) : '--';
                const id = (m.id || '').substring(0, 8) + '...';

                html += '<tr>';
                html += `<td class="db-cell-name" title="${_escapeHtml(m.filename || '')}">${_escapeHtml(filename)}</td>`;
                html += `<td>${size}</td>`;
                html += `<td>${chunks}</td>`;
                html += `<td>${dataSize}</td>`;
                html += `<td>${created}</td>`;
                html += `<td class="db-cell-id" title="${m.id || ''}">${id}</td>`;
                html += '</tr>';
            }

            html += '</tbody></table>';
        }

        // Blobs table
        html += '<h3 class="db-section-title">Blobs</h3>';
        if (blobs.length === 0) {
            html += '<p class="db-empty">No blobs found</p>';
        } else {
            html += '<table class="db-table"><thead><tr>';
            html += '<th>Hash</th><th>Size</th>';
            html += '</tr></thead><tbody>';

            for (const b of blobs) {
                const hashShort = (b.hash_hex || '').substring(0, 16) + '...';
                const size = formatBytes(b.size || 0);

                html += '<tr>';
                html += `<td class="db-cell-hash" title="${b.hash_hex || ''}">${hashShort}</td>`;
                html += `<td>${size}</td>`;
                html += '</tr>';
            }

            html += '</tbody></table>';
        }

        _container.innerHTML = html;
    }

    function _formatDate(dateStr) {
        try {
            const d = new Date(dateStr);
            return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        } catch {
            return dateStr;
        }
    }

    function _escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    return { init, refresh };
})();
