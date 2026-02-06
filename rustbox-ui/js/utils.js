/* ═══════════════════════════════════════════════════════════════════
   RustBox - Utility Functions
   Shared formatters and helpers
   ═══════════════════════════════════════════════════════════════════ */

/**
 * Format byte count into human-readable string.
 * @param {number} bytes - Byte count
 * @param {number} [decimals=1] - Decimal places
 * @returns {string} Formatted string (e.g., "1.5 MB")
 */
function formatBytes(bytes, decimals = 1) {
    if (bytes === 0 || bytes == null) return '0 B';
    if (bytes < 0) bytes = Math.abs(bytes);

    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const k = 1024;
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    const idx = Math.min(i, units.length - 1);
    const value = bytes / Math.pow(k, idx);

    // Show no decimals for bytes
    if (idx === 0) return `${Math.round(value)} B`;

    return `${value.toFixed(decimals)} ${units[idx]}`;
}

/**
 * Format a date into YYYY-MM-DD HH:MM.
 * Accepts epoch seconds (number) or ISO 8601 / RFC 3339 strings.
 * @param {number|string} input - Unix timestamp in seconds or date string
 * @returns {string} Formatted date string
 */
function formatDate(input) {
    if (!input) return '--';

    let d;
    if (typeof input === 'number') {
        d = new Date(input * 1000);       // epoch seconds
    } else {
        d = new Date(input);              // ISO string
    }

    if (isNaN(d.getTime())) return '--';  // guard: invalid date

    const year = d.getFullYear();
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    const hours = String(d.getHours()).padStart(2, '0');
    const minutes = String(d.getMinutes()).padStart(2, '0');

    return `${year}-${month}-${day} ${hours}:${minutes}`;
}

/**
 * Get file icon configuration based on filename extension.
 * Returns { class, label, svg } where svg is an inline SVG string.
 *
 * @param {string} filename
 * @returns {{ class: string, label: string, svg: string }}
 */
function getFileIcon(filename) {
    if (!filename) {
        return _iconDef('default', 'FILE', _svgFile());
    }

    const ext = filename.split('.').pop().toLowerCase();

    const map = {
        // Documents
        pdf:  _iconDef('pdf',   'PDF',  _svgDoc()),
        doc:  _iconDef('doc',   'DOC',  _svgDoc()),
        docx: _iconDef('doc',   'DOC',  _svgDoc()),
        odt:  _iconDef('doc',   'ODT',  _svgDoc()),
        rtf:  _iconDef('doc',   'RTF',  _svgDoc()),

        // Spreadsheets
        xls:  _iconDef('xls',   'XLS',  _svgGrid()),
        xlsx: _iconDef('xls',   'XLS',  _svgGrid()),
        csv:  _iconDef('xls',   'CSV',  _svgGrid()),
        ods:  _iconDef('xls',   'ODS',  _svgGrid()),

        // Images
        jpg:  _iconDef('img',   'IMG',  _svgImage()),
        jpeg: _iconDef('img',   'IMG',  _svgImage()),
        png:  _iconDef('img',   'PNG',  _svgImage()),
        gif:  _iconDef('img',   'GIF',  _svgImage()),
        svg:  _iconDef('img',   'SVG',  _svgImage()),
        webp: _iconDef('img',   'IMG',  _svgImage()),
        bmp:  _iconDef('img',   'BMP',  _svgImage()),
        ico:  _iconDef('img',   'ICO',  _svgImage()),

        // Video
        mp4:  _iconDef('video', 'MP4',  _svgPlay()),
        mkv:  _iconDef('video', 'MKV',  _svgPlay()),
        avi:  _iconDef('video', 'AVI',  _svgPlay()),
        mov:  _iconDef('video', 'MOV',  _svgPlay()),
        webm: _iconDef('video', 'WEBM', _svgPlay()),
        wmv:  _iconDef('video', 'WMV',  _svgPlay()),

        // Audio
        mp3:  _iconDef('audio', 'MP3',  _svgMusic()),
        wav:  _iconDef('audio', 'WAV',  _svgMusic()),
        flac: _iconDef('audio', 'FLAC', _svgMusic()),
        aac:  _iconDef('audio', 'AAC',  _svgMusic()),
        ogg:  _iconDef('audio', 'OGG',  _svgMusic()),
        m4a:  _iconDef('audio', 'M4A',  _svgMusic()),

        // Archives
        zip:  _iconDef('zip',   'ZIP',  _svgArchive()),
        rar:  _iconDef('zip',   'RAR',  _svgArchive()),
        '7z': _iconDef('zip',   '7Z',   _svgArchive()),
        tar:  _iconDef('zip',   'TAR',  _svgArchive()),
        gz:   _iconDef('zip',   'GZ',   _svgArchive()),
        bz2:  _iconDef('zip',   'BZ2',  _svgArchive()),
        xz:   _iconDef('zip',   'XZ',   _svgArchive()),

        // Code
        js:   _iconDef('code',  'JS',   _svgCode()),
        ts:   _iconDef('code',  'TS',   _svgCode()),
        py:   _iconDef('code',  'PY',   _svgCode()),
        rs:   _iconDef('code',  'RS',   _svgCode()),
        go:   _iconDef('code',  'GO',   _svgCode()),
        c:    _iconDef('code',  'C',    _svgCode()),
        cpp:  _iconDef('code',  'C++',  _svgCode()),
        h:    _iconDef('code',  'H',    _svgCode()),
        java: _iconDef('code',  'JAVA', _svgCode()),
        html: _iconDef('code',  'HTML', _svgCode()),
        css:  _iconDef('code',  'CSS',  _svgCode()),
        json: _iconDef('code',  'JSON', _svgCode()),
        xml:  _iconDef('code',  'XML',  _svgCode()),
        yaml: _iconDef('code',  'YAML', _svgCode()),
        yml:  _iconDef('code',  'YML',  _svgCode()),
        toml: _iconDef('code',  'TOML', _svgCode()),
        sh:   _iconDef('code',  'SH',   _svgCode()),
        sql:  _iconDef('code',  'SQL',  _svgCode()),

        // Text
        txt:  _iconDef('text',  'TXT',  _svgFile()),
        md:   _iconDef('text',  'MD',   _svgFile()),
        log:  _iconDef('text',  'LOG',  _svgFile()),
    };

    return map[ext] || _iconDef('default', ext.toUpperCase().slice(0, 4) || 'FILE', _svgFile());
}

function _iconDef(type, label, svg) {
    return { class: `file-icon file-icon-${type}`, label, svg };
}

// ── Inline SVG templates ────────────────────────────────────────────

function _svgFile() {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>';
}

function _svgDoc() {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>';
}

function _svgGrid() {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="3" y1="15" x2="21" y2="15"/><line x1="9" y1="3" x2="9" y2="21"/><line x1="15" y1="3" x2="15" y2="21"/></svg>';
}

function _svgImage() {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>';
}

function _svgPlay() {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"/></svg>';
}

function _svgMusic() {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/></svg>';
}

function _svgArchive() {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/></svg>';
}

function _svgCode() {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>';
}

/**
 * Debounce a function call.
 * @param {Function} fn - Function to debounce
 * @param {number} ms - Delay in milliseconds
 * @returns {Function} Debounced function
 */
function debounce(fn, ms) {
    let timer = null;
    return function (...args) {
        clearTimeout(timer);
        timer = setTimeout(() => fn.apply(this, args), ms);
    };
}

/**
 * Generate a short unique ID for toast tracking.
 * @returns {string}
 */
function uid() {
    return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}
