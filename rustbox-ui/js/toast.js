/* ═══════════════════════════════════════════════════════════════════
   RustBox - Toast Notification System
   Apple-style frosted glass toasts with animations
   ═══════════════════════════════════════════════════════════════════ */

const Toast = (() => {
    const MAX_VISIBLE = 5;
    const DEFAULT_DURATION = 4000; // ms

    /** @type {Map<string, { el: HTMLElement, timer: number|null }>} */
    const _active = new Map();

    let _container = null;

    function _getContainer() {
        if (!_container) {
            _container = document.getElementById('toast-container');
        }
        return _container;
    }

    // ── SVG Icons ───────────────────────────────────────────────────

    const ICONS = {
        success: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
            <polyline points="22 4 12 14.01 9 11.01"/>
        </svg>`,

        error: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/>
            <line x1="15" y1="9" x2="9" y2="15"/>
            <line x1="9" y1="9" x2="15" y2="15"/>
        </svg>`,

        info: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/>
            <line x1="12" y1="16" x2="12" y2="12"/>
            <line x1="12" y1="8" x2="12.01" y2="8"/>
        </svg>`,

        progress: '<div class="toast-spinner"></div>',
    };

    const CLOSE_SVG = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <line x1="18" y1="6" x2="6" y2="18"/>
        <line x1="6" y1="6" x2="18" y2="18"/>
    </svg>`;

    // ── Internal Helpers ────────────────────────────────────────────

    function _enforceLimit() {
        const container = _getContainer();
        while (_active.size >= MAX_VISIBLE) {
            // Dismiss the oldest (first inserted)
            const oldest = _active.keys().next().value;
            dismiss(oldest);
        }
    }

    function _buildElement(id, message, type, detail) {
        const el = document.createElement('div');
        el.className = `toast toast-${type}`;
        el.dataset.toastId = id;

        // Icon
        const iconDiv = document.createElement('div');
        iconDiv.className = 'toast-icon';
        iconDiv.innerHTML = ICONS[type] || ICONS.info;

        // Body
        const bodyDiv = document.createElement('div');
        bodyDiv.className = 'toast-body';

        const msgP = document.createElement('p');
        msgP.className = 'toast-message';
        msgP.textContent = message;
        bodyDiv.appendChild(msgP);

        if (detail) {
            const detailP = document.createElement('p');
            detailP.className = 'toast-detail';
            detailP.textContent = detail;
            bodyDiv.appendChild(detailP);
        }

        // Close button
        const closeBtn = document.createElement('button');
        closeBtn.className = 'toast-close';
        closeBtn.innerHTML = CLOSE_SVG;
        closeBtn.setAttribute('aria-label', 'Dismiss');
        closeBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            dismiss(id);
        });

        el.appendChild(iconDiv);
        el.appendChild(bodyDiv);
        el.appendChild(closeBtn);

        return el;
    }

    // ── Public API ──────────────────────────────────────────────────

    /**
     * Show a toast notification.
     * @param {string} message - Toast message
     * @param {'success'|'error'|'info'|'progress'} [type='info'] - Toast type
     * @param {number|null} [duration] - Auto-dismiss in ms. null = no auto-dismiss.
     *                                   Defaults to 4000 (except progress = no auto-dismiss).
     * @param {string} [detail] - Optional secondary text
     * @returns {string} Toast ID for later updates/dismissal
     */
    function show(message, type = 'info', duration, detail) {
        _enforceLimit();

        const id = uid();
        const container = _getContainer();
        const el = _buildElement(id, message, type, detail);

        // Auto-dismiss timer bar (visual indicator)
        const autoDismiss = duration !== null &&
            (duration !== undefined ? duration > 0 : type !== 'progress');
        const actualDuration = duration != null ? duration : (type === 'progress' ? 0 : DEFAULT_DURATION);

        if (autoDismiss && actualDuration > 0) {
            const timerBar = document.createElement('div');
            timerBar.className = 'toast-timer';
            timerBar.style.setProperty('--toast-duration', `${actualDuration}ms`);
            el.appendChild(timerBar);
        }

        container.appendChild(el);

        // Force reflow so animation starts
        el.offsetHeight; // eslint-disable-line no-unused-expressions

        // Schedule auto-dismiss
        let timer = null;
        if (autoDismiss && actualDuration > 0) {
            timer = setTimeout(() => dismiss(id), actualDuration);

            // Pause on hover
            el.addEventListener('mouseenter', () => {
                if (timer) {
                    clearTimeout(timer);
                    timer = null;
                }
            });
            el.addEventListener('mouseleave', () => {
                timer = setTimeout(() => dismiss(id), actualDuration / 2);
                _active.set(id, { el, timer });
            });
        }

        _active.set(id, { el, timer });
        return id;
    }

    /**
     * Show a progress toast that persists until updated or dismissed.
     * @param {string} message
     * @param {string} [id] - Optional custom ID
     * @returns {string} Toast ID
     */
    function showProgress(message, id) {
        _enforceLimit();

        const toastId = id || uid();
        const container = _getContainer();

        // If a toast with this ID already exists, update it instead
        if (_active.has(toastId)) {
            update(toastId, message, 'progress');
            return toastId;
        }

        const el = _buildElement(toastId, message, 'progress');

        // Add indeterminate progress bar
        const barContainer = document.createElement('div');
        barContainer.className = 'toast-progress-bar-container';
        const bar = document.createElement('div');
        bar.className = 'toast-progress-bar indeterminate';
        barContainer.appendChild(bar);
        el.querySelector('.toast-body').appendChild(barContainer);

        container.appendChild(el);
        el.offsetHeight; // force reflow

        _active.set(toastId, { el, timer: null });
        return toastId;
    }

    /**
     * Update an existing toast's message and/or type.
     * @param {string} id - Toast ID
     * @param {string} [message] - New message
     * @param {'success'|'error'|'info'|'progress'} [type] - New type
     * @param {number|null} [autoDismissMs] - Set auto-dismiss (null to clear)
     */
    function update(id, message, type, autoDismissMs) {
        const entry = _active.get(id);
        if (!entry) return;

        const { el } = entry;

        // Update message
        if (message) {
            const msgEl = el.querySelector('.toast-message');
            if (msgEl) msgEl.textContent = message;
        }

        // Update type
        if (type) {
            // Remove old type class
            el.className = el.className.replace(/toast-(success|error|info|progress)/g, '');
            el.classList.add(`toast-${type}`);

            // Update icon
            const iconEl = el.querySelector('.toast-icon');
            if (iconEl) iconEl.innerHTML = ICONS[type] || ICONS.info;

            // Remove progress bar if switching away from progress
            if (type !== 'progress') {
                const barContainer = el.querySelector('.toast-progress-bar-container');
                if (barContainer) barContainer.remove();

                // Remove spinner from icon
                const spinner = el.querySelector('.toast-spinner');
                if (spinner) spinner.remove();
            }
        }

        // Set new auto-dismiss
        if (autoDismissMs != null && autoDismissMs > 0) {
            if (entry.timer) clearTimeout(entry.timer);
            entry.timer = setTimeout(() => dismiss(id), autoDismissMs);
            _active.set(id, entry);
        }
    }

    /**
     * Update progress bar percentage.
     * @param {string} id - Toast ID
     * @param {number} percent - 0-100
     */
    function setProgress(id, percent) {
        const entry = _active.get(id);
        if (!entry) return;

        const bar = entry.el.querySelector('.toast-progress-bar');
        if (bar) {
            bar.classList.remove('indeterminate');
            bar.style.width = `${Math.min(100, Math.max(0, percent))}%`;
        }
    }

    /**
     * Dismiss a toast with exit animation.
     * @param {string} id - Toast ID
     */
    function dismiss(id) {
        const entry = _active.get(id);
        if (!entry) return;

        const { el, timer } = entry;
        if (timer) clearTimeout(timer);
        _active.delete(id);

        el.classList.add('toast-exit');
        el.addEventListener('animationend', () => {
            el.remove();
        }, { once: true });

        // Fallback removal if animationend doesn't fire
        setTimeout(() => {
            if (el.parentNode) el.remove();
        }, 400);
    }

    /**
     * Dismiss all active toasts.
     */
    function dismissAll() {
        for (const id of _active.keys()) {
            dismiss(id);
        }
    }

    return {
        show,
        showProgress,
        update,
        setProgress,
        dismiss,
        dismissAll,
    };
})();
