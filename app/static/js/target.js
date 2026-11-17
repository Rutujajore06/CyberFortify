// Fortress Bank Demo Portal Controller

let currentSessionToken = null;
let currentSessionUser = null;
const VALID_ADMIN_TOKEN = 'Bearer cyberfortify-admin-token-valid-2026';

document.addEventListener('DOMContentLoaded', () => {
    refreshTargetStatus();
    loadTargetFeedback();
});

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// 1. Target Status & Defenses
async function refreshTargetStatus() {
    const btn = document.getElementById('btn-refresh-target-status');
    if (btn) btn.innerHTML = `<span>⏳ Checking...</span>`;

    try {
        const res = await fetch('/api/target/status');
        const data = await res.json();

        if (data.status === 'online') {
            const portalBadge = document.getElementById('target-portal-status-badge');
            if (portalBadge) {
                portalBadge.className = 'badge badge-low';
                portalBadge.innerHTML = `<span class="status-dot"></span><span>Target: Online</span>`;
            }

            const defs = data.active_defenses || {};

            updateDefenseBadge('status-badge-rate-limiting', defs.rate_limiting, 'Active Lockout', 'Vulnerable');
            updateDefenseBadge('status-badge-rbac', defs.rbac_enforcement, 'Strict RBAC', 'Broken Access');
            updateDefenseBadge('status-badge-parameterized', defs.parameterized_queries, 'Parameterized', 'SQLi Exposed');
            updateDefenseBadge('status-badge-sanitization', defs.input_sanitization, 'Sanitized', 'XSS Exposed');
        }
    } catch (err) {
        console.warn('Failed to fetch target status', err);
        const portalBadge = document.getElementById('target-portal-status-badge');
        if (portalBadge) {
            portalBadge.className = 'badge badge-critical';
            portalBadge.innerText = 'Target Offline';
        }
    } finally {
        if (btn) btn.innerHTML = `<span>↺ Refresh Status</span>`;
    }
}

function updateDefenseBadge(elementId, isEnabled, activeLabel, disabledLabel) {
    const el = document.getElementById(elementId);
    if (!el) return;
    if (isEnabled) {
        el.innerHTML = `<span class="badge badge-low" style="background: rgba(16, 185, 129, 0.2); color: #34d399; font-weight: 700;">✓ ${activeLabel}</span>`;
    } else {
        el.innerHTML = `<span class="badge badge-critical" style="background: rgba(244, 63, 94, 0.2); color: #fb7185; font-weight: 700;">⚠️ ${disabledLabel}</span>`;
    }
}

// 2. Authentication (Scenario 1)
function quickFillLogin(username, password) {
    document.getElementById('target-login-username').value = username;
    document.getElementById('target-login-password').value = password;
}

async function handleTargetLogin(e) {
    if (e) e.preventDefault();
    const username = document.getElementById('target-login-username').value.trim();
    const password = document.getElementById('target-login-password').value;
    const resultBox = document.getElementById('target-login-result');
    const btn = document.getElementById('btn-target-login');

    if (!username) return;

    btn.disabled = true;
    btn.innerHTML = `<span>⏳ Authenticating...</span>`;
    resultBox.style.display = 'none';

    try {
        const res = await fetch('/api/target/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        resultBox.style.display = 'block';

        if (res.status === 200 && data.status === 'success') {
            currentSessionToken = data.token;
            currentSessionUser = data;

            // Update active session label
            const sessLabel = document.getElementById('active-session-label');
            if (sessLabel) {
                sessLabel.innerText = `${data.role} token for '${username}' (${data.account_number})`;
                sessLabel.style.color = '#38bdf8';
            }

            resultBox.style.background = 'rgba(16, 185, 129, 0.1)';
            resultBox.style.border = '1px solid rgba(16, 185, 129, 0.3)';
            resultBox.style.color = '#34d399';
            resultBox.innerHTML = `
                <div style="font-weight: 700; margin-bottom: 0.25rem;">✓ ${data.message}</div>
                <div style="font-size: 0.8rem; color: #fff;">
                    Role: <span class="badge badge-low">${data.role}</span> &bull; Account: <code>${data.account_number}</code>
                </div>
                <div style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--accent-cyan); margin-top: 0.4rem; word-break: break-all;">
                    Token: ${escapeHtml(data.token)}
                </div>
            `;
        } else if (res.status === 429) {
            // Lockout triggered
            resultBox.style.background = 'rgba(245, 158, 11, 0.15)';
            resultBox.style.border = '1px solid rgba(245, 158, 11, 0.4)';
            resultBox.style.color = '#fbbf24';
            resultBox.innerHTML = `
                <div style="font-weight: 700; margin-bottom: 0.25rem;">🛑 HTTP 429: Account / IP Lockout Active!</div>
                <div style="font-size: 0.85rem; color: #fde68a;">${data.message || data.error}</div>
                <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.4rem;">
                    Defensive rate limiting has detected repeated brute force guessing and temporarily throttled requests.
                </div>
            `;
        } else {
            // Invalid credentials
            resultBox.style.background = 'rgba(244, 63, 94, 0.1)';
            resultBox.style.border = '1px solid rgba(244, 63, 94, 0.3)';
            resultBox.style.color = '#fb7185';
            resultBox.innerHTML = `
                <div style="font-weight: 700;">⚠️ Authentication Failed (HTTP ${res.status})</div>
                <div style="font-size: 0.85rem;">${data.error || 'Invalid credentials provided'}</div>
            `;
        }
    } catch (err) {
        resultBox.style.display = 'block';
        resultBox.style.background = 'rgba(244, 63, 94, 0.1)';
        resultBox.style.color = '#fb7185';
        resultBox.innerHTML = `<div>Network error connecting to login endpoint: ${err.message}</div>`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<span>🔐 Sign In to Portal</span>`;
    }
}

async function simulateFailedLogins(count = 3) {
    const username = document.getElementById('target-login-username').value.trim() || 'test_locked_user';
    document.getElementById('target-login-username').value = username;
    document.getElementById('target-login-password').value = 'wrongpass';

    const resultBox = document.getElementById('target-login-result');
    resultBox.style.display = 'block';
    resultBox.style.background = 'rgba(56, 189, 248, 0.1)';
    resultBox.style.border = '1px solid rgba(56, 189, 248, 0.3)';
    resultBox.style.color = 'var(--accent-cyan)';
    resultBox.innerHTML = `<div>Executing ${count} rapid failed login attempts for '${username}'...</div>`;

    for (let i = 1; i <= count; i++) {
        await fetch('/api/target/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password: `bad_${i}` })
        });
    }

    // Now attempt a 4th login
    handleTargetLogin();
}

// 3. Search & SQL Injection (Scenario 3)
function quickFillSearch(query) {
    document.getElementById('target-search-query').value = query;
    handleTargetSearch();
}

async function handleTargetSearch() {
    const query = document.getElementById('target-search-query').value;
    const resultBox = document.getElementById('target-search-result');
    const btn = document.getElementById('btn-target-search');

    btn.disabled = true;
    btn.innerHTML = `<span>⏳ Searching...</span>`;

    try {
        const res = await fetch(`/api/target/search?q=${encodeURIComponent(query)}`);
        const data = await res.json();

        if (res.status === 200 && data.status === 'success') {
            const results = data.results || [];
            if (results.length === 0) {
                resultBox.innerHTML = `
                    <div style="background: rgba(11, 19, 36, 0.6); padding: 1rem; border-radius: var(--radius-sm); border: 1px solid var(--border-color); color: var(--text-muted); font-size: 0.85rem; text-align: center;">
                        No customer accounts matched query: <code>${escapeHtml(query)}</code>
                    </div>
                `;
            } else {
                resultBox.innerHTML = `
                    <div style="margin-bottom: 0.5rem; display: flex; justify-content: space-between; align-items: center;">
                        <span style="font-size: 0.8rem; color: var(--accent-cyan);">Found ${results.length} account(s) matching '${escapeHtml(query)}'</span>
                        ${results.length > 1 && query.includes("'") ? '<span class="badge badge-critical">SQLi Breach Observed!</span>' : ''}
                    </div>
                    <div class="table-responsive">
                        <table class="table" style="font-size: 0.85rem;">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Username</th>
                                    <th>Role</th>
                                    <th>Account #</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${results.map(r => `
                                    <tr>
                                        <td>#${r.id}</td>
                                        <td style="font-weight: 600; color: #fff;">${escapeHtml(r.username)}</td>
                                        <td><span class="badge ${r.role === 'ADMIN' ? 'badge-critical' : 'badge-low'}">${r.role}</span></td>
                                        <td><code>${escapeHtml(r.account_number)}</code></td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                `;
            }
        } else if (res.status === 400 && data.status === 'blocked') {
            resultBox.innerHTML = `
                <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); padding: 1rem; border-radius: var(--radius-sm); color: #34d399;">
                    <div style="font-weight: 700; margin-bottom: 0.25rem;">🛡️ SQL Injection Neutralized (HTTP 400)</div>
                    <div style="font-size: 0.85rem; color: #fff;">${escapeHtml(data.error)}</div>
                    <div style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted); margin-top: 0.5rem;">Blocked Query: ${escapeHtml(query)}</div>
                </div>
            `;
        } else if (res.status === 500) {
            resultBox.innerHTML = `
                <div style="background: rgba(244, 63, 94, 0.1); border: 1px solid rgba(244, 63, 94, 0.3); padding: 1rem; border-radius: var(--radius-sm); color: #fb7185;">
                    <div style="font-weight: 700;">⚠️ Database Syntax Anomaly (HTTP 500)</div>
                    <div style="font-size: 0.85rem;">${escapeHtml(data.error)}</div>
                </div>
            `;
        }
    } catch (err) {
        resultBox.innerHTML = `<div style="color: #fb7185; padding: 1rem;">Search request failed: ${err.message}</div>`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<span>🔎 Search</span>`;
    }
}

// 4. Treasury Secrets & RBAC (Scenario 2)
async function handleTargetSecrets() {
    const selectedMode = document.querySelector('input[name="target-auth-mode"]:checked').value;
    const resultBox = document.getElementById('target-secrets-result');
    const btn = document.getElementById('btn-target-secrets');

    btn.disabled = true;
    btn.innerHTML = `<span>⏳ Verifying Privilege...</span>`;

    let headers = {};
    if (selectedMode === 'session') {
        if (!currentSessionToken) {
            resultBox.innerHTML = `
                <div style="background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.3); padding: 1rem; border-radius: var(--radius-sm); color: #fbbf24;">
                    ⚠️ No active user session token found. Please sign in via the login panel above first, or select Anonymous / Valid Admin mode.
                </div>
            `;
            btn.disabled = false;
            btn.innerHTML = `<span>🛡️ Request Administrative Vault Secrets</span>`;
            return;
        }
        headers['Authorization'] = currentSessionToken;
    } else if (selectedMode === 'admin') {
        headers['Authorization'] = VALID_ADMIN_TOKEN;
    }

    try {
        const res = await fetch('/api/target/admin/secrets', {
            method: 'GET',
            headers: headers
        });
        const data = await res.json();

        if (res.status === 200 && data.status === 'granted') {
            const s = data.secrets || {};
            resultBox.innerHTML = `
                <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); padding: 1rem; border-radius: var(--radius-sm);">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                        <span style="font-weight: 700; color: #34d399;">🔓 Access Granted to Treasury Vault (HTTP 200)</span>
                        <span class="badge ${selectedMode === 'none' ? 'badge-critical' : 'badge-low'}">
                            ${selectedMode === 'none' ? 'Vulnerable Forced Browsing!' : 'Authorized Token'}
                        </span>
                    </div>
                    <p style="color: var(--text-secondary); font-size: 0.85rem; margin-bottom: 0.75rem;">
                        ${escapeHtml(data.message)}
                    </p>
                    <div class="code-preview" style="font-size: 0.8rem;">
Vault Master Key:      ${escapeHtml(s.vault_master_key || 'N/A')}
Reserve Vault Balance: ${escapeHtml(s.reserve_vault_balance || 'N/A')}
Encryption Standard:   ${escapeHtml(s.encryption_standard || 'N/A')}
Debug Mode:            ${s.debug_mode ? 'True' : 'False'}
                    </div>
                </div>
            `;
        } else {
            resultBox.innerHTML = `
                <div style="background: rgba(244, 63, 94, 0.1); border: 1px solid rgba(244, 63, 94, 0.3); padding: 1rem; border-radius: var(--radius-sm); color: #fb7185;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem;">
                        <span style="font-weight: 700;">⛔ Access Denied: 403 Forbidden</span>
                        <span class="badge badge-low" style="background: rgba(16, 185, 129, 0.2); color: #34d399;">RBAC Guard Active</span>
                    </div>
                    <div style="font-size: 0.85rem; color: #fff;">${escapeHtml(data.error)}</div>
                    <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.4rem;">${escapeHtml(data.details || '')}</div>
                </div>
            `;
        }
    } catch (err) {
        resultBox.innerHTML = `<div style="color: #fb7185; padding: 1rem;">Secrets request failed: ${err.message}</div>`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<span>🛡️ Request Administrative Vault Secrets</span>`;
    }
}

// 5. Feedback & Input Validation (Scenario 4)
function quickFillFeedback(author, content) {
    document.getElementById('target-feedback-author').value = author;
    document.getElementById('target-feedback-content').value = content;
}

async function handleTargetFeedback(e) {
    if (e) e.preventDefault();
    const author = document.getElementById('target-feedback-author').value.trim();
    const content = document.getElementById('target-feedback-content').value;
    const resultBox = document.getElementById('target-feedback-result');
    const btn = document.getElementById('btn-target-feedback');

    if (!author || !content) return;

    btn.disabled = true;
    btn.innerHTML = `<span>⏳ Submitting...</span>`;
    resultBox.style.display = 'none';

    try {
        const res = await fetch('/api/target/feedback', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ author, content })
        });
        const data = await res.json();
        resultBox.style.display = 'block';

        if (res.status === 201) {
            resultBox.style.background = 'rgba(16, 185, 129, 0.1)';
            resultBox.style.border = '1px solid rgba(16, 185, 129, 0.3)';
            resultBox.style.color = '#34d399';
            resultBox.innerHTML = `
                <div style="font-weight: 700;">✓ ${data.message}</div>
                <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">
                    Stored payload: <code>${escapeHtml(data.stored_content)}</code>
                </div>
            `;
            loadTargetFeedback();
        } else if (res.status === 400) {
            resultBox.style.background = 'rgba(16, 185, 129, 0.1)';
            resultBox.style.border = '1px solid rgba(16, 185, 129, 0.3)';
            resultBox.style.color = '#34d399';
            resultBox.innerHTML = `
                <div style="font-weight: 700;">🛡️ Disallowed Script Blocked (HTTP 400)</div>
                <div style="font-size: 0.85rem; color: #fff;">${escapeHtml(data.error)}</div>
                <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">
                    Sanitized Preview: <code>${escapeHtml(data.sanitized_preview || '')}</code>
                </div>
            `;
        } else {
            resultBox.style.background = 'rgba(244, 63, 94, 0.1)';
            resultBox.style.color = '#fb7185';
            resultBox.innerHTML = `<div>Submission failed with HTTP ${res.status}: ${escapeHtml(data.error || 'Error')}</div>`;
        }
    } catch (err) {
        resultBox.style.display = 'block';
        resultBox.style.background = 'rgba(244, 63, 94, 0.1)';
        resultBox.style.color = '#fb7185';
        resultBox.innerHTML = `<div>Feedback request error: ${err.message}</div>`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<span>📤 Submit Feedback</span>`;
    }
}

async function loadTargetFeedback() {
    const listEl = document.getElementById('target-feedback-list');
    const badge = document.getElementById('feedback-count-badge');

    try {
        const res = await fetch('/api/target/feedback');
        const items = await res.json();

        if (Array.isArray(items)) {
            if (badge) badge.innerText = `${items.length} items`;
            if (items.length === 0) {
                listEl.innerHTML = `<div style="color: var(--text-muted); font-size: 0.8rem; text-align: center; padding: 1rem 0;">No feedback entries recorded.</div>`;
                return;
            }

            listEl.innerHTML = items.map(item => {
                const dateStr = item.submitted_at ? new Date(item.submitted_at).toLocaleTimeString() : 'N/A';
                return `
                    <div style="padding: 0.6rem 0.75rem; background: rgba(11, 19, 36, 0.6); border: 1px solid var(--border-color); border-radius: var(--radius-sm); margin-bottom: 0.5rem;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem;">
                            <strong style="color: var(--accent-cyan); font-size: 0.85rem;">${escapeHtml(item.author)}</strong>
                            <span style="color: var(--text-muted); font-size: 0.75rem;">${dateStr}</span>
                        </div>
                        <div style="color: var(--text-primary); font-size: 0.8rem; font-family: var(--font-mono); word-break: break-all;">
                            ${escapeHtml(item.content)}
                        </div>
                    </div>
                `;
            }).join('');
        }
    } catch (err) {
        console.warn('Could not load feedback', err);
    }
}
