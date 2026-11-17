/**
 * CyberFortify - Live Target Registration & Authorization Workflow Controller
 */

let allTargetsCache = [];

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function formatUtcLocalInput(dateObj) {
    const pad = n => String(n).padStart(2, '0');
    return `${dateObj.getUTCFullYear()}-${pad(dateObj.getUTCMonth() + 1)}-${pad(dateObj.getUTCDate())}T${pad(dateObj.getUTCHours())}:${pad(dateObj.getUTCMinutes())}`;
}

function setDefaultDates() {
    const now = new Date();
    const nextWeek = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    const startInput = document.getElementById('reg-start');
    const expiryInput = document.getElementById('reg-expiry');
    if (startInput) startInput.value = formatUtcLocalInput(now);
    if (expiryInput) expiryInput.value = formatUtcLocalInput(nextWeek);
}

function resetRegistrationForm() {
    document.getElementById('register-target-form').reset();
    document.getElementById('reg-paths').value = '/';
    document.getElementById('reg-rate').value = '10';
    setDefaultDates();
    hideFeedback();
}

function showFeedback(message, isError = false) {
    const el = document.getElementById('reg-feedback');
    el.style.display = 'block';
    if (isError) {
        el.style.background = 'rgba(244, 63, 94, 0.12)';
        el.style.border = '1px solid rgba(244, 63, 94, 0.45)';
        el.style.color = '#fda4af';
    } else {
        el.style.background = 'rgba(16, 185, 129, 0.12)';
        el.style.border = '1px solid rgba(16, 185, 129, 0.45)';
        el.style.color = '#6ee7b7';
    }
    el.innerHTML = message;
}

function hideFeedback() {
    const el = document.getElementById('reg-feedback');
    if (el) el.style.display = 'none';
}

function getStatusBadge(status) {
    const map = {
        'APPROVED': '<span class="badge" style="background:rgba(16,185,129,0.18); color:#34d399; border:1px solid rgba(16,185,129,0.4);">APPROVED</span>',
        'PENDING_APPROVAL': '<span class="badge" style="background:rgba(56,189,248,0.18); color:#38bdf8; border:1px solid rgba(56,189,248,0.4);">PENDING APPROVAL</span>',
        'PENDING_VERIFICATION': '<span class="badge" style="background:rgba(245,158,11,0.18); color:#fbbf24; border:1px solid rgba(245,158,11,0.4);">PENDING VERIFICATION</span>',
        'REJECTED': '<span class="badge badge-critical">REJECTED</span>',
        'EXPIRED': '<span class="badge" style="background:rgba(148,163,184,0.15); color:#94a3b8; border:1px solid rgba(148,163,184,0.35);">EXPIRED</span>',
        'REVOKED': '<span class="badge badge-critical">REVOKED</span>'
    };
    return map[status] || `<span class="badge">${escapeHtml(status)}</span>`;
}

async function registerTarget(event) {
    event.preventDefault();
    hideFeedback();

    const btn = document.getElementById('btn-register-target');
    const url = document.getElementById('reg-url').value.trim();
    const ownerName = document.getElementById('reg-owner-name').value.trim();
    const ownerEmail = document.getElementById('reg-owner-email').value.trim();
    const verificationMethod = document.getElementById('reg-verification-method').value;
    const pathsRaw = document.getElementById('reg-paths').value.trim();
    const maxRate = parseInt(document.getElementById('reg-rate').value, 10);
    const startVal = document.getElementById('reg-start').value;
    const expiryVal = document.getElementById('reg-expiry').value;
    const ownerConsent = document.getElementById('reg-consent').checked;

    const methodBoxes = Array.from(document.querySelectorAll('input[name="allowed_methods"]:checked'));
    const allowedMethods = methodBoxes.map(cb => cb.value);

    if (allowedMethods.length === 0) {
        showFeedback('Select at least one safe HTTP method (GET, HEAD, or OPTIONS).', true);
        return;
    }

    const payload = {
        target_url: url,
        owner_name: ownerName,
        owner_email: ownerEmail,
        owner_consent: ownerConsent,
        verification_method: verificationMethod,
        approved_paths: pathsRaw || '/',
        allowed_methods: allowedMethods,
        start_date: startVal ? `${startVal}:00Z` : null,
        expiry_date: expiryVal ? `${expiryVal}:00Z` : null,
        max_request_rate: maxRate
    };

    btn.disabled = true;
    try {
        const res = await fetch('/api/live/targets', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!res.ok) {
            showFeedback(`<strong>Registration Blocked (${escapeHtml(data.error_type || 'ERROR')}):</strong> ${escapeHtml(data.message)}`, true);
            return;
        }
        const t = data.target;
        showFeedback(
            `<strong>Target Registered:</strong> <code>${escapeHtml(t.domain)}</code> (${escapeHtml(t.target_uuid)}). ` +
            `Verification Token: <code>${escapeHtml(t.verification_token)}</code>. Complete verification and admin approval below.`,
            false
        );
        await loadTargets();
    } catch (err) {
        showFeedback(`Network error registering target: ${escapeHtml(err.message)}`, true);
    } finally {
        btn.disabled = false;
    }
}

async function loadTargets() {
    const statusFilter = document.getElementById('status-filter').value;
    const tbody = document.getElementById('targets-table-body');
    const url = statusFilter ? `/api/live/targets?status=${encodeURIComponent(statusFilter)}` : '/api/live/targets';

    try {
        const res = await fetch(url);
        const data = await res.json();
        const targets = data.targets || [];
        allTargetsCache = targets;

        // Update stats using unfiltered or summary counts
        const s = data.summary || {};
        document.getElementById('stat-approved').textContent = s.approved || 0;
        document.getElementById('stat-pending').textContent = (s.pending_verification || 0) + (s.pending_approval || 0);
        document.getElementById('stat-inactive').textContent = (s.expired || 0) + (s.rejected || 0);

        if (targets.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:1.5rem;">No registered live targets found. Register an authorized website above to begin.</td></tr>';
            return;
        }

        tbody.innerHTML = targets.map(t => {
            const pathsStr = (t.approved_paths || []).join(', ');
            const methodsStr = (t.allowed_methods || []).join(', ');
            const startShort = (t.start_date || '').slice(0, 16).replace('T', ' ');
            const expShort = (t.expiry_date || '').slice(0, 16).replace('T', ' ');

            const role = window.CURRENT_USER_ROLE || '';
            const isAdminOrDemo = (role === '' || role === 'ADMIN');
            const isViewer = (role === 'VIEWER');

            let actionsHtml = `<div style="display:flex; gap:0.4rem; flex-wrap:wrap;">`;
            if (!isViewer) {
                actionsHtml += `<button class="btn btn-secondary btn-sm" onclick="openVerifyModal('${escapeHtml(t.target_uuid)}')">🔑 Details / Verify</button>`;
            }

            if (isAdminOrDemo && t.auth_status === 'PENDING_APPROVAL') {
                actionsHtml += `<button class="btn btn-primary btn-sm" onclick="approveTarget('${escapeHtml(t.target_uuid)}')">✓ Approve</button>`;
            }
            if (isAdminOrDemo && (t.auth_status === 'PENDING_VERIFICATION' || t.auth_status === 'PENDING_APPROVAL' || t.auth_status === 'APPROVED')) {
                actionsHtml += `<button class="btn btn-danger btn-sm" onclick="rejectTarget('${escapeHtml(t.target_uuid)}')">✕ Reject</button>`;
            }
            if (t.is_scannable) {
                actionsHtml += `<a href="/live-assessment?target=${encodeURIComponent(t.target_uuid)}" class="btn btn-primary btn-sm">📡 Assess</a>`;
            }
            actionsHtml += `</div>`;

            return `
                <tr>
                    <td>
                        <div style="font-weight:600; color:#fff;">${escapeHtml(t.domain)}</div>
                        <div style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-muted);">${escapeHtml(t.target_url)}</div>
                        <div style="font-size:0.7rem; color:var(--text-muted);">${escapeHtml(t.target_uuid)}</div>
                    </td>
                    <td>
                        <div style="font-size:0.85rem;">${escapeHtml(t.owner_name)}</div>
                        <div style="font-size:0.75rem; color:var(--text-secondary);">${escapeHtml(t.owner_email)}</div>
                        <div style="font-size:0.7rem; color:${t.is_verified ? 'var(--accent-emerald)' : 'var(--accent-amber)'};">
                            ${t.is_verified
                                ? (t.verification_method === 'signed_attestation' ? '✓ Self-Attestation Recorded' : '✓ Ownership Verified')
                                : '⏳ Authorization Confirmation Pending'}
                        </div>
                    </td>
                    <td>
                        ${getStatusBadge(t.auth_status)}
                        ${t.rejection_reason ? `<div style="font-size:0.72rem; color:#fda4af; margin-top:0.25rem;">${escapeHtml(t.rejection_reason)}</div>` : ''}
                    </td>
                    <td style="font-family:var(--font-mono); font-size:0.78rem;">
                        <div>Paths: <span style="color:var(--accent-cyan);">${escapeHtml(pathsStr)}</span></div>
                        <div>Methods: ${escapeHtml(methodsStr)}</div>
                        <div>Rate Limit: ${escapeHtml(t.max_request_rate)} req/min</div>
                    </td>
                    <td style="font-size:0.78rem; font-family:var(--font-mono);">
                        <div>Start: ${escapeHtml(startShort)}</div>
                        <div>Expiry: ${escapeHtml(expShort)}</div>
                    </td>
                    <td>${actionsHtml}</td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" style="color:#fb7185; text-align:center;">Failed to load targets: ${escapeHtml(err.message)}</td></tr>`;
    }
}

function openVerifyModal(targetUuid) {
    const t = allTargetsCache.find(item => item.target_uuid === targetUuid);
    if (!t) return;

    const methodInstructions = {
        'http_file': `Host a plain text file at <code>https://${escapeHtml(t.domain)}/.well-known/cyberfortify-verify.txt</code> containing the exact token below, or submit the token directly for signed attestation.`,
        'meta_tag': `Add <code>&lt;meta name="cyberfortify-verification" content="${escapeHtml(t.verification_token)}"&gt;</code> inside the <code>&lt;head&gt;</code> of <code>https://${escapeHtml(t.domain)}/</code>, or submit the token below.`,
        'dns_txt': `Publish a DNS TXT record on <code>${escapeHtml(t.domain)}</code> with value <code>${escapeHtml(t.verification_token)}</code>, then confirm with the token below.`,
        'signed_attestation': `Confirm your explicit authorization declaration by submitting the assigned token below. <strong>Note:</strong> Self-attestation records your signed declaration and requires administrator approval; it does not claim independent DNS/HTTP domain ownership proof.`
    };

    const html = `
        <h2 style="color:#fff; margin-bottom:0.5rem;">🔑 Authorization &amp; Verification: ${escapeHtml(t.domain)}</h2>
        <div style="margin-bottom:1rem;">${getStatusBadge(t.auth_status)} <span style="font-family:var(--font-mono); font-size:0.8rem; color:var(--text-muted); margin-left:0.5rem;">${escapeHtml(t.target_uuid)}</span></div>

        <div style="background:rgba(0,242,254,0.06); border:1px solid rgba(0,242,254,0.25); padding:0.9rem; border-radius:var(--radius-sm); margin-bottom:1rem;">
            <div style="font-size:0.75rem; text-transform:uppercase; color:var(--accent-cyan); font-weight:600; margin-bottom:0.25rem;">Verification Token (${escapeHtml(t.verification_method)})</div>
            <div style="font-family:var(--font-mono); font-size:0.9rem; color:#fff; word-break:break-all;">${escapeHtml(t.verification_token)}</div>
            <p style="font-size:0.8rem; color:var(--text-secondary); margin-top:0.5rem; line-height:1.5;">
                ${methodInstructions[t.verification_method] || ''}
            </p>
        </div>

        ${!t.is_verified && t.auth_status === 'PENDING_VERIFICATION' ? `
            <div style="margin-bottom:1rem;">
                <label style="display:block; font-size:0.8rem; color:var(--text-secondary); margin-bottom:0.3rem;">Submit Verification Token (or leave blank to check live HTTP/Meta endpoint)</label>
                <input type="text" id="modal-verify-token" placeholder="${escapeHtml(t.verification_token)}"
                       style="width:100%; font-family:var(--font-mono); padding:0.6rem; background:var(--bg-input); border:1px solid var(--border-color); color:#fff; border-radius:var(--radius-sm); margin-bottom:0.6rem;">
                <div style="display:flex; gap:0.5rem;">
                    <button class="btn btn-primary btn-sm" onclick="submitVerification('${escapeHtml(t.target_uuid)}', true)">✓ Verify with Token</button>
                    ${(t.verification_method === 'http_file' || t.verification_method === 'meta_tag') ?
                        `<button class="btn btn-secondary btn-sm" onclick="submitVerification('${escapeHtml(t.target_uuid)}', false)">🌐 Verify Live Endpoint</button>` : ''}
                </div>
            </div>
        ` : ''}

        <div id="modal-action-feedback" style="margin-top:0.75rem; font-size:0.82rem;"></div>

        <div style="margin-top:1rem; padding-top:1rem; border-top:1px solid var(--border-color); font-size:0.8rem; color:var(--text-secondary);">
            <div><strong>Approved Paths:</strong> <code>${escapeHtml((t.approved_paths || []).join(', '))}</code></div>
            <div><strong>Allowed Methods:</strong> <code>${escapeHtml((t.allowed_methods || []).join(', '))}</code></div>
            <div><strong>Rate Limit:</strong> ${escapeHtml(t.max_request_rate)} req/min</div>
            <div><strong>Validity:</strong> ${escapeHtml(t.start_date)} &rarr; ${escapeHtml(t.expiry_date)}</div>
            ${t.verified_at ? `<div><strong>Verified At:</strong> ${escapeHtml(t.verified_at)} (${escapeHtml(t.verification_notes || '')})</div>` : ''}
            ${t.approved_at ? `<div><strong>Approved By:</strong> ${escapeHtml(t.approved_by)} at ${escapeHtml(t.approved_at)}</div>` : ''}
        </div>
    `;
    openModal(html);
}

async function submitVerification(targetUuid, useTokenInput) {
    const feedback = document.getElementById('modal-action-feedback');
    const tokenEl = document.getElementById('modal-verify-token');
    const payload = {};
    if (useTokenInput && tokenEl) {
        payload.verification_token = tokenEl.value.trim();
    }

    feedback.style.color = 'var(--accent-cyan)';
    feedback.textContent = 'Verifying website ownership...';

    try {
        const res = await fetch(`/api/live/targets/${encodeURIComponent(targetUuid)}/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!res.ok) {
            feedback.style.color = '#fb7185';
            feedback.textContent = data.message || 'Verification failed.';
            return;
        }
        feedback.style.color = '#34d399';
        feedback.textContent = data.message;
        await loadTargets();
        setTimeout(() => closeModal(), 900);
    } catch (err) {
        feedback.style.color = '#fb7185';
        feedback.textContent = err.message;
    }
}

async function approveTarget(targetUuid) {
    try {
        const res = await fetch(`/api/live/targets/${encodeURIComponent(targetUuid)}/approve`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ approved_by: 'admin' })
        });
        const data = await res.json();
        if (!res.ok) {
            showFeedback(`<strong>Approval Error:</strong> ${escapeHtml(data.message)}`, true);
            return;
        }
        showFeedback(`<strong>Approved:</strong> ${escapeHtml(data.message)}`, false);
        await loadTargets();
    } catch (err) {
        showFeedback(`Approval request failed: ${escapeHtml(err.message)}`, true);
    }
}

async function rejectTarget(targetUuid) {
    const reason = prompt('Enter reason for rejecting/revoking this target:', 'Authorization scope rejected by administrator');
    if (reason === null) return;

    try {
        const res = await fetch(`/api/live/targets/${encodeURIComponent(targetUuid)}/reject`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ reason: reason.trim() || 'Rejected by administrator', rejected_by: 'admin' })
        });
        const data = await res.json();
        if (!res.ok) {
            showFeedback(`<strong>Reject Error:</strong> ${escapeHtml(data.message)}`, true);
            return;
        }
        showFeedback(`<strong>Rejected:</strong> ${escapeHtml(data.message)}`, false);
        await loadTargets();
    } catch (err) {
        showFeedback(`Reject request failed: ${escapeHtml(err.message)}`, true);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    setDefaultDates();
    loadTargets();
});
