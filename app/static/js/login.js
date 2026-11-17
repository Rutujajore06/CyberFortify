/**
 * CyberFortify - Authentication & Admin RBAC User Management Controller
 */

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function showAuthFeedback(msg, isError = false) {
    const el = document.getElementById('auth-feedback');
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
    el.innerHTML = msg;
}

async function loadAuthState() {
    try {
        const res = await fetch('/api/auth/me');
        const data = await res.json();
        if (data.csrf_token && window.setCsrfToken) {
            window.setCsrfToken(data.csrf_token);
        }

        const summary = document.getElementById('auth-status-summary');
        const badges = document.getElementById('auth-mode-badges');
        const setupCard = document.getElementById('admin-setup-card');
        const adminSection = document.getElementById('admin-users-section');

        setupCard.style.display = data.has_admin ? 'none' : 'block';

        if (data.authenticated && data.user) {
            summary.innerHTML = `Signed in as <strong>${escapeHtml(data.user.username)}</strong> (${escapeHtml(data.user.email)}) &mdash; Role: <strong style="color:var(--accent-cyan);">${escapeHtml(data.user.role_label)}</strong>`;
            if (data.user.role === 'ADMIN') {
                adminSection.style.display = 'block';
                await loadAdminUsers();
            } else {
                adminSection.style.display = 'none';
            }
        } else {
            summary.innerHTML = data.auth_enforced
                ? 'Not signed in. <strong>Authentication is strictly required</strong> for Live Testing endpoints.'
                : 'Not signed in. Running in <strong>Local Loopback Demo Mode</strong> (sign in to demonstrate strict Admin / Website Owner / Viewer RBAC).';
            adminSection.style.display = 'none';
        }

        badges.innerHTML = `
            <span class="badge ${data.auth_enforced ? 'badge-critical' : 'badge-low'}">
                ${data.auth_enforced ? 'AUTH ENFORCED' : 'LOCAL DEMO MODE'}
            </span>
            <span class="badge" style="background:rgba(56,189,248,0.15); color:#7dd3fc; border:1px solid rgba(56,189,248,0.35);">
                ${data.public_deployment ? 'PUBLIC DEPLOYMENT' : 'LOOPBACK LOCAL'}
            </span>
        `;
    } catch (err) {
        console.error('Error loading auth state', err);
    }
}

async function submitAdminSetup(event) {
    event.preventDefault();
    const payload = {
        username: document.getElementById('setup-username').value.trim(),
        email: document.getElementById('setup-email').value.trim(),
        password: document.getElementById('setup-password').value
    };
    const res = await fetch('/api/auth/setup-admin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) {
        showAuthFeedback(`<strong>Setup Error:</strong> ${escapeHtml(data.message)}`, true);
        return;
    }
    showAuthFeedback(`<strong>Success:</strong> ${escapeHtml(data.message)}`, false);
    setTimeout(() => window.location.reload(), 600);
}

async function submitLogin(event) {
    event.preventDefault();
    const payload = {
        identifier: document.getElementById('login-identifier').value.trim(),
        password: document.getElementById('login-password').value
    };
    const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) {
        showAuthFeedback(`<strong>Sign In Failed:</strong> ${escapeHtml(data.message)}`, true);
        return;
    }
    showAuthFeedback(`<strong>Signed In:</strong> ${escapeHtml(data.message)}`, false);
    setTimeout(() => window.location.reload(), 500);
}

async function submitRegister(event) {
    event.preventDefault();
    const payload = {
        username: document.getElementById('reg-username').value.trim(),
        email: document.getElementById('reg-email').value.trim(),
        role: document.getElementById('reg-role').value,
        password: document.getElementById('reg-password').value
    };
    const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) {
        showAuthFeedback(`<strong>Registration Error:</strong> ${escapeHtml(data.message)}`, true);
        return;
    }
    showAuthFeedback(`<strong>Registered:</strong> ${escapeHtml(data.message)}`, false);
    setTimeout(() => window.location.reload(), 500);
}

async function loadAdminUsers() {
    const tbody = document.getElementById('admin-users-tbody');
    const res = await fetch('/api/auth/users');
    if (!res.ok) return;
    const data = await res.json();
    const users = data.users || [];
    tbody.innerHTML = users.map(u => `
        <tr>
            <td style="font-weight:600; color:#fff;">${escapeHtml(u.username)}</td>
            <td>${escapeHtml(u.email)}</td>
            <td><span class="badge">${escapeHtml(u.role_label)}</span></td>
            <td style="font-family:var(--font-mono); font-size:0.78rem;">${escapeHtml((u.created_at || '').slice(0, 19).replace('T', ' '))}</td>
            <td style="font-family:var(--font-mono); font-size:0.78rem;">${escapeHtml((u.last_login_at || 'Never').slice(0, 19).replace('T', ' '))}</td>
        </tr>
    `).join('');
}

async function adminCreateUser(event) {
    event.preventDefault();
    const payload = {
        username: document.getElementById('adm-new-username').value.trim(),
        email: document.getElementById('adm-new-email').value.trim(),
        role: document.getElementById('adm-new-role').value,
        password: document.getElementById('adm-new-password').value
    };
    const res = await fetch('/api/auth/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) {
        showAuthFeedback(`<strong>User Provisioning Error:</strong> ${escapeHtml(data.message)}`, true);
        return;
    }
    showAuthFeedback(`<strong>User Created:</strong> ${escapeHtml(data.message)}`, false);
    document.getElementById('adm-new-username').value = '';
    document.getElementById('adm-new-email').value = '';
    document.getElementById('adm-new-password').value = '';
    await loadAdminUsers();
}

document.addEventListener('DOMContentLoaded', loadAuthState);
