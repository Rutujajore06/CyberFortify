/**
 * CyberFortify - Live Website Assessment Dashboard Controller
 */

let liveTargets = [];
let currentLiveAssessment = null;
let currentLiveFilter = 'all';

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function getAuthBadge(status) {
    const map = {
        'APPROVED': '<span class="badge" style="background:rgba(16,185,129,0.18); color:#34d399; border:1px solid rgba(16,185,129,0.4);">APPROVED</span>',
        'PENDING_APPROVAL': '<span class="badge" style="background:rgba(56,189,248,0.18); color:#38bdf8; border:1px solid rgba(56,189,248,0.4);">PENDING APPROVAL</span>',
        'PENDING_VERIFICATION': '<span class="badge" style="background:rgba(245,158,11,0.18); color:#fbbf24; border:1px solid rgba(245,158,11,0.4);">PENDING VERIFICATION</span>',
        'REJECTED': '<span class="badge badge-critical">REJECTED</span>',
        'EXPIRED': '<span class="badge" style="background:rgba(148,163,184,0.15); color:#94a3b8; border:1px solid rgba(148,163,184,0.35);">EXPIRED</span>'
    };
    return map[status] || `<span class="badge">${escapeHtml(status)}</span>`;
}

function getSeverityBadge(severity, status) {
    const st = (status || '').toUpperCase();
    const sev = (severity || 'INFO').toUpperCase();
    if (st === 'PASS' || st === 'DEFENDED') {
        return '<span class="badge" style="background:rgba(16,185,129,0.15); color:#34d399; border:1px solid rgba(16,185,129,0.35);">PASS</span>';
    }
    const colors = {
        'CRITICAL': 'background:rgba(244,63,94,0.2); color:#fb7185; border:1px solid rgba(244,63,94,0.45);',
        'HIGH': 'background:rgba(245,158,11,0.2); color:#fbbf24; border:1px solid rgba(245,158,11,0.45);',
        'MEDIUM': 'background:rgba(99,102,241,0.2); color:#a5b4fc; border:1px solid rgba(99,102,241,0.45);',
        'LOW': 'background:rgba(56,189,248,0.2); color:#7dd3fc; border:1px solid rgba(56,189,248,0.45);',
        'INFO': 'background:rgba(148,163,184,0.15); color:#cbd5e1; border:1px solid rgba(148,163,184,0.3);'
    };
    return `<span class="badge" style="${colors[sev] || colors.INFO}">${escapeHtml(sev)} &bull; ${escapeHtml(st)}</span>`;
}

async function loadRegisteredTargets() {
    const select = document.getElementById('live-target-select');
    try {
        const res = await fetch('/api/live/targets');
        const data = await res.json();
        liveTargets = data.targets || [];

        if (liveTargets.length === 0) {
            select.innerHTML = '<option value="">No registered targets — register one on Live Targets page</option>';
            onTargetSelected();
            return;
        }

        const params = new URLSearchParams(window.location.search);
        const preselect = params.get('target');

        select.innerHTML = '<option value="">-- Select a registered website target --</option>' +
            liveTargets.map(t => {
                const label = `${t.domain} [${t.auth_status}] (${t.target_uuid})`;
                const selected = preselect && preselect === t.target_uuid ? 'selected' : '';
                return `<option value="${escapeHtml(t.target_uuid)}" ${selected}>${escapeHtml(label)}</option>`;
            }).join('');

        onTargetSelected();
    } catch (err) {
        select.innerHTML = `<option value="">Error loading targets: ${escapeHtml(err.message)}</option>`;
    }
}

function onTargetSelected() {
    const uuid = document.getElementById('live-target-select').value;
    const summaryEl = document.getElementById('selected-target-summary');
    const runBtn = document.getElementById('btn-run-live-scan');
    const pathInput = document.getElementById('live-scan-path');
    const errEl = document.getElementById('live-scan-error');
    errEl.style.display = 'none';

    const t = liveTargets.find(item => item.target_uuid === uuid);
    if (!t) {
        summaryEl.style.display = 'none';
        runBtn.disabled = true;
        return;
    }

    pathInput.value = (t.approved_paths && t.approved_paths[0]) ? t.approved_paths[0] : '/';
    summaryEl.style.display = 'flex';
    summaryEl.innerHTML = `
        <div>
            <strong style="color:#fff;">${escapeHtml(t.domain)}</strong> &nbsp; ${getAuthBadge(t.auth_status)}
            <div style="color:var(--text-secondary); margin-top:0.25rem;">
                Approved Paths: <code>${escapeHtml((t.approved_paths || []).join(', '))}</code> &bull;
                Allowed Methods: <code>${escapeHtml((t.allowed_methods || []).join(', '))}</code> &bull;
                Rate Limit: <strong>${escapeHtml(t.max_request_rate)} req/min</strong>
            </div>
        </div>
        <div style="text-align:right; font-family:var(--font-mono); font-size:0.78rem; color:var(--text-secondary);">
            <div>Valid Until: ${escapeHtml((t.expiry_date || '').slice(0, 19).replace('T', ' '))} UTC</div>
            <div style="color:${t.is_scannable ? 'var(--accent-emerald)' : '#fb7185'}; font-weight:600; margin-top:0.2rem;">
                ${t.is_scannable ? '✓ Ready for Authorized Live Assessment' : '✕ Blocked — Target must be Verified, Approved & Active'}
            </div>
        </div>
    `;
    runBtn.disabled = !t.is_scannable;
}

function setProgress(percent, stepText) {
    const card = document.getElementById('live-progress-card');
    card.style.display = 'block';
    document.getElementById('progress-percent-label').textContent = `${percent}%`;
    document.getElementById('progress-bar-fill').style.width = `${percent}%`;
    document.getElementById('progress-step-label').textContent = stepText;
}

async function triggerLiveAssessment() {
    const targetUuid = document.getElementById('live-target-select').value;
    const scanPath = document.getElementById('live-scan-path').value.trim() || '/';
    const errEl = document.getElementById('live-scan-error');
    const runBtn = document.getElementById('btn-run-live-scan');

    if (!targetUuid) return;
    errEl.style.display = 'none';
    runBtn.disabled = true;

    setProgress(15, 'Validating authorization, expiry, DNS resolution, and SSRF policy...');
    const stepTimer = setTimeout(() => setProgress(55, 'Inspecting live TLS certificate, HTTPS redirects, headers, and cookie flags...'), 700);

    try {
        const res = await fetch('/api/live/assessments/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_uuid: targetUuid, path: scanPath })
        });
        clearTimeout(stepTimer);
        const data = await res.json();

        if (!res.ok) {
            document.getElementById('live-progress-card').style.display = 'none';
            errEl.style.display = 'block';
            errEl.innerHTML = `<strong>Assessment Blocked (${escapeHtml(data.error_type || 'ERROR')}):</strong> ${escapeHtml(data.message)}`;
            await loadLiveAuditLogs();
            await loadRegisteredTargets();
            return;
        }

        setProgress(100, 'Assessment completed and persisted to SQLite.');
        renderLiveAssessment(data.assessment);
        await loadLiveHistory();
        await loadLiveAuditLogs();
        setTimeout(() => {
            document.getElementById('live-progress-card').style.display = 'none';
        }, 1200);
    } catch (err) {
        clearTimeout(stepTimer);
        document.getElementById('live-progress-card').style.display = 'none';
        errEl.style.display = 'block';
        errEl.textContent = `Request error: ${err.message}`;
    } finally {
        onTargetSelected();
    }
}

function renderLiveAssessment(assessment) {
    currentLiveAssessment = assessment;
    document.getElementById('live-results-section').style.display = 'block';

    const score = assessment.security_score ?? 0;
    const grade = assessment.security_grade || 'N/A';
    const gradeBadge = document.getElementById('live-result-grade-badge');
    gradeBadge.textContent = `Grade ${grade} (${score}/100)`;
    if (score >= 80) {
        gradeBadge.style.cssText = 'background:rgba(16,185,129,0.2); color:#34d399; border:1px solid rgba(16,185,129,0.45);';
    } else if (score >= 60) {
        gradeBadge.style.cssText = 'background:rgba(245,158,11,0.2); color:#fbbf24; border:1px solid rgba(245,158,11,0.45);';
    } else {
        gradeBadge.style.cssText = 'background:rgba(244,63,94,0.2); color:#fb7185; border:1px solid rgba(244,63,94,0.45);';
    }

    const meta = assessment.metadata || {};
    document.getElementById('live-result-meta').textContent =
        `Target: ${assessment.target_url} • Resolved IP: ${meta.resolved_ip || 'N/A'} • TLS: ${meta.tls_version || 'N/A'} • Run ID: ${assessment.assessment_uuid} • Completed: ${(assessment.completed_at || '').slice(0, 19).replace('T', ' ')} UTC`;

    document.getElementById('live-kpi-score').innerHTML = `${score}<span style="font-size:0.9rem; color:var(--text-muted);">/100</span>`;
    document.getElementById('live-kpi-passed').textContent = assessment.passed_checks ?? 0;
    document.getElementById('live-kpi-failed').textContent = assessment.failed_checks ?? 0;
    document.getElementById('live-kpi-critical').textContent = assessment.critical_count ?? 0;
    document.getElementById('live-kpi-high').textContent = assessment.high_count ?? 0;
    document.getElementById('live-kpi-medium').textContent = assessment.medium_count ?? 0;
    document.getElementById('live-kpi-low').textContent = assessment.low_count ?? 0;

    const remBtn = document.getElementById('btn-open-remediation');
    if (remBtn && assessment.target_uuid) {
        remBtn.href = `/live-remediation?target=${encodeURIComponent(assessment.target_uuid)}`;
    }

    renderFindingsList();
}

function filterLiveFindings(mode) {
    currentLiveFilter = mode;
    renderFindingsList();
}

function renderFindingsList() {
    if (!currentLiveAssessment) return;
    const container = document.getElementById('live-findings-container');
    let findings = currentLiveAssessment.findings || [];

    if (currentLiveFilter === 'failed') {
        findings = findings.filter(f => ['FAIL', 'WARNING', 'WARN', 'VULNERABLE'].includes((f.status || '').toUpperCase()));
    } else if (currentLiveFilter === 'passed') {
        findings = findings.filter(f => ['PASS', 'DEFENDED'].includes((f.status || '').toUpperCase()));
    }

    if (findings.length === 0) {
        container.innerHTML = '<div class="card" style="text-align:center; color:var(--text-muted);">No findings match the selected filter.</div>';
        return;
    }

    container.innerHTML = findings.map(f => {
        const isPass = ['PASS', 'DEFENDED'].includes((f.status || '').toUpperCase());
        const borderAccent = isPass ? 'rgba(16,185,129,0.35)' : (
            f.severity === 'CRITICAL' ? 'rgba(244,63,94,0.5)' :
            f.severity === 'HIGH' ? 'rgba(245,158,11,0.45)' : 'rgba(99,102,241,0.4)'
        );
        return `
            <div class="card" style="border-left: 4px solid ${borderAccent}; padding: 1.15rem 1.35rem;">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem; margin-bottom:0.65rem;">
                    <div>
                        <span style="font-size:0.72rem; color:var(--accent-cyan); text-transform:uppercase; font-weight:600;">${escapeHtml(f.category)}</span>
                        <h4 style="color:#fff; font-size:1rem; margin-top:0.1rem;">${escapeHtml(f.title)}</h4>
                    </div>
                    ${getSeverityBadge(f.severity, f.status)}
                </div>
                <div style="background:rgba(0,0,0,0.25); padding:0.7rem 0.9rem; border-radius:var(--radius-sm); font-family:var(--font-mono); font-size:0.8rem; color:var(--text-primary); margin-bottom:0.65rem;">
                    <strong style="color:var(--text-secondary);">Evidence:</strong> ${escapeHtml(f.evidence)}
                </div>
                <div style="font-size:0.84rem; color:var(--text-secondary); line-height:1.5;">
                    <strong style="color:var(--accent-emerald);">Remediation Recommendation:</strong> ${escapeHtml(f.remediation)}
                </div>
            </div>
        `;
    }).join('');
}

async function loadLiveHistory() {
    const tbody = document.getElementById('live-history-body');
    try {
        const res = await fetch('/api/live/assessments?limit=25');
        const data = await res.json();
        const rows = data.assessments || [];

        if (rows.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--text-muted); padding:1.25rem;">No live assessments recorded yet.</td></tr>';
            return;
        }

        tbody.innerHTML = rows.map(a => `
            <tr>
                <td style="font-family:var(--font-mono); font-size:0.8rem;">${escapeHtml(a.assessment_uuid)}</td>
                <td>
                    <div style="font-weight:600; color:#fff;">${escapeHtml(a.domain)}</div>
                    <div style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-muted);">${escapeHtml(a.target_url)}</div>
                </td>
                <td style="font-family:var(--font-mono); font-size:0.78rem;">${escapeHtml((a.started_at || '').slice(0, 19).replace('T', ' '))}</td>
                <td><strong>${escapeHtml(a.security_score)}/100</strong> <span class="badge">${escapeHtml(a.security_grade)}</span></td>
                <td><span style="color:var(--accent-emerald);">${a.passed_checks}</span> / <span style="color:#fb7185;">${a.failed_checks}</span></td>
                <td style="font-family:var(--font-mono); font-size:0.8rem;">
                    <span style="color:#f43f5e;">${a.critical_count}</span> /
                    <span style="color:var(--accent-amber);">${a.high_count}</span> /
                    <span style="color:var(--accent-indigo);">${a.medium_count}</span> /
                    <span style="color:var(--accent-blue);">${a.low_count}</span>
                </td>
                <td>
                    <button class="btn btn-secondary btn-sm" onclick="inspectLiveAssessment('${escapeHtml(a.assessment_uuid)}')">Inspect</button>
                </td>
            </tr>
        `).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="7" style="color:#fb7185; text-align:center;">Failed to load history: ${escapeHtml(err.message)}</td></tr>`;
    }
}

async function inspectLiveAssessment(assessmentUuid) {
    try {
        const res = await fetch(`/api/live/assessments/${encodeURIComponent(assessmentUuid)}`);
        const data = await res.json();
        if (res.ok && data.assessment) {
            renderLiveAssessment(data.assessment);
            document.getElementById('live-results-section').scrollIntoView({ behavior: 'smooth' });
        }
    } catch (err) {
        console.error('Failed to load live assessment detail', err);
    }
}

async function loadLiveAuditLogs() {
    const tbody = document.getElementById('live-audit-body');
    try {
        const res = await fetch('/api/live/audit-logs?limit=30');
        const data = await res.json();
        const logs = data.logs || [];

        if (logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:1.25rem;">No live testing audit logs yet.</td></tr>';
            return;
        }

        tbody.innerHTML = logs.map(l => {
            const outcomeColor = (l.outcome === 'BLOCKED' || l.outcome === 'REJECTED' || l.outcome === 'FAILED')
                ? '#fb7185'
                : (l.outcome === 'EXPIRED' ? '#fbbf24' : '#34d399');
            return `
                <tr>
                    <td style="font-family:var(--font-mono); font-size:0.76rem;">${escapeHtml((l.timestamp || '').slice(0, 19).replace('T', ' '))}</td>
                    <td style="font-family:var(--font-mono); font-size:0.78rem; color:#fff;">${escapeHtml(l.action)}</td>
                    <td><span class="badge" style="color:${outcomeColor}; border:1px solid ${outcomeColor}; background:rgba(255,255,255,0.03);">${escapeHtml(l.outcome)}</span></td>
                    <td style="font-family:var(--font-mono); font-size:0.78rem;">${escapeHtml(l.domain || '-')}${l.resolved_ip ? ` (${escapeHtml(l.resolved_ip)})` : ''}</td>
                    <td style="font-size:0.8rem; color:var(--text-secondary);">${escapeHtml(l.reason || l.url || '')}</td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" style="color:#fb7185; text-align:center;">Failed to load audit logs: ${escapeHtml(err.message)}</td></tr>`;
    }
}

function downloadLiveReport(fmt) {
    if (!currentLiveAssessment) return;
    const uuid = currentLiveAssessment.assessment_uuid;
    window.location.href = `/api/live/assessments/${encodeURIComponent(uuid)}/report?format=${encodeURIComponent(fmt || 'html')}`;
}

function exportLiveReportJson() {
    if (!currentLiveAssessment) return;
    downloadLiveReport('json');
}

document.addEventListener('DOMContentLoaded', () => {
    loadRegisteredTargets();
    loadLiveHistory();
    loadLiveAuditLogs();
});
