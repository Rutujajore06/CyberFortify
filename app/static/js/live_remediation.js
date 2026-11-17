/**
 * CyberFortify - Live Vulnerability Remediation & Retesting Controller
 */

let remTargets = [];
let currentRemediations = [];
let currentRemFilter = 'all';
let latestAssessmentUuidForReport = null;

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function showRemBanner(message, isError = false) {
    const el = document.getElementById('rem-feedback-banner');
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

function hideRemBanner() {
    const el = document.getElementById('rem-feedback-banner');
    if (el) el.style.display = 'none';
}

function getRemStatusBadge(status) {
    const styles = {
        'Open': 'background:rgba(244,63,94,0.18); color:#fb7185; border:1px solid rgba(244,63,94,0.4);',
        'In Progress': 'background:rgba(245,158,11,0.18); color:#fbbf24; border:1px solid rgba(245,158,11,0.4);',
        'Fixed': 'background:rgba(56,189,248,0.18); color:#38bdf8; border:1px solid rgba(56,189,248,0.4);',
        'Verified': 'background:rgba(16,185,129,0.2); color:#34d399; border:1px solid rgba(16,185,129,0.45);'
    };
    return `<span class="badge" style="${styles[status] || ''}">${escapeHtml(status)}</span>`;
}

function getSeverityBadge(severity, findingStatus) {
    const sev = (severity || 'INFO').toUpperCase();
    const st = (findingStatus || '').toUpperCase();
    if (st === 'PASS' || st === 'DEFENDED') {
        return '<span class="badge" style="background:rgba(16,185,129,0.18); color:#34d399; border:1px solid rgba(16,185,129,0.4);">PASS</span>';
    }
    const colors = {
        'CRITICAL': 'background:rgba(244,63,94,0.22); color:#fb7185; border:1px solid rgba(244,63,94,0.5);',
        'HIGH': 'background:rgba(245,158,11,0.22); color:#fbbf24; border:1px solid rgba(245,158,11,0.5);',
        'MEDIUM': 'background:rgba(99,102,241,0.22); color:#a5b4fc; border:1px solid rgba(99,102,241,0.5);',
        'LOW': 'background:rgba(56,189,248,0.22); color:#7dd3fc; border:1px solid rgba(56,189,248,0.5);'
    };
    return `<span class="badge" style="${colors[sev] || ''}">${escapeHtml(sev)} &bull; ${escapeHtml(st)}</span>`;
}

async function loadTargetsForRemediation() {
    const select = document.getElementById('rem-target-select');
    try {
        const res = await fetch('/api/live/targets');
        const data = await res.json();
        remTargets = data.targets || [];

        if (remTargets.length === 0) {
            select.innerHTML = '<option value="">No registered targets available</option>';
            onRemTargetChanged();
            return;
        }

        const params = new URLSearchParams(window.location.search);
        const preselect = params.get('target');
        const defaultTarget = preselect || (remTargets.find(t => t.auth_status === 'APPROVED') || remTargets[0]).target_uuid;

        select.innerHTML = '<option value="">-- Select a target --</option>' +
            remTargets.map(t => {
                const selected = t.target_uuid === defaultTarget ? 'selected' : '';
                return `<option value="${escapeHtml(t.target_uuid)}" ${selected}>${escapeHtml(t.domain)} [${escapeHtml(t.auth_status)}] (${escapeHtml(t.target_uuid)})</option>`;
            }).join('');

        await onRemTargetChanged();
    } catch (err) {
        select.innerHTML = `<option value="">Error loading targets: ${escapeHtml(err.message)}</option>`;
    }
}

async function onRemTargetChanged() {
    hideRemBanner();
    const targetUuid = document.getElementById('rem-target-select').value;
    const retestBtn = document.getElementById('btn-run-retest');
    const pathInput = document.getElementById('rem-retest-path');

    const target = remTargets.find(t => t.target_uuid === targetUuid);
    if (!target) {
        retestBtn.disabled = true;
        setReportButtonsEnabled(false);
        document.getElementById('comparison-section').style.display = 'none';
        document.getElementById('remediations-list').innerHTML =
            '<div class="card" style="text-align:center; color:var(--text-muted);">Select a target to view findings and remediation tracker.</div>';
        return;
    }

    retestBtn.disabled = !target.is_scannable;
    pathInput.value = (target.approved_paths && target.approved_paths[0]) ? target.approved_paths[0] : '/';

    await Promise.all([
        loadRemediations(targetUuid),
        loadComparison(targetUuid),
        loadTargetHistory(targetUuid)
    ]);
}

function setReportButtonsEnabled(enabled) {
    ['btn-dl-html', 'btn-dl-md', 'btn-dl-json'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.disabled = !enabled;
    });
}

async function loadRemediations(targetUuid) {
    try {
        const res = await fetch(`/api/live/remediations?target_uuid=${encodeURIComponent(targetUuid)}`);
        const data = await res.json();
        if (!res.ok) {
            showRemBanner(escapeHtml(data.message || 'Failed to load remediations.'), true);
            return;
        }
        const s = data.summary || {};
        document.getElementById('rem-kpi-open').textContent = s.open || 0;
        document.getElementById('rem-kpi-inprogress').textContent = s.in_progress || 0;
        document.getElementById('rem-kpi-fixed').textContent = s.fixed || 0;
        document.getElementById('rem-kpi-verified').textContent = s.verified || 0;

        currentRemediations = data.remediations || [];
        renderRemediationCards();
    } catch (err) {
        showRemBanner(`Error loading remediations: ${escapeHtml(err.message)}`, true);
    }
}

function filterRemediations(status) {
    currentRemFilter = status;
    renderRemediationCards();
}

function renderRemediationCards() {
    const container = document.getElementById('remediations-list');
    let items = currentRemediations;
    if (currentRemFilter !== 'all') {
        items = items.filter(r => r.remediation_status === currentRemFilter);
    }

    if (items.length === 0) {
        container.innerHTML = '<div class="card" style="text-align:center; color:var(--text-muted);">No tracked vulnerabilities match this filter (or run an initial live assessment first).</div>';
        return;
    }

    container.innerHTML = items.map(r => {
        const canConfirmVerified = r.retest_confirmed === true;
        const borderColor = r.remediation_status === 'Verified' || r.remediation_status === 'Fixed'
            ? 'rgba(16,185,129,0.45)'
            : (r.severity === 'CRITICAL' ? 'rgba(244,63,94,0.55)' :
               r.severity === 'HIGH' ? 'rgba(245,158,11,0.5)' : 'rgba(99,102,241,0.45)');

        return `
            <div class="card" style="border-left: 4px solid ${borderColor};">
                <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:0.75rem; margin-bottom:0.85rem;">
                    <div>
                        <div style="display:flex; align-items:center; gap:0.5rem; flex-wrap:wrap; margin-bottom:0.3rem;">
                            <span style="font-size:0.72rem; color:var(--accent-cyan); text-transform:uppercase; font-weight:600;">${escapeHtml(r.category)}</span>
                            <span style="font-family:var(--font-mono); font-size:0.75rem; background:rgba(0,242,254,0.09); color:#7dd3fc; padding:0.15rem 0.5rem; border-radius:4px; border:1px solid rgba(0,242,254,0.22);">
                                Header / Surface: ${escapeHtml(r.affected_header)}
                            </span>
                        </div>
                        <h3 style="color:#fff; font-size:1.05rem;">${escapeHtml(r.title)}</h3>
                    </div>
                    <div style="display:flex; gap:0.45rem; align-items:center; flex-wrap:wrap;">
                        ${getSeverityBadge(r.severity, r.finding_status)}
                        ${getRemStatusBadge(r.remediation_status)}
                    </div>
                </div>

                <div style="background:rgba(0,0,0,0.25); padding:0.75rem 0.9rem; border-radius:var(--radius-sm); font-family:var(--font-mono); font-size:0.8rem; color:var(--text-primary); margin-bottom:0.75rem;">
                    <strong style="color:var(--text-secondary);">Latest Observed Evidence:</strong> ${escapeHtml(r.evidence)}
                </div>

                <div style="background:rgba(16,185,129,0.05); border:1px solid rgba(16,185,129,0.2); padding:0.75rem 0.9rem; border-radius:var(--radius-sm); font-size:0.84rem; color:var(--text-secondary); margin-bottom:0.9rem; line-height:1.55;">
                    <strong style="color:var(--accent-emerald);">Remediation Instructions (Owner Action):</strong> ${escapeHtml(r.remediation_instructions)}
                </div>

                <div style="display:grid; grid-template-columns: 220px 1fr auto; gap:0.75rem; align-items:end; flex-wrap:wrap;">
                    <div>
                        <label style="display:block; font-size:0.75rem; color:var(--text-secondary); margin-bottom:0.25rem;">Remediation Status</label>
                        <select id="status-${escapeHtml(r.remediation_uuid)}"
                                style="width:100%; padding:0.55rem 0.7rem; background:var(--bg-input); border:1px solid var(--border-color); color:#fff; border-radius:var(--radius-sm); font-size:0.84rem;">
                            <option value="Open" ${r.remediation_status === 'Open' ? 'selected' : ''}>Open</option>
                            <option value="In Progress" ${r.remediation_status === 'In Progress' ? 'selected' : ''}>In Progress</option>
                            <option value="Fixed" ${r.remediation_status === 'Fixed' ? 'selected' : ''} ${canConfirmVerified ? '' : 'disabled'}>Fixed (Requires Passing Retest)</option>
                            <option value="Verified" ${r.remediation_status === 'Verified' ? 'selected' : ''} ${canConfirmVerified ? '' : 'disabled'}>Verified (Requires Passing Retest)</option>
                        </select>
                    </div>
                    <div>
                        <label style="display:block; font-size:0.75rem; color:var(--text-secondary); margin-bottom:0.25rem;">Owner Remediation Notes</label>
                        <input type="text" id="notes-${escapeHtml(r.remediation_uuid)}" value="${escapeHtml(r.remediation_notes || '')}"
                               placeholder="Record configuration change applied (e.g., Added CSP header in vercel.json)..."
                               style="width:100%; padding:0.55rem 0.75rem; background:var(--bg-input); border:1px solid var(--border-color); color:#fff; border-radius:var(--radius-sm); font-size:0.84rem;">
                    </div>
                    <div>
                        <button class="btn btn-secondary btn-sm" onclick="saveRemediation('${escapeHtml(r.remediation_uuid)}')">💾 Save</button>
                    </div>
                </div>

                <div style="margin-top:0.65rem; font-size:0.73rem; color:var(--text-muted); font-family:var(--font-mono); display:flex; gap:1rem; flex-wrap:wrap;">
                    <span>First Detected: ${escapeHtml(r.first_detected_assessment_uuid)}</span>
                    <span>Latest Check: ${escapeHtml(r.latest_assessment_uuid)}</span>
                    ${r.verified_assessment_uuid ? `<span style="color:var(--accent-emerald);">Retest Confirmed: ${escapeHtml(r.verified_assessment_uuid)}</span>` : '<span>Retest Confirmed: Pending real retest</span>'}
                </div>
            </div>
        `;
    }).join('');
}

async function saveRemediation(remediationUuid) {
    hideRemBanner();
    const statusEl = document.getElementById(`status-${remediationUuid}`);
    const notesEl = document.getElementById(`notes-${remediationUuid}`);
    const targetUuid = document.getElementById('rem-target-select').value;

    try {
        const res = await fetch(`/api/live/remediations/${encodeURIComponent(remediationUuid)}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                remediation_status: statusEl.value,
                remediation_notes: notesEl.value
            })
        });
        const data = await res.json();
        if (!res.ok) {
            showRemBanner(`<strong>Update Blocked (${escapeHtml(data.error_type || 'ERROR')}):</strong> ${escapeHtml(data.message)}`, true);
            await loadRemediations(targetUuid);
            return;
        }
        showRemBanner(`<strong>Saved:</strong> ${escapeHtml(data.message)}`, false);
        await loadRemediations(targetUuid);
    } catch (err) {
        showRemBanner(`Error saving remediation: ${escapeHtml(err.message)}`, true);
    }
}

async function loadComparison(targetUuid) {
    const section = document.getElementById('comparison-section');
    try {
        const res = await fetch(`/api/live/assessments/compare?target_uuid=${encodeURIComponent(targetUuid)}`);
        const data = await res.json();
        if (!res.ok || !data.has_assessments || !data.comparison) {
            section.style.display = 'none';
            latestAssessmentUuidForReport = null;
            setReportButtonsEnabled(false);
            return;
        }
        renderComparison(data.comparison);
    } catch (err) {
        section.style.display = 'none';
    }
}

function renderComparison(cmp) {
    const section = document.getElementById('comparison-section');
    section.style.display = 'block';

    const before = cmp.before;
    const after = cmp.after;
    latestAssessmentUuidForReport = after.assessment_uuid;
    setReportButtonsEnabled(true);

    document.getElementById('comparison-meta').textContent = before
        ? `Comparing Previous (${before.assessment_uuid}) → Latest (${after.assessment_uuid})`
        : `Baseline recorded (${after.assessment_uuid}). Apply fixes on your target website and click Retest to compare before-and-after results.`;

    const verdictBadge = document.getElementById('comparison-verdict-badge');
    verdictBadge.textContent = cmp.verdict.replace(/_/g, ' ');
    if (cmp.verdict === 'ALL_VULNERABILITIES_REMEDIATED' || cmp.verdict === 'SECURITY_POSTURE_IMPROVED') {
        verdictBadge.style.cssText = 'background:rgba(16,185,129,0.2); color:#34d399; border:1px solid rgba(16,185,129,0.45);';
    } else if (cmp.verdict === 'SECURITY_POSTURE_REGRESSED') {
        verdictBadge.style.cssText = 'background:rgba(244,63,94,0.2); color:#fb7185; border:1px solid rgba(244,63,94,0.45);';
    } else {
        verdictBadge.style.cssText = 'background:rgba(99,102,241,0.2); color:#a5b4fc; border:1px solid rgba(99,102,241,0.45);';
    }

    document.getElementById('cmp-before-score').textContent = before ? `${before.security_score}/100 (${before.security_grade})` : 'N/A';
    document.getElementById('cmp-before-id').textContent = before ? before.assessment_uuid : 'Initial baseline only';
    document.getElementById('cmp-after-score').textContent = `${after.security_score}/100 (${after.security_grade})`;
    document.getElementById('cmp-after-id').textContent = after.assessment_uuid;

    const deltaEl = document.getElementById('cmp-score-delta');
    const delta = cmp.score_delta || 0;
    deltaEl.textContent = before ? (delta > 0 ? `+${delta}` : `${delta}`) : '0';
    deltaEl.style.color = delta > 0 ? 'var(--accent-emerald)' : (delta < 0 ? '#fb7185' : '#94a3b8');

    document.getElementById('cmp-fixed-count').textContent = cmp.summary.fixed_count;
    document.getElementById('cmp-remaining-count').textContent = cmp.summary.remaining_count + cmp.summary.new_or_regressed_count;
    document.getElementById('cmp-new-sub').textContent = `New / Regressed: ${cmp.summary.new_or_regressed_count}`;

    const fixedList = document.getElementById('cmp-fixed-list');
    if (cmp.fixed_vulnerabilities.length === 0) {
        fixedList.innerHTML = '<li style="color:var(--text-muted);">No newly fixed vulnerabilities confirmed yet.</li>';
    } else {
        fixedList.innerHTML = cmp.fixed_vulnerabilities.map(f =>
            `<li><strong style="color:#fff;">${escapeHtml(f.title)}</strong> (<code>${escapeHtml(f.affected_header)}</code>) &mdash; Confirmed Fixed</li>`
        ).join('');
    }

    const remList = document.getElementById('cmp-remaining-list');
    const stillOpen = [...(cmp.remaining_vulnerabilities || []), ...(cmp.new_vulnerabilities || [])];
    if (stillOpen.length === 0) {
        remList.innerHTML = '<li style="color:var(--accent-emerald);">None — all checks passed!</li>';
    } else {
        remList.innerHTML = stillOpen.map(f =>
            `<li><strong style="color:#fff;">${escapeHtml(f.title)}</strong> (<code>${escapeHtml(f.affected_header)}</code>) &mdash; ${escapeHtml(f.severity)} (${escapeHtml(f.current_status)})</li>`
        ).join('');
    }
}

async function triggerLiveRetest() {
    hideRemBanner();
    const targetUuid = document.getElementById('rem-target-select').value;
    const scanPath = document.getElementById('rem-retest-path').value.trim() || '/';
    const btn = document.getElementById('btn-run-retest');

    if (!targetUuid) return;
    btn.disabled = true;
    btn.innerHTML = '<span>⏳ Retesting Live Target...</span>';

    try {
        const res = await fetch('/api/live/retest/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_uuid: targetUuid, path: scanPath })
        });
        const data = await res.json();
        if (!res.ok) {
            showRemBanner(`<strong>Retest Blocked (${escapeHtml(data.error_type || 'ERROR')}):</strong> ${escapeHtml(data.message)}`, true);
            return;
        }
        showRemBanner(`<strong>Retest Complete:</strong> ${escapeHtml(data.message)}`, false);
        if (data.data && data.data.comparison) {
            renderComparison(data.data.comparison);
        }
        await loadRemediations(targetUuid);
        await loadTargetHistory(targetUuid);
    } catch (err) {
        showRemBanner(`Retest request error: ${escapeHtml(err.message)}`, true);
    } finally {
        btn.innerHTML = '<span>🔄 Retest Target</span>';
        const t = remTargets.find(item => item.target_uuid === targetUuid);
        btn.disabled = !(t && t.is_scannable);
    }
}

async function loadTargetHistory(targetUuid) {
    const tbody = document.getElementById('rem-history-body');
    try {
        const res = await fetch(`/api/live/assessments?target_uuid=${encodeURIComponent(targetUuid)}&limit=25`);
        const data = await res.json();
        const rows = data.assessments || [];
        if (rows.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted);">No assessments recorded for this target yet.</td></tr>';
            return;
        }
        tbody.innerHTML = rows.map(a => `
            <tr>
                <td style="font-family:var(--font-mono); font-size:0.8rem;">${escapeHtml(a.assessment_uuid)}</td>
                <td style="font-family:var(--font-mono); font-size:0.78rem;">${escapeHtml((a.started_at || '').slice(0, 19).replace('T', ' '))}</td>
                <td><span class="badge">${escapeHtml(a.status)}</span></td>
                <td><strong>${escapeHtml(a.security_score)}/100</strong> (${escapeHtml(a.security_grade)})</td>
                <td><span style="color:var(--accent-emerald);">${a.passed_checks}</span> / <span style="color:#fb7185;">${a.failed_checks}</span></td>
                <td>
                    <div style="display:flex; gap:0.35rem;">
                        <a href="/api/live/assessments/${encodeURIComponent(a.assessment_uuid)}/report?format=html" class="btn btn-secondary btn-sm">HTML</a>
                        <a href="/api/live/assessments/${encodeURIComponent(a.assessment_uuid)}/report?format=md" class="btn btn-secondary btn-sm">MD</a>
                        <a href="/api/live/assessments/${encodeURIComponent(a.assessment_uuid)}/report?format=json" class="btn btn-secondary btn-sm">JSON</a>
                    </div>
                </td>
            </tr>
        `).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" style="color:#fb7185; text-align:center;">Failed to load history: ${escapeHtml(err.message)}</td></tr>`;
    }
}

function downloadLatestReport(fmt) {
    if (!latestAssessmentUuidForReport) return;
    window.location.href = `/api/live/assessments/${encodeURIComponent(latestAssessmentUuidForReport)}/report?format=${encodeURIComponent(fmt)}`;
}

document.addEventListener('DOMContentLoaded', loadTargetsForRemediation);
