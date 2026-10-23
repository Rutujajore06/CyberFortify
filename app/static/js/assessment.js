// CyberFortify Website Security Assessment Controller

let currentAssessmentData = null;
let currentFilter = 'all';
let configuredDemoOrigin = 'http://127.0.0.1:5000';

document.addEventListener('DOMContentLoaded', () => {
    loadScopeConfig();
    loadAssessmentHistory();
});

async function loadScopeConfig() {
    try {
        const res = await fetch('/api/assessment/config');
        const data = await res.json();
        if (data.status === 'success' && data.demo_origin) {
            configuredDemoOrigin = data.demo_origin;
            const originEl = document.getElementById('scope-target-origin');
            if (originEl) {
                originEl.innerText = configuredDemoOrigin;
            }
            const inputEl = document.getElementById('target-url-input');
            if (inputEl) {
                inputEl.placeholder = configuredDemoOrigin;
                if (!inputEl.value || !inputEl.value.trim()) {
                    inputEl.value = configuredDemoOrigin;
                }
            }
        }
    } catch (err) {
        console.warn('Could not load assessment scope config:', err);
    }
}

async function loadAssessmentHistory() {
    try {
        const res = await fetch('/api/assessment/history?limit=10');
        const data = await res.json();
        const tbody = document.getElementById('assessment-history-body');
        const badge = document.getElementById('history-badge');

        if (!data || data.status !== 'success' || !data.assessments || data.assessments.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted);">No assessments recorded yet. Run your first assessment above!</td></tr>`;
            if (badge) badge.innerText = '0 runs';
            return;
        }

        if (badge) badge.innerText = `${data.count} recent runs`;

        tbody.innerHTML = data.assessments.map(a => {
            const statusBadgeClass = a.overall_status === 'FORTIFIED' ? 'badge-low' : (a.overall_status === 'PARTIALLY_FORTIFIED' ? 'badge-high' : 'badge-critical');
            const dateStr = a.timestamp ? new Date(a.timestamp).toLocaleString() : 'N/A';
            return `
                <tr>
                    <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--accent-cyan);">${a.assessment_uuid}</td>
                    <td style="color: var(--text-secondary); font-size: 0.8rem;">${dateStr}</td>
                    <td style="font-family: var(--font-mono); font-size: 0.8rem;">${escapeHtml(a.target_url)}</td>
                    <td><span class="badge ${statusBadgeClass}">${a.overall_status}</span></td>
                    <td style="color: var(--accent-emerald); font-weight: 600;">${a.passed_checks}</td>
                    <td style="color: #fb7185; font-weight: 600;">${a.failed_checks}</td>
                    <td>
                        <button class="btn btn-secondary btn-sm" onclick="inspectPastAssessment('${a.assessment_uuid}')">
                            View Report
                        </button>
                    </td>
                </tr>
            `;
        }).join('');

        // If results section is not yet populated, render the latest assessment
        if (!currentAssessmentData && data.assessments.length > 0) {
            inspectPastAssessment(data.assessments[0].assessment_uuid);
        }

    } catch (err) {
        console.error('Error loading assessment history:', err);
    }
}

async function triggerAssessment() {
    const urlInput = document.getElementById('target-url-input');
    const rawUrl = urlInput.value.trim();
    const btn = document.getElementById('btn-run-assessment');
    const loader = document.getElementById('assessment-loader');
    const resultsContainer = document.getElementById('assessment-results');
    const errorBox = document.getElementById('scope-error-container');
    const errorMsg = document.getElementById('scope-error-message');

    // Reset error state
    errorBox.style.display = 'none';

    if (!rawUrl) {
        showScopeError(`Target URL cannot be empty. Please enter the Fortress Bank demo URL (e.g., ${configuredDemoOrigin}).`);
        return;
    }

    // Set UI to loading state
    btn.disabled = true;
    btn.innerHTML = `<span>⏳ Evaluating...</span>`;
    loader.style.display = 'block';
    resultsContainer.style.display = 'none';

    try {
        const res = await fetch('/api/assessment/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: rawUrl })
        });

        const data = await res.json();

        loader.style.display = 'none';
        btn.disabled = false;
        btn.innerHTML = `<span>🛡️ Assess Demo</span>`;

        if (!res.ok || data.status === 'error') {
            showScopeError(data.message || 'Assessment rejected by scope enforcer.');
            return;
        }

        currentAssessmentData = data.assessment;
        renderAssessment(data.assessment);
        loadAssessmentHistory();

    } catch (err) {
        loader.style.display = 'none';
        btn.disabled = false;
        btn.innerHTML = `<span>🛡️ Assess Demo</span>`;
        showScopeError(`Network or execution error: ${err.message}`);
    }
}

function showScopeError(msg) {
    const errorBox = document.getElementById('scope-error-container');
    const errorMsg = document.getElementById('scope-error-message');
    errorMsg.innerText = msg;
    errorBox.style.display = 'block';
}

function resetDemoUrl() {
    document.getElementById('target-url-input').value = configuredDemoOrigin;
    document.getElementById('scope-error-container').style.display = 'none';
}

async function inspectPastAssessment(uuid) {
    try {
        const res = await fetch(`/api/assessment/${uuid}`);
        const data = await res.json();
        if (data.status === 'success' && data.assessment) {
            currentAssessmentData = data.assessment;
            renderAssessment(data.assessment);
            // Smoothly scroll to results
            document.getElementById('assessment-results').scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    } catch (err) {
        console.error('Error fetching past assessment:', err);
    }
}

function renderAssessment(assessment) {
    const resultsContainer = document.getElementById('assessment-results');
    resultsContainer.style.display = 'block';

    // Status Badge
    const badge = document.getElementById('results-status-badge');
    const status = assessment.overall_status || 'UNKNOWN';
    badge.innerText = status;
    badge.className = 'badge ' + (status === 'FORTIFIED' ? 'badge-low' : (status === 'PARTIALLY_FORTIFIED' ? 'badge-high' : 'badge-critical'));

    // Metadata Text
    const dateStr = assessment.timestamp ? new Date(assessment.timestamp).toUTCString() : 'N/A';
    document.getElementById('results-meta-text').innerHTML = `
        Target: <code style="color: var(--accent-cyan);">${escapeHtml(assessment.target_url)}</code> &bull; 
        Scope: <strong>${escapeHtml(assessment.scope_target)}</strong> &bull; 
        Run UUID: <code>${assessment.assessment_uuid}</code> &bull; 
        Evaluated: ${dateStr}
    `;

    // Counts
    const findings = assessment.findings || [];
    document.getElementById('metric-total-checks').innerText = assessment.total_checks || findings.length;
    document.getElementById('metric-passed-checks').innerText = assessment.passed_checks || 0;
    document.getElementById('metric-failed-checks').innerText = assessment.failed_checks || 0;

    let critical = 0, high = 0, medium = 0, info = 0;
    findings.forEach(f => {
        const sev = (f.severity || '').toUpperCase();
        if (sev === 'CRITICAL') critical++;
        else if (sev === 'HIGH') high++;
        else if (sev === 'MEDIUM') medium++;
        else info++;
    });

    document.getElementById('metric-critical-count').innerText = critical;
    document.getElementById('metric-high-count').innerText = high;
    document.getElementById('metric-medium-count').innerText = medium;
    document.getElementById('metric-info-count').innerText = info;

    renderFindingsCards(findings);
}

function renderFindingsCards(findings) {
    const container = document.getElementById('findings-container');

    const filtered = findings.filter(f => {
        if (currentFilter === 'vulnerable') return f.status === 'VULNERABLE' || f.status === 'WARNING';
        if (currentFilter === 'defended') return f.status === 'DEFENDED' || f.status === 'PASS';
        return true;
    });

    if (filtered.length === 0) {
        container.innerHTML = `<div class="card" style="text-align: center; color: var(--text-muted); padding: 2rem;">No findings match the selected filter.</div>`;
        return;
    }

    container.innerHTML = filtered.map(f => {
        const isVuln = f.status === 'VULNERABLE' || f.status === 'WARNING';
        const borderColor = isVuln ? (f.severity === 'CRITICAL' ? 'rgba(244, 63, 94, 0.4)' : 'rgba(245, 158, 11, 0.4)') : 'rgba(16, 185, 129, 0.3)';
        const cardBg = isVuln ? 'rgba(17, 28, 51, 0.7)' : 'rgba(13, 21, 39, 0.7)';

        const sevBadgeClass = 
            f.severity === 'CRITICAL' ? 'badge-critical' :
            f.severity === 'HIGH' ? 'badge-high' :
            f.severity === 'MEDIUM' ? 'badge-medium' :
            f.severity === 'LOW' ? 'badge-low' : 'badge-benign';

        const statusBadgeClass = isVuln ? 'badge-critical' : 'badge-low';

        return `
            <div class="card" style="border-color: ${borderColor}; background: ${cardBg};">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 0.75rem;">
                    <div>
                        <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.25rem;">
                            <span class="badge ${sevBadgeClass}">${f.severity}</span>
                            <span class="badge ${statusBadgeClass}">${f.status}</span>
                            <span style="color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; font-weight: 600;">${escapeHtml(f.category)}</span>
                        </div>
                        <h4 style="color: #fff; font-size: 1.05rem; font-weight: 600; margin-top: 0.25rem;">${escapeHtml(f.title)}</h4>
                    </div>
                </div>

                <!-- Observed Evidence -->
                <div style="margin-bottom: 0.85rem;">
                    <div style="font-size: 0.75rem; color: var(--accent-cyan); text-transform: uppercase; font-weight: 600; margin-bottom: 0.35rem; display: flex; align-items: center; gap: 0.4rem;">
                        <span>🔎</span> Observed Evidence:
                    </div>
                    <div class="code-preview" style="color: #e2e8f0; font-size: 0.825rem; line-height: 1.5; background: #060a14;">
                        ${escapeHtml(f.evidence)}
                    </div>
                </div>

                <!-- Remediation Guidance -->
                <div>
                    <div style="font-size: 0.75rem; color: var(--accent-emerald); text-transform: uppercase; font-weight: 600; margin-bottom: 0.35rem; display: flex; align-items: center; gap: 0.4rem;">
                        <span>⚡</span> Recommended Remediation:
                    </div>
                    <div style="color: var(--text-secondary); font-size: 0.85rem; line-height: 1.5; background: rgba(255, 255, 255, 0.02); padding: 0.65rem 0.85rem; border-radius: var(--radius-sm); border-left: 3px solid ${isVuln ? 'var(--accent-amber)' : 'var(--accent-emerald)'};">
                        ${escapeHtml(f.remediation)}
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function filterFindings(filterType) {
    currentFilter = filterType;
    ['all', 'vulnerable', 'defended'].forEach(id => {
        const el = document.getElementById(`filter-${id}`);
        if (el) {
            if (id === filterType) {
                el.classList.add('btn-primary');
                el.classList.remove('btn-secondary');
            } else {
                el.classList.remove('btn-primary');
                el.classList.add('btn-secondary');
            }
        }
    });

    if (currentAssessmentData && currentAssessmentData.findings) {
        renderFindingsCards(currentAssessmentData.findings);
    }
}

function exportFindingsJson() {
    if (!currentAssessmentData) return;
    const blob = new Blob([JSON.stringify(currentAssessmentData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cyberfortify_assessment_${currentAssessmentData.assessment_uuid || 'export'}.json`;
    a.click();
    URL.revokeObjectURL(url);
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
