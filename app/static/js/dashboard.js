// CyberFortify Executive Dashboard Controller

let scenarioChart = null;
let severityChart = null;

async function loadDashboardMetrics() {
    try {
        // 1. Fetch Overall Evaluation KPIs
        const evalRes = await fetch('/api/evaluations/overall');
        const evalData = await evalRes.json();
        let scenarioBreakdown = null;
        if (evalData.status === 'success') {
            const m = evalData.metrics;
            document.getElementById('kpi-runs').innerText = m.total_runs || 0;
            document.getElementById('kpi-attacks').innerText = m.total_attacks || 0;
            document.getElementById('kpi-alerts').innerText = m.total_alerts || 0;
            document.getElementById('kpi-detection-rate').innerText = `${m.detection_rate || 0}%`;
            document.getElementById('kpi-latency').innerText = `${m.avg_latency_ms || 0} ms`;
            scenarioBreakdown = m.scenario_breakdown;
        }

        // 2. Fetch Severity Summary & Render Doughnut Chart
        const alertSumRes = await fetch('/api/alerts/summary');
        const alertSumData = await alertSumRes.json();
        if (alertSumData.status === 'success') {
            renderSeverityChart(alertSumData.summary);
        }

        // 3. Fetch Recent Runs & Render Scenario Coverage Chart
        const runsRes = await fetch('/api/simulations?limit=5');
        const runsData = await runsRes.json();
        if (runsData.status === 'success') {
            renderRecentRunsTable(runsData.runs);
            renderScenarioChart(scenarioBreakdown);
        }

        // 4. Fetch Recent Alerts
        const alertsRes = await fetch('/api/alerts?limit=5');
        const alertsData = await alertsRes.json();
        if (alertsData.status === 'success') {
            renderRecentAlertsTable(alertsData.alerts);
        }

    } catch (err) {
        console.error('Error loading dashboard data:', err);
    }
}

function renderSeverityChart(summary) {
    const ctx = document.getElementById('severityChart').getContext('2d');
    const labels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    const dataValues = [
        summary.CRITICAL || 0,
        summary.HIGH || 0,
        summary.MEDIUM || 0,
        summary.LOW || 0
    ];

    if (severityChart) {
        severityChart.destroy();
    }

    severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: dataValues,
                backgroundColor: [
                    '#f43f5e', // Critical (Rose)
                    '#f59e0b', // High (Amber)
                    '#818cf8', // Medium (Indigo)
                    '#10b981'  // Low (Emerald)
                ],
                borderColor: '#111c33',
                borderWidth: 2,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#94a3b8', font: { family: 'Inter', size: 12 } }
                }
            },
            cutout: '65%'
        }
    });
}

function renderScenarioChart(scenarioBreakdown) {
    const ctx = document.getElementById('scenarioChart').getContext('2d');

    // Scenarios and keys
    const scenarioLabels = ['Brute Force', 'Broken Access', 'SQL Injection', 'Input / XSS', 'Benign Baseline'];
    const scenarioKeys = ['brute_force', 'unauthorized_access', 'sql_injection', 'input_validation', 'benign'];

    let simulatedCounts = [5, 3, 4, 4, 4];
    let detectedCounts = [5, 3, 4, 4, 0];

    if (scenarioBreakdown && Object.keys(scenarioBreakdown).length > 0) {
        simulatedCounts = scenarioKeys.map(k => (scenarioBreakdown[k] ? scenarioBreakdown[k].attacks : 0));
        detectedCounts = scenarioKeys.map(k => (scenarioBreakdown[k] ? scenarioBreakdown[k].detected : 0));
    }

    if (scenarioChart) {
        scenarioChart.destroy();
    }

    scenarioChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: scenarioLabels,
            datasets: [
                {
                    label: 'Attacks Executed',
                    data: simulatedCounts,
                    backgroundColor: 'rgba(244, 63, 94, 0.75)',
                    borderColor: '#f43f5e',
                    borderWidth: 1,
                    borderRadius: 4
                },
                {
                    label: 'Alerts Triggered',
                    data: detectedCounts,
                    backgroundColor: 'rgba(0, 242, 254, 0.75)',
                    borderColor: '#00f2fe',
                    borderWidth: 1,
                    borderRadius: 4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#94a3b8' }
                },
                y: {
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#94a3b8', stepSize: 1 },
                    beginAtZero: true
                }
            },
            plugins: {
                legend: {
                    position: 'top',
                    labels: { color: '#94a3b8', font: { family: 'Inter', size: 12 } }
                }
            }
        }
    });
}

function renderRecentAlertsTable(alerts) {
    const tbody = document.getElementById('recent-alerts-body');
    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No security alerts detected yet.</td></tr>`;
        return;
    }

    tbody.innerHTML = alerts.map(a => {
        let badgeClass = 'badge-low';
        if (a.severity === 'CRITICAL') badgeClass = 'badge-critical';
        else if (a.severity === 'HIGH') badgeClass = 'badge-high';
        else if (a.severity === 'MEDIUM') badgeClass = 'badge-medium';

        return `
            <tr>
                <td><span class="badge ${badgeClass}">${a.severity}</span></td>
                <td><code>${a.rule_id}</code></td>
                <td>${a.detection_latency_ms} ms</td>
                <td><span class="card-badge">${a.status}</span></td>
                <td>
                    <button class="btn btn-secondary btn-sm" onclick="inspectAlert(${a.id})">Inspect</button>
                </td>
            </tr>
        `;
    }).join('');
}

function renderRecentRunsTable(runs) {
    const tbody = document.getElementById('recent-runs-body');
    if (!runs || runs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No simulation runs recorded yet.</td></tr>`;
        return;
    }

    tbody.innerHTML = runs.map(r => {
        const timeFormatted = r.started_at ? new Date(r.started_at).toLocaleTimeString() : 'N/A';
        return `
            <tr>
                <td><strong>${r.scenario_name.toUpperCase()}</strong></td>
                <td>${r.total_requests} reqs</td>
                <td><span style="color: var(--accent-emerald);">${r.blocked_by_defense || 0}</span></td>
                <td style="color: var(--text-muted); font-size: 0.75rem;">${timeFormatted}</td>
                <td>
                    <a href="/simulations" class="btn btn-secondary btn-sm">Details</a>
                </td>
            </tr>
        `;
    }).join('');
}

async function inspectAlert(alertId) {
    try {
        const res = await fetch(`/api/alerts/${alertId}`);
        const data = await res.json();
        if (data.status === 'success') {
            const a = data.alert;
            const content = `
                <h3 style="color: #fff; margin-bottom: 1rem;">Alert Inspection: ${a.rule_name}</h3>
                <div style="margin-bottom: 0.75rem;">
                    <span class="badge badge-${a.severity.toLowerCase()}">${a.severity}</span>
                    <span style="margin-left: 0.5rem; color: var(--text-secondary);">Rule ID: <code>${a.rule_id}</code></span>
                </div>
                <p style="color: var(--text-secondary); margin-bottom: 1rem;">${a.description}</p>
                <h4 style="color: #fff; margin-bottom: 0.5rem; font-size: 0.9rem;">Triggered Request Telemetry:</h4>
                <div class="code-preview" style="margin-bottom: 1rem;">
Endpoint: ${a.endpoint || 'N/A'}
Status Code: ${a.status_code || 'N/A'}
User Identifier: ${a.user_identifier || 'anonymous'}
Payload: ${a.payload_data || 'None'}
                </div>
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-size: 0.75rem; color: var(--text-muted);">Latency: ${a.detection_latency_ms} ms</span>
                    <button class="btn btn-primary btn-sm" onclick="acknowledgeAlert(${a.id})">Mark Acknowledged</button>
                </div>
            `;
            openModal(content);
        }
    } catch (err) {
        console.error('Failed to inspect alert', err);
    }
}

async function acknowledgeAlert(alertId) {
    try {
        await fetch(`/api/alerts/${alertId}/status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: 'ACKNOWLEDGED' })
        });
        closeModal();
        loadDashboardMetrics();
    } catch (err) {
        console.error('Failed to acknowledge alert', err);
    }
}

async function runFullBattery() {
    const btn = document.getElementById('btn-quick-battery');
    btn.disabled = true;
    btn.innerHTML = `<span>⏳ Simulating Battery...</span>`;

    try {
        const res = await fetch('/api/simulations/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scenario: 'all', notes: 'Dashboard Quick Battery' })
        });
        const data = await res.json();
        if (data.status === 'success') {
            loadDashboardMetrics();
        }
    } catch (err) {
        console.error('Simulation error', err);
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<span>⚡ Run Full Test Battery</span>`;
    }
}

async function runDashboardQuickAssessment() {
    const input = document.getElementById('dashboard-target-url');
    const btn = document.getElementById('btn-dashboard-assess');
    const feedback = document.getElementById('dashboard-assessment-feedback');
    const rawUrl = (input.value || '').trim();

    if (!rawUrl) {
        feedback.style.display = 'block';
        feedback.innerHTML = `<div style="color: #fb7185; font-size: 0.85rem;">⚠️ Please provide the demo URL (e.g., http://127.0.0.1:5000).</div>`;
        return;
    }

    btn.disabled = true;
    btn.innerHTML = `<span>⏳ Assessing...</span>`;
    feedback.style.display = 'block';
    feedback.innerHTML = `<div style="color: var(--accent-cyan); font-size: 0.85rem;">⏳ Evaluating Fortress Bank demo configuration and audit telemetry...</div>`;

    try {
        const res = await fetch('/api/assessment/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: rawUrl })
        });
        const data = await res.json();

        if (!res.ok || data.status === 'error') {
            feedback.innerHTML = `
                <div style="background: rgba(244, 63, 94, 0.1); border: 1px solid rgba(244, 63, 94, 0.4); padding: 0.75rem 1rem; border-radius: var(--radius-sm); color: #fb7185; font-size: 0.85rem;">
                    <strong>⚠️ Scope Violation:</strong> ${data.message || 'Target URL rejected by demo scope enforcer.'}
                </div>
            `;
            return;
        }

        const a = data.assessment;
        const statusBadgeClass = a.overall_status === 'FORTIFIED' ? 'badge-low' : (a.overall_status === 'PARTIALLY_FORTIFIED' ? 'badge-high' : 'badge-critical');
        feedback.innerHTML = `
            <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); padding: 0.75rem 1rem; border-radius: var(--radius-sm); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.75rem;">
                <div>
                    <span class="badge ${statusBadgeClass}">${a.overall_status}</span>
                    <span style="color: #fff; font-size: 0.85rem; margin-left: 0.5rem;">
                        Assessment Complete &bull; <strong>${a.passed_checks}</strong> checks defended, <strong>${a.failed_checks}</strong> need remediation.
                    </span>
                </div>
                <a href="/assessment" class="btn btn-secondary btn-sm">View Full Assessment Findings &rarr;</a>
            </div>
        `;

    } catch (err) {
        feedback.innerHTML = `<div style="color: #fb7185; font-size: 0.85rem;">⚠️ Request failed: ${err.message}</div>`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<span>🛡️ Assess Demo</span>`;
    }
}

document.addEventListener('DOMContentLoaded', loadDashboardMetrics);
