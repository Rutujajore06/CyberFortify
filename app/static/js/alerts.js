// CyberFortify Blue Team Alert Center Controller

async function loadAlerts() {
    const severity = document.getElementById('filter-severity').value;
    const status = document.getElementById('filter-status').value;
    const ruleId = document.getElementById('filter-rule').value;

    let url = `/api/alerts?limit=100`;
    if (severity) url += `&severity=${encodeURIComponent(severity)}`;
    if (status) url += `&status=${encodeURIComponent(status)}`;
    if (ruleId) url += `&rule_id=${encodeURIComponent(ruleId)}`;

    try {
        // Fetch alerts
        const res = await fetch(url);
        const data = await res.json();
        if (data.status === 'success') {
            document.getElementById('alerts-count-badge').innerText = `${data.total} Alerts Matched`;
            renderAlertsTable(data.alerts);
        }

        // Fetch summary counters
        const sumRes = await fetch('/api/alerts/summary');
        const sumData = await sumRes.json();
        if (sumData.status === 'success') {
            const s = sumData.summary;
            document.getElementById('count-critical').innerText = s.CRITICAL || 0;
            document.getElementById('count-high').innerText = s.HIGH || 0;
            document.getElementById('count-medium').innerText = s.MEDIUM || 0;
            document.getElementById('count-low').innerText = s.LOW || 0;
        }

    } catch (err) {
        console.error('Failed to load alerts', err);
    }
}

function filterBySeverity(sev) {
    document.getElementById('filter-severity').value = sev;
    loadAlerts();
}

function renderAlertsTable(alerts) {
    const tbody = document.getElementById('alerts-table-body');
    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No alerts match the selected criteria.</td></tr>`;
        return;
    }

    tbody.innerHTML = alerts.map(a => {
        let badgeClass = 'badge-low';
        if (a.severity === 'CRITICAL') badgeClass = 'badge-critical';
        else if (a.severity === 'HIGH') badgeClass = 'badge-high';
        else if (a.severity === 'MEDIUM') badgeClass = 'badge-medium';

        const timeStr = a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : 'N/A';

        return `
            <tr>
                <td><span class="badge ${badgeClass}">${a.severity}</span></td>
                <td><code>${a.rule_id}</code></td>
                <td><strong>${a.rule_name}</strong></td>
                <td><span style="font-family: var(--font-mono); font-size: 0.8rem;">${a.endpoint || '/api/target/*'}</span></td>
                <td><span style="color: var(--accent-cyan);">${a.detection_latency_ms} ms</span></td>
                <td><span class="card-badge">${a.status}</span></td>
                <td style="color: var(--text-muted); font-size: 0.8rem;">${timeStr}</td>
                <td>
                    <button class="btn btn-secondary btn-sm" onclick="inspectAlertModal(${a.id})">Inspect</button>
                    ${a.status !== 'RESOLVED' ? `
                        <button class="btn btn-secondary btn-sm" style="margin-left: 0.25rem;" onclick="changeAlertStatus(${a.id}, 'RESOLVED')">Resolve</button>
                    ` : ''}
                </td>
            </tr>
        `;
    }).join('');
}

async function changeAlertStatus(alertId, newStatus) {
    try {
        await fetch(`/api/alerts/${alertId}/status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: newStatus })
        });
        loadAlerts();
    } catch (err) {
        console.error('Failed to update alert status', err);
    }
}

async function inspectAlertModal(alertId) {
    try {
        const res = await fetch(`/api/alerts/${alertId}`);
        const data = await res.json();
        if (data.status === 'success') {
            const a = data.alert;
            const content = `
                <h3 style="color: #fff; margin-bottom: 0.5rem;">Alert Triage: ${a.rule_name}</h3>
                <div style="margin-bottom: 1rem;">
                    <span class="badge badge-${a.severity.toLowerCase()}">${a.severity}</span>
                    <span style="margin-left: 0.5rem; color: var(--accent-cyan);"><code>${a.rule_id}</code></span>
                    <span style="margin-left: 0.5rem; color: var(--text-muted); font-size: 0.8rem;">Status: ${a.status}</span>
                </div>
                
                <h4 style="color: #fff; margin-bottom: 0.25rem; font-size: 0.85rem;">Detection Correlation Reason:</h4>
                <p style="color: var(--text-secondary); margin-bottom: 1.25rem; font-size: 0.9rem;">${a.description}</p>

                <h4 style="color: #fff; margin-bottom: 0.25rem; font-size: 0.85rem;">Triggering Request Telemetry:</h4>
                <div class="code-preview" style="margin-bottom: 1rem;">
Endpoint: ${a.endpoint || 'N/A'}
Method: ${a.http_method || 'POST/GET'}
Status Code: ${a.status_code || 200}
IP Address: ${a.ip_address || '127.0.0.1'}
User: ${a.user_identifier || 'anonymous'}
Scenario: ${a.attack_scenario || 'unclassified'}
Payload: ${a.payload_data || 'None'}
                </div>

                <div style="background: rgba(0, 242, 254, 0.05); border: 1px solid rgba(0, 242, 254, 0.2); padding: 0.75rem; border-radius: 6px; margin-bottom: 1.5rem;">
                    <div style="font-size: 0.75rem; color: var(--accent-cyan); font-weight: bold; margin-bottom: 0.25rem;">DETECTION LATENCY</div>
                    <div style="font-size: 0.9rem; color: #fff;">${a.detection_latency_ms} ms between event ingestion and alert creation.</div>
                </div>

                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <button class="btn btn-secondary btn-sm" onclick="changeAlertStatus(${a.id}, 'ACKNOWLEDGED'); closeModal();">Acknowledge</button>
                        <button class="btn btn-secondary btn-sm" style="margin-left: 0.5rem;" onclick="changeAlertStatus(${a.id}, 'RESOLVED'); closeModal();">Mark Resolved</button>
                    </div>
                    <button class="btn btn-secondary btn-sm" onclick="closeModal()">Close</button>
                </div>
            `;
            openModal(content);
        }
    } catch (err) {
        console.error('Failed to inspect alert', err);
    }
}

document.addEventListener('DOMContentLoaded', loadAlerts);
