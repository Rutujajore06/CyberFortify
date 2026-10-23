// CyberFortify Audit Log Explorer Controller

let currentPage = 0;
const pageSize = 25;
let totalEvents = 0;

async function loadEvents(page = 0) {
    currentPage = page;
    const search = document.getElementById('log-search').value.trim();
    const scenario = document.getElementById('log-scenario').value;
    const classification = document.getElementById('log-classification').value;

    let url = `/api/events?limit=${pageSize}&offset=${currentPage * pageSize}`;
    let csvUrl = `/api/events/export/csv?1=1`;

    if (search) {
        url += `&search=${encodeURIComponent(search)}`;
        csvUrl += `&search=${encodeURIComponent(search)}`;
    }
    if (scenario) {
        url += `&scenario=${encodeURIComponent(scenario)}`;
        csvUrl += `&scenario=${encodeURIComponent(scenario)}`;
    }
    if (classification !== '') {
        url += `&is_attack=${encodeURIComponent(classification)}`;
        csvUrl += `&is_attack=${encodeURIComponent(classification)}`;
    }

    // Update CSV export button href
    document.getElementById('btn-export-csv').href = csvUrl;

    try {
        const res = await fetch(url);
        const data = await res.json();
        if (data.status === 'success') {
            totalEvents = data.total;
            document.getElementById('total-events-badge').innerText = `${totalEvents} Events Recorded`;
            renderEventsTable(data.events);
            updatePaginationControls();
        }
    } catch (err) {
        console.error('Failed to load events', err);
    }
}

function renderEventsTable(events) {
    const tbody = document.getElementById('events-table-body');
    if (!events || events.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-muted);">No audit events found.</td></tr>`;
        return;
    }

    tbody.innerHTML = events.map(e => {
        const timeStr = e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : 'N/A';
        const isAttack = Boolean(e.is_attack);
        const badgeClass = isAttack ? 'badge-attack' : 'badge-benign';
        const label = isAttack ? 'ATTACK' : 'BENIGN';
        const payloadSnippet = e.payload_data ? (e.payload_data.length > 40 ? e.payload_data.substring(0, 40) + '...' : e.payload_data) : '-';

        let statusColor = '#38bdf8';
        if (e.status_code >= 400 && e.status_code < 500) statusColor = '#f59e0b';
        if (e.status_code >= 500) statusColor = '#f43f5e';
        if (e.status_code === 429 || e.status_code === 403) statusColor = '#10b981';

        return `
            <tr>
                <td>#${e.id}</td>
                <td style="color: var(--text-muted); font-size: 0.8rem;">${timeStr}</td>
                <td><span style="font-family: var(--font-mono); font-size: 0.8rem;">${e.ip_address || '127.0.0.1'}</span></td>
                <td><strong>${e.http_method}</strong></td>
                <td><code>${e.endpoint}</code></td>
                <td><span style="color: ${statusColor}; font-weight: bold;">${e.status_code}</span></td>
                <td><span class="badge ${badgeClass}">${label}</span></td>
                <td><span class="card-badge">${(e.attack_scenario || 'benign').toUpperCase()}</span></td>
                <td style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-secondary); max-width: 200px;">
                    <a href="javascript:void(0)" onclick="inspectEventModal(${e.id})" style="color: var(--accent-cyan); text-decoration: none;">
                        ${escapeHtml(payloadSnippet)}
                    </a>
                </td>
            </tr>
        `;
    }).join('');
}

function updatePaginationControls() {
    const totalPages = Math.ceil(totalEvents / pageSize) || 1;
    document.getElementById('pagination-info').innerText = `Showing Page ${currentPage + 1} of ${totalPages} (${totalEvents} events)`;
    document.getElementById('btn-prev-page').disabled = (currentPage === 0);
    document.getElementById('btn-next-page').disabled = (currentPage >= totalPages - 1);
}

function changePage(delta) {
    const newPage = currentPage + delta;
    if (newPage >= 0) {
        loadEvents(newPage);
    }
}

function resetFilters() {
    document.getElementById('log-search').value = '';
    document.getElementById('log-scenario').value = '';
    document.getElementById('log-classification').value = '';
    loadEvents(0);
}

async function inspectEventModal(eventId) {
    try {
        const res = await fetch(`/api/events/${eventId}`);
        const data = await res.json();
        if (data.status === 'success' && data.event) {
            const e = data.event;
            const content = `
                <h3 style="color: #fff; margin-bottom: 0.75rem;">Security Audit Event #${e.id}</h3>
                <div style="margin-bottom: 1rem;">
                    <span class="badge ${e.is_attack ? 'badge-attack' : 'badge-benign'}">${e.is_attack ? 'ATTACK GROUND TRUTH' : 'BENIGN TRAFFIC'}</span>
                    <span style="margin-left: 0.5rem; color: var(--text-secondary);">Scenario: <code>${e.attack_scenario}</code></span>
                </div>
                <div class="code-preview" style="margin-bottom: 1rem;">
Event UUID: ${e.event_uuid}
Timestamp: ${e.timestamp}
IP Address: ${e.ip_address}
HTTP Method: ${e.http_method}
Endpoint: ${e.endpoint}
HTTP Status Code: ${e.status_code}
User Identifier: ${e.user_identifier || 'anonymous'}
Expected Rule: ${e.expected_rule || 'None'}
Simulation Run ID: ${e.simulation_run_id || 'N/A'}
                </div>
                <h4 style="color: #fff; margin-bottom: 0.25rem; font-size: 0.85rem;">Captured Raw Payload:</h4>
                <div class="code-preview" style="margin-bottom: 1rem; color: var(--accent-cyan);">
${e.payload_data || 'Empty Payload'}
                </div>
                <div style="display: flex; justify-content: flex-end;">
                    <button class="btn btn-secondary btn-sm" onclick="closeModal()">Close</button>
                </div>
            `;
            openModal(content);
        }
    } catch (err) {
        console.error('Failed to inspect event', err);
    }
}

function escapeHtml(text) {
    if (!text) return '';
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

document.addEventListener('DOMContentLoaded', () => loadEvents(0));
