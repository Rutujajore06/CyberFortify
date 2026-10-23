// CyberFortify Red Team Simulation Console Controller

function appendTerminal(line, type = 'info') {
    const consoleEl = document.getElementById('simulation-console');
    const time = new Date().toLocaleTimeString();
    let prefix = `[${time}] `;
    
    if (type === 'attack') prefix += `<span style="color: #f43f5e;">[ATTACK]</span> `;
    else if (type === 'blocked') prefix += `<span style="color: #10b981;">[BLOCKED BY DEFENSE]</span> `;
    else if (type === 'success') prefix += `<span style="color: #00f2fe;">[SUCCESS]</span> `;
    else if (type === 'eval') prefix += `<span style="color: #f59e0b;">[EVALUATION]</span> `;
    else prefix += `<span style="color: #38bdf8;">[INFO]</span> `;

    consoleEl.innerHTML += `\n${prefix}${line}`;
    consoleEl.scrollTop = consoleEl.scrollHeight;
}

function clearTerminal() {
    document.getElementById('simulation-console').innerHTML = `[RESET] Terminal cleared. Ready for next simulation.`;
}

async function launchScenario(scenario) {
    appendTerminal(`Initiating adversary simulation run for scenario '${scenario.toUpperCase()}'...`, 'info');
    appendTerminal(`Executing safe, controlled security test probes against Fortress target app...`, 'info');

    try {
        const response = await fetch('/api/simulations/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scenario: scenario, notes: `Console Run: ${scenario}` })
        });
        const resData = await response.json();

        if (resData.status === 'success') {
            const data = resData.data;
            const run = data.run_info;
            const evalData = data.evaluation;

            appendTerminal(`Run UUID: ${run.run_uuid}`, 'success');
            appendTerminal(`Total Requests: ${data.results_count} | Attacks: ${data.attack_count} | Benign: ${data.benign_count}`, 'attack');
            
            if (data.blocked_count > 0) {
                appendTerminal(`Active Defenses Blocked: ${data.blocked_count} attack attempts!`, 'blocked');
            } else {
                appendTerminal(`Defenses Active: NONE (Baseline vulnerable execution permitted)`, 'info');
            }

            appendTerminal(`Blue Team Alerts Triggered: ${data.alerts_generated ? data.alerts_generated.length : 0}`, 'eval');
            if (evalData) {
                appendTerminal(`Detection Recall Rate: ${evalData.detection_rate}% | Precision: ${evalData.precision_rate}% | Mean Latency: ${evalData.avg_latency_ms} ms`, 'eval');
            }
            appendTerminal(`Adversary simulation completed successfully. Ground truth records persisted.`, 'success');

            loadSimulationHistory();
        } else {
            appendTerminal(`Error during execution: ${resData.message}`, 'attack');
        }
    } catch (err) {
        appendTerminal(`Network or server error executing simulation: ${err.message}`, 'attack');
    }
}

async function loadSimulationHistory() {
    try {
        const res = await fetch('/api/simulations?limit=15');
        const data = await res.json();
        if (data.status === 'success') {
            document.getElementById('history-count').innerText = `${data.count} Runs Recorded`;
            renderHistoryTable(data.runs);
        }
    } catch (err) {
        console.error('Failed to load history', err);
    }
}

function renderHistoryTable(runs) {
    const tbody = document.getElementById('simulations-history-body');
    if (!runs || runs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted);">No simulation history available.</td></tr>`;
        return;
    }

    tbody.innerHTML = runs.map(r => {
        const timeStr = r.started_at ? new Date(r.started_at).toLocaleString() : 'N/A';
        const uuidShort = r.run_uuid ? r.run_uuid.substring(0, 8) + '...' : 'N/A';
        return `
            <tr>
                <td><code>${uuidShort}</code></td>
                <td><strong>${r.scenario_name.toUpperCase()}</strong></td>
                <td>${r.total_requests}</td>
                <td><span style="color: #f43f5e;">${r.attack_requests}</span></td>
                <td><span style="color: #10b981;">${r.blocked_by_defense}</span></td>
                <td style="color: var(--text-muted); font-size: 0.8rem;">${timeStr}</td>
                <td>
                    <button class="btn btn-secondary btn-sm" onclick="inspectSimulationRun('${r.run_uuid}')">Inspect</button>
                </td>
            </tr>
        `;
    }).join('');
}

async function inspectSimulationRun(runUuid) {
    try {
        const res = await fetch(`/api/simulations/${runUuid}`);
        const data = await res.json();
        if (data.status === 'success') {
            const run = data.run;
            const evalData = data.evaluation || {};
            const cm = evalData.summary ? evalData.summary.confusion_matrix : null;

            const modalHtml = `
                <h3 style="color: #fff; margin-bottom: 0.5rem;">Simulation Run Details</h3>
                <div style="color: var(--accent-cyan); font-family: var(--font-mono); font-size: 0.8rem; margin-bottom: 1rem;">
                    Run UUID: ${run.run_uuid}
                </div>
                <div class="grid-kpi" style="margin-bottom: 1rem;">
                    <div style="background: rgba(255,255,255,0.02); padding: 0.75rem; border-radius: 6px;">
                        <div style="font-size: 0.7rem; color: var(--text-muted);">SCENARIO</div>
                        <div style="font-size: 1.1rem; color: #fff; font-weight: bold;">${run.scenario_name.toUpperCase()}</div>
                    </div>
                    <div style="background: rgba(255,255,255,0.02); padding: 0.75rem; border-radius: 6px;">
                        <div style="font-size: 0.7rem; color: var(--text-muted);">DETECTION RATE</div>
                        <div style="font-size: 1.1rem; color: var(--accent-emerald); font-weight: bold;">${evalData.detection_rate || 0}%</div>
                    </div>
                    <div style="background: rgba(255,255,255,0.02); padding: 0.75rem; border-radius: 6px;">
                        <div style="font-size: 0.7rem; color: var(--text-muted);">BLOCKED BY DEFENSE</div>
                        <div style="font-size: 1.1rem; color: var(--accent-cyan); font-weight: bold;">${run.blocked_by_defense || 0} / ${run.attack_requests}</div>
                    </div>
                </div>

                ${cm ? `
                <h4 style="color: #fff; margin-bottom: 0.5rem; font-size: 0.9rem;">Confusion Matrix & Accuracy Breakdown:</h4>
                <div class="table-responsive" style="margin-bottom: 1rem;">
                    <table class="table" style="font-size: 0.8rem;">
                        <thead>
                            <tr>
                                <th>True Positives (TP)</th>
                                <th>False Positives (FP)</th>
                                <th>False Negatives (FN)</th>
                                <th>True Negatives (TN)</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td style="color: var(--accent-emerald); font-weight: bold;">${cm.true_positives}</td>
                                <td style="color: var(--accent-rose); font-weight: bold;">${cm.false_positives}</td>
                                <td style="color: var(--accent-amber); font-weight: bold;">${cm.false_negatives}</td>
                                <td style="color: var(--accent-blue); font-weight: bold;">${cm.true_negatives}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                ` : ''}

                <div style="display: flex; justify-content: flex-end; margin-top: 1rem;">
                    <button class="btn btn-secondary btn-sm" onclick="closeModal()">Close</button>
                </div>
            `;
            openModal(modalHtml);
        }
    } catch (err) {
        console.error('Error fetching run details', err);
    }
}

document.addEventListener('DOMContentLoaded', loadSimulationHistory);
