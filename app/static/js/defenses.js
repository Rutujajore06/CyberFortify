// CyberFortify Remediation & Retesting Controller

async function loadDefenses() {
    try {
        const res = await fetch('/api/defenses');
        const data = await res.json();
        if (data.status === 'success') {
            renderDefensesGrid(data.defenses);
        }
    } catch (err) {
        console.error('Failed to load defenses', err);
    }
}

function renderDefensesGrid(defenses) {
    const grid = document.getElementById('defenses-grid');
    if (!defenses || defenses.length === 0) {
        grid.innerHTML = `<div class="card"><div style="color: var(--text-muted);">No defense controls configured.</div></div>`;
        return;
    }

    grid.innerHTML = defenses.map(d => {
        const isChecked = Boolean(d.is_enabled);
        const statusColor = isChecked ? 'var(--accent-emerald)' : 'var(--text-muted)';
        const statusText = isChecked ? 'FORTIFIED (ACTIVE)' : 'VULNERABLE (DISABLED)';

        return `
            <div class="card">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1rem;">
                    <div>
                        <span style="font-size: 0.75rem; color: ${statusColor}; font-weight: bold; text-transform: uppercase;">
                            ${statusText}
                        </span>
                        <h3 style="color: #fff; font-size: 1.05rem; margin-top: 0.25rem;">${d.name}</h3>
                    </div>
                    <label class="switch-control">
                        <input type="checkbox" ${isChecked ? 'checked' : ''} onchange="toggleDefense('${d.defense_key}', this.checked)">
                        <span class="slider"></span>
                    </label>
                </div>
                <p style="color: var(--text-secondary); font-size: 0.85rem; margin-bottom: 1rem; line-height: 1.5;">
                    ${d.description}
                </p>
                <div style="background: rgba(0, 242, 254, 0.04); border: 1px solid rgba(0, 242, 254, 0.15); padding: 0.75rem; border-radius: var(--radius-sm); font-size: 0.75rem; color: var(--accent-cyan);">
                    <strong>Remediation Strategy:</strong> ${d.remediation_guidance}
                </div>
            </div>
        `;
    }).join('');
}

async function toggleDefense(defenseKey, isEnabled) {
    try {
        await fetch('/api/defenses/toggle', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ defense_key: defenseKey, is_enabled: isEnabled })
        });
        loadDefenses();
    } catch (err) {
        console.error('Failed to toggle defense', err);
    }
}

async function bulkToggle(enableAll) {
    try {
        await fetch('/api/defenses/bulk-toggle', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enable_all: enableAll })
        });
        loadDefenses();
    } catch (err) {
        console.error('Bulk toggle error', err);
    }
}

async function runRetestExperiment() {
    const btn = document.getElementById('btn-run-retest');
    btn.disabled = true;
    btn.innerHTML = `<span>⏳ Retesting Baseline vs Fortified...</span>`;

    try {
        const res = await fetch('/api/retest/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scenario: 'all' })
        });
        const resData = await res.json();

        if (resData.status === 'success') {
            const data = resData.data;
            const comp = data.comparison;
            const base = comp.baseline;
            const fort = comp.fortified;

            // Fill baseline numbers
            document.getElementById('base-attacks').innerText = base.attack_requests;
            document.getElementById('base-blocked').innerText = base.blocked_by_defense;
            document.getElementById('base-rate').innerText = `${base.block_rate_percent}%`;
            document.getElementById('base-breaches').innerText = base.successful_breaches;

            // Fill fortified numbers
            document.getElementById('fort-attacks').innerText = fort.attack_requests;
            document.getElementById('fort-blocked').innerText = fort.blocked_by_defense;
            document.getElementById('fort-rate').innerText = `${fort.block_rate_percent}%`;
            document.getElementById('fort-improvement').innerText = `+${comp.improvement_percent}%`;

            // Verdict Badge
            const verdict = document.getElementById('retest-verdict-badge');
            verdict.className = 'badge badge-low';
            verdict.innerText = comp.security_verdict;

            // Render Remediations
            renderRemediationsList(data.remediations);

            // Reload defenses grid
            loadDefenses();
        }
    } catch (err) {
        console.error('Retest error', err);
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<span>🔬 Run Before & After Retest</span>`;
    }
}

function renderRemediationsList(remediations) {
    const container = document.getElementById('remediations-list');
    if (!remediations) return;

    container.innerHTML = remediations.map(r => `
        <div style="background: rgba(255, 255, 255, 0.02); border: 1px solid var(--border-color); border-radius: var(--radius-sm); padding: 1rem;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                <strong style="color: #fff; font-size: 0.95rem;">${r.vulnerability}</strong>
                <span class="badge badge-low">REMEDIATED</span>
            </div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; font-size: 0.8rem; margin-bottom: 0.75rem;">
                <div style="color: #fb7185;">
                    <strong>Before:</strong> ${r.before_status}
                </div>
                <div style="color: var(--accent-emerald);">
                    <strong>After:</strong> ${r.after_status}
                </div>
            </div>
            <div style="font-size: 0.75rem; color: var(--text-secondary); background: #070d1a; padding: 0.5rem; border-radius: 4px;">
                <strong>Engineering Action:</strong> ${r.recommendation}
            </div>
        </div>
    `).join('');
}

document.addEventListener('DOMContentLoaded', loadDefenses);
