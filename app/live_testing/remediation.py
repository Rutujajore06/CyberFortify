import html
import json
import uuid
from app.database import get_db_connection
from app.models.live_target_model import (
    get_live_target_by_uuid,
    get_live_assessment_by_uuid,
    get_recent_live_assessments,
    log_live_audit,
    utc_now_iso
)

VALID_REMEDIATION_STATUSES = {'Open', 'In Progress', 'Fixed', 'Verified'}

# Maps each scanner check_key to the affected HTTP header or transport/config surface
AFFECTED_HEADER_MAP = {
    'https_availability': 'HTTPS / Port 443',
    'tls_certificate': 'TLS X.509 Certificate',
    'http_to_https_redirect': 'Location (HTTP -> HTTPS Redirect)',
    'header_csp': 'Content-Security-Policy',
    'header_hsts': 'Strict-Transport-Security',
    'header_x_content_type_options': 'X-Content-Type-Options',
    'header_x_frame_options': 'X-Frame-Options',
    'header_referrer_policy': 'Referrer-Policy',
    'cookie_security_flags': 'Set-Cookie',
    'server_info_exposure': 'Server / X-Powered-By',
    'config_permissions_policy': 'Permissions-Policy',
    'config_cors_policy': 'Access-Control-Allow-Origin',
    'http_response_unavailable': 'HTTP/HTTPS Endpoint'
}

# Rich owner-actionable remediation guidance per check_key
DETAILED_REMEDIATION_GUIDES = {
    'header_csp': (
        "Configure a Content-Security-Policy header on your web server or hosting config "
        "(e.g., vercel.json headers, Nginx add_header, or Flask after_request). "
        "Recommended starter policy: \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'\". "
        "Test thoroughly before enforcing to avoid breaking legitimate assets."
    ),
    'header_hsts': (
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses "
        "so browsers enforce HTTPS and resist downgrade/SSL-stripping attacks."
    ),
    'header_x_content_type_options': (
        "Set 'X-Content-Type-Options: nosniff' across all responses to prevent browsers from MIME-sniffing "
        "responses away from the declared Content-Type."
    ),
    'header_x_frame_options': (
        "Set 'X-Frame-Options: DENY' (or 'SAMEORIGIN' if same-origin framing is needed) and pair with "
        "CSP \"frame-ancestors 'none'\" to prevent clickjacking."
    ),
    'header_referrer_policy': (
        "Add 'Referrer-Policy: strict-origin-when-cross-origin' (or 'no-referrer') to prevent leaking "
        "full paths or query parameters to third-party origins."
    ),
    'cookie_security_flags': (
        "Update session and sensitive cookie definitions to include 'Secure; HttpOnly; SameSite=Lax' "
        "(or 'SameSite=Strict') to protect cookies from interception, XSS theft, and CSRF."
    ),
    'server_info_exposure': (
        "Suppress version-revealing banners such as 'Server' version numbers and 'X-Powered-By' "
        "(e.g., 'server_tokens off;' in Nginx, 'ServerTokens Prod' in Apache, or remove 'X-Powered-By' middleware)."
    ),
    'config_permissions_policy': (
        "Add 'Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()' to restrict "
        "browser hardware and sensitive APIs not used by the application."
    ),
    'config_cors_policy': (
        "Replace wildcard 'Access-Control-Allow-Origin: *' with an explicit origin allowlist on sensitive "
        "or authenticated routes, and never combine '*' with 'Access-Control-Allow-Credentials: true'."
    ),
    'https_availability': (
        "Provision and enable a valid TLS certificate on port 443 via your hosting provider or Let's Encrypt."
    ),
    'tls_certificate': (
        "Install a valid, unexpired X.509 certificate from a trusted CA matching the domain, enable automated "
        "renewal, and restrict TLS protocols to TLSv1.2 and TLSv1.3."
    ),
    'http_to_https_redirect': (
        "Configure port 80 (HTTP) to permanently redirect (HTTP 301 or 308) all traffic to the HTTPS origin."
    )
}


def get_affected_header(check_key):
    """Returns the affected security header or transport component name for a check_key."""
    return AFFECTED_HEADER_MAP.get(check_key, check_key)


def get_remediation_instructions(check_key, fallback=''):
    """Returns concrete owner-actionable remediation instructions for a check_key."""
    return DETAILED_REMEDIATION_GUIDES.get(check_key) or fallback or (
        "Review the finding evidence and harden the target server configuration, then run a live retest."
    )


def _is_failing_status(status):
    return (status or '').upper() in ('FAIL', 'VULNERABLE', 'WARNING', 'WARN')


def _is_passing_status(status):
    return (status or '').upper() in ('PASS', 'DEFENDED')


def _hydrate_remediation(row):
    if not row:
        return None
    d = dict(row)
    d['retest_confirmed'] = bool(d.get('retest_confirmed'))
    return d


def sync_remediations_from_assessment(assessment):
    """
    Synchronizes vulnerability remediation tracking records in SQLite from a REAL COMPLETED assessment.

    Integrity Rules:
    - Original assessments & audit logs are NEVER overwritten or deleted.
    - New failing/warning findings are tracked with initial status 'Open' (retest_confirmed=0).
    - Existing 'Open' / 'In Progress' items keep their workflow status & owner notes while updating evidence.
    - Previously failing items that PASS on a subsequent real assessment automatically transition:
        * 'Open' / 'In Progress' -> 'Fixed' (retest_confirmed=1, verified_assessment_uuid set)
        * 'Fixed' (passing a subsequent confirmation retest) -> 'Verified' (verified_at set)
    - Previously 'Fixed' / 'Verified' items that FAIL again (regression) automatically reopen to 'Open'
      with retest_confirmed=0 and an audit log entry.
    """
    if not assessment or assessment.get('status') != 'COMPLETED':
        return []

    target_uuid = assessment['target_uuid']
    domain = assessment['domain']
    assessment_uuid = assessment['assessment_uuid']
    findings = assessment.get('findings') or []
    now = utc_now_iso()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM live_remediations WHERE target_uuid = ?', (target_uuid,))
    existing_by_key = {r['check_key']: dict(r) for r in cursor.fetchall()}

    audit_events = []

    for f in findings:
        check_key = f.get('check_key', 'unknown')
        f_status = (f.get('status') or 'FAIL').upper()
        severity = (f.get('severity') or 'INFO').upper()
        title = f.get('title') or check_key
        category = f.get('category') or 'General'
        evidence = f.get('evidence') or ''
        affected_header = get_affected_header(check_key)
        instructions = get_remediation_instructions(check_key, fallback=f.get('remediation') or '')

        existing = existing_by_key.get(check_key)

        if _is_failing_status(f_status):
            if existing is None:
                rem_uuid = f"rem-{uuid.uuid4().hex[:12]}"
                cursor.execute('''
                    INSERT INTO live_remediations (
                        remediation_uuid, target_uuid, domain, check_key, title, category,
                        affected_header, severity, finding_status, remediation_status,
                        evidence, remediation_instructions, remediation_notes,
                        first_detected_assessment_uuid, latest_assessment_uuid,
                        verified_assessment_uuid, retest_confirmed,
                        fixed_at, verified_at, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Open', ?, ?, '', ?, ?, NULL, 0, NULL, NULL, ?, ?)
                ''', (
                    rem_uuid, target_uuid, domain, check_key, title, category,
                    affected_header, severity, f_status,
                    evidence, instructions,
                    assessment_uuid, assessment_uuid,
                    now, now
                ))
            else:
                prev_rem_status = existing['remediation_status']
                if prev_rem_status in ('Fixed', 'Verified'):
                    # Regression detected on a real retest -> automatically reopen!
                    new_rem_status = 'Open'
                    audit_events.append((
                        'REMEDIATION_REGRESSION',
                        'WARNING',
                        f"Finding '{check_key}' ({affected_header}) regressed to {f_status} in {assessment_uuid}; reopened from {prev_rem_status} to Open."
                    ))
                else:
                    # Preserve owner's 'Open' or 'In Progress' status and notes
                    new_rem_status = prev_rem_status

                cursor.execute('''
                    UPDATE live_remediations
                    SET title = ?, category = ?, affected_header = ?, severity = ?,
                        finding_status = ?, remediation_status = ?, evidence = ?,
                        remediation_instructions = ?, latest_assessment_uuid = ?,
                        retest_confirmed = 0, updated_at = ?
                    WHERE id = ?
                ''', (
                    title, category, affected_header, severity,
                    f_status, new_rem_status, evidence,
                    instructions, assessment_uuid,
                    now, existing['id']
                ))

        elif _is_passing_status(f_status) and existing is not None:
            # Previously detected finding now PASSES in a real live retest!
            prev_rem_status = existing['remediation_status']
            if prev_rem_status in ('Open', 'In Progress'):
                new_rem_status = 'Fixed'
                fixed_at = now
                verified_at = existing.get('verified_at')
                audit_events.append((
                    'REMEDIATION_FIXED_BY_RETEST',
                    'SUCCESS',
                    f"Finding '{check_key}' ({affected_header}) passed live retest {assessment_uuid}; transitioned {prev_rem_status} -> Fixed."
                ))
            elif prev_rem_status == 'Fixed' and existing.get('latest_assessment_uuid') != assessment_uuid:
                new_rem_status = 'Verified'
                fixed_at = existing.get('fixed_at') or now
                verified_at = now
                audit_events.append((
                    'REMEDIATION_VERIFIED_BY_RETEST',
                    'SUCCESS',
                    f"Finding '{check_key}' ({affected_header}) passed confirmation retest {assessment_uuid}; transitioned Fixed -> Verified."
                ))
            else:
                new_rem_status = prev_rem_status
                fixed_at = existing.get('fixed_at') or now
                verified_at = existing.get('verified_at')

            cursor.execute('''
                UPDATE live_remediations
                SET severity = ?, finding_status = ?, remediation_status = ?,
                    evidence = ?, latest_assessment_uuid = ?,
                    verified_assessment_uuid = ?, retest_confirmed = 1,
                    fixed_at = ?, verified_at = ?, updated_at = ?
                WHERE id = ?
            ''', (
                severity, f_status, new_rem_status,
                evidence, assessment_uuid,
                assessment_uuid, fixed_at, verified_at, now,
                existing['id']
            ))

    conn.commit()
    conn.close()

    for action, outcome, reason in audit_events:
        log_live_audit(
            action=action,
            outcome=outcome,
            target_uuid=target_uuid,
            domain=domain,
            reason=reason,
            actor='retest-engine'
        )

    return get_remediations_for_target(target_uuid)


def ensure_remediations_synced(target_uuid):
    """
    If a target has completed live assessments but no remediation rows yet (e.g., pre-existing
    assessments run before this module was added), syncs them in chronological order.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT count(*) as c FROM live_remediations WHERE target_uuid = ?', (target_uuid,))
    count = cursor.fetchone()['c']
    conn.close()

    if count == 0:
        recent = get_recent_live_assessments(limit=25, target_uuid=target_uuid)
        completed = [a for a in reversed(recent) if a.get('status') == 'COMPLETED']
        for item in completed:
            full = get_live_assessment_by_uuid(item['assessment_uuid'])
            if full:
                sync_remediations_from_assessment(full)


def get_remediations_for_target(target_uuid, status_filter=None):
    """Returns tracked remediation items for a target ordered by severity & status."""
    ensure_remediations_synced(target_uuid)
    conn = get_db_connection()
    cursor = conn.cursor()
    if status_filter and status_filter in VALID_REMEDIATION_STATUSES:
        cursor.execute('''
            SELECT * FROM live_remediations
            WHERE target_uuid = ? AND remediation_status = ?
            ORDER BY id ASC
        ''', (target_uuid, status_filter))
    else:
        cursor.execute('''
            SELECT * FROM live_remediations
            WHERE target_uuid = ?
            ORDER BY id ASC
        ''', (target_uuid,))
    rows = [_hydrate_remediation(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def get_remediation_by_uuid(remediation_uuid):
    """Fetches a single remediation record by UUID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM live_remediations WHERE remediation_uuid = ?', (remediation_uuid,))
    row = cursor.fetchone()
    conn.close()
    return _hydrate_remediation(row)


def update_remediation_item(remediation_uuid, new_status=None, notes=None, actor='owner'):
    """
    Updates a remediation item's workflow status and/or owner remediation notes.

    Strict Integrity Rule:
    - Users MAY set 'Open' or 'In Progress' and update 'remediation_notes' at any time.
    - Users CANNOT set 'Fixed' or 'Verified' unless a real live retest has ALREADY passed
      for that finding (retest_confirmed == True). Attempting to bypass retest verification
      returns an error ('RETEST_REQUIRED').
    """
    item = get_remediation_by_uuid(remediation_uuid)
    if not item:
        return None, 'NOT_FOUND', f"Remediation item '{remediation_uuid}' not found."

    target_status = item['remediation_status']
    verified_at = item.get('verified_at')

    if new_status is not None:
        if new_status not in VALID_REMEDIATION_STATUSES:
            return None, 'VALIDATION_ERROR', (
                f"Invalid remediation status '{new_status}'. "
                f"Allowed values: {sorted(list(VALID_REMEDIATION_STATUSES))}."
            )

        if new_status in ('Fixed', 'Verified') and not item['retest_confirmed']:
            log_live_audit(
                action='REMEDIATION_MANUAL_FIX_BLOCKED',
                outcome='BLOCKED',
                target_uuid=item['target_uuid'],
                domain=item['domain'],
                reason=(
                    f"Blocked manual status change to '{new_status}' for '{item['check_key']}' "
                    "without a passing live retest."
                ),
                actor=actor
            )
            return None, 'RETEST_REQUIRED', (
                f"Cannot mark '{item['title']}' as '{new_status}' without a passing live retest. "
                "Apply the fix on your website, set status to 'In Progress', and click 'Retest' to verify."
            )

        target_status = new_status
        if new_status == 'Verified' and not verified_at:
            verified_at = utc_now_iso()

    updated_notes = item['remediation_notes'] if notes is None else str(notes).strip()
    now = utc_now_iso()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE live_remediations
        SET remediation_status = ?, remediation_notes = ?, verified_at = ?, updated_at = ?
        WHERE remediation_uuid = ?
    ''', (target_status, updated_notes, verified_at, now, remediation_uuid))
    conn.commit()
    conn.close()

    log_live_audit(
        action='REMEDIATION_UPDATED',
        outcome='SUCCESS',
        target_uuid=item['target_uuid'],
        domain=item['domain'],
        reason=(
            f"Updated remediation '{item['check_key']}' ({item['affected_header']}): "
            f"status={target_status}, notes_length={len(updated_notes)}."
        ),
        actor=actor
    )

    return get_remediation_by_uuid(remediation_uuid), None, None


def compare_live_assessments(baseline, latest):
    """
    Compares two real completed live assessments (previous/baseline vs latest) and confirms:
    - Before-and-after security scores & grades + exact delta
    - Fixed vulnerabilities (failed/warned in baseline -> PASS in latest)
    - Remaining vulnerabilities (still failing/warning in latest)
    - New / regressed vulnerabilities (passed/absent in baseline -> failed/warned in latest)
    - Unchanged passed checks
    """
    if not latest:
        return None

    latest_findings = {f['check_key']: f for f in (latest.get('findings') or [])}
    baseline_findings = {f['check_key']: f for f in (baseline.get('findings') or [])} if baseline else {}

    fixed_vulnerabilities = []
    remaining_vulnerabilities = []
    new_vulnerabilities = []
    unchanged_passed = []

    all_keys = list(dict.fromkeys(list(baseline_findings.keys()) + list(latest_findings.keys())))

    for key in all_keys:
        b = baseline_findings.get(key)
        l = latest_findings.get(key)
        affected_header = get_affected_header(key)

        b_fail = bool(b and _is_failing_status(b.get('status')))
        l_fail = bool(l and _is_failing_status(l.get('status')))
        l_pass = bool(l and _is_passing_status(l.get('status')))

        if b_fail and l_pass:
            fixed_vulnerabilities.append({
                'check_key': key,
                'title': l.get('title') or b.get('title'),
                'category': l.get('category') or b.get('category'),
                'affected_header': affected_header,
                'previous_severity': b.get('severity'),
                'previous_status': b.get('status'),
                'current_status': l.get('status'),
                'previous_evidence': b.get('evidence'),
                'current_evidence': l.get('evidence'),
                'remediation_status': 'Fixed'
            })
        elif b_fail and l_fail:
            remaining_vulnerabilities.append({
                'check_key': key,
                'title': l.get('title'),
                'category': l.get('category'),
                'affected_header': affected_header,
                'severity': l.get('severity'),
                'previous_status': b.get('status'),
                'current_status': l.get('status'),
                'evidence': l.get('evidence'),
                'remediation': get_remediation_instructions(key, l.get('remediation') or '')
            })
        elif (not b_fail) and l_fail:
            new_vulnerabilities.append({
                'check_key': key,
                'title': l.get('title'),
                'category': l.get('category'),
                'affected_header': affected_header,
                'severity': l.get('severity'),
                'previous_status': b.get('status') if b else 'N/A',
                'current_status': l.get('status'),
                'evidence': l.get('evidence'),
                'remediation': get_remediation_instructions(key, l.get('remediation') or '')
            })
        elif l_pass:
            unchanged_passed.append({
                'check_key': key,
                'title': l.get('title'),
                'category': l.get('category'),
                'affected_header': affected_header,
                'status': l.get('status'),
                'evidence': l.get('evidence')
            })

    b_score = baseline.get('security_score') if baseline else None
    l_score = latest.get('security_score', 0)
    score_delta = (l_score - b_score) if b_score is not None else 0

    if baseline is None:
        verdict = 'INITIAL_BASELINE_RECORDED'
    elif len(fixed_vulnerabilities) > 0 and len(remaining_vulnerabilities) == 0 and len(new_vulnerabilities) == 0:
        verdict = 'ALL_VULNERABILITIES_REMEDIATED'
    elif score_delta > 0 or len(fixed_vulnerabilities) > 0:
        verdict = 'SECURITY_POSTURE_IMPROVED'
    elif score_delta < 0 or len(new_vulnerabilities) > 0:
        verdict = 'SECURITY_POSTURE_REGRESSED'
    else:
        verdict = 'NO_CHANGE_DETECTED'

    return {
        'has_previous': baseline is not None,
        'verdict': verdict,
        'before': {
            'assessment_uuid': baseline['assessment_uuid'],
            'completed_at': baseline.get('completed_at') or baseline.get('started_at'),
            'security_score': b_score,
            'security_grade': baseline.get('security_grade'),
            'passed_checks': baseline.get('passed_checks', 0),
            'failed_checks': baseline.get('failed_checks', 0),
            'critical_count': baseline.get('critical_count', 0),
            'high_count': baseline.get('high_count', 0),
            'medium_count': baseline.get('medium_count', 0),
            'low_count': baseline.get('low_count', 0)
        } if baseline else None,
        'after': {
            'assessment_uuid': latest['assessment_uuid'],
            'completed_at': latest.get('completed_at') or latest.get('started_at'),
            'security_score': l_score,
            'security_grade': latest.get('security_grade'),
            'passed_checks': latest.get('passed_checks', 0),
            'failed_checks': latest.get('failed_checks', 0),
            'critical_count': latest.get('critical_count', 0),
            'high_count': latest.get('high_count', 0),
            'medium_count': latest.get('medium_count', 0),
            'low_count': latest.get('low_count', 0)
        },
        'score_delta': score_delta,
        'summary': {
            'fixed_count': len(fixed_vulnerabilities),
            'remaining_count': len(remaining_vulnerabilities),
            'new_or_regressed_count': len(new_vulnerabilities),
            'unchanged_passed_count': len(unchanged_passed)
        },
        'fixed_vulnerabilities': fixed_vulnerabilities,
        'remaining_vulnerabilities': remaining_vulnerabilities,
        'new_vulnerabilities': new_vulnerabilities,
        'unchanged_passed': unchanged_passed
    }


def get_previous_completed_assessment(target_uuid, exclude_uuid=None):
    """Returns the most recent completed assessment for a target (optionally excluding one UUID)."""
    recent = get_recent_live_assessments(limit=25, target_uuid=target_uuid)
    for row in recent:
        if row.get('status') == 'COMPLETED' and row['assessment_uuid'] != exclude_uuid:
            return get_live_assessment_by_uuid(row['assessment_uuid'])
    return None


def run_live_retest(target_uuid, path=None, baseline_assessment_uuid=None):
    """
    Executes a safe non-invasive live retest on an approved target, preserves the original
    assessment history & audit logs, updates remediation statuses based on real results,
    and returns a full before-and-after comparison.
    """
    from app.live_testing.scanner import run_live_assessment

    if baseline_assessment_uuid:
        baseline = get_live_assessment_by_uuid(baseline_assessment_uuid)
        if baseline and baseline.get('target_uuid') != target_uuid:
            baseline = None
    else:
        baseline = get_previous_completed_assessment(target_uuid)

    # Ensure baseline findings are tracked before comparing
    if baseline:
        ensure_remediations_synced(target_uuid)

    # Execute fresh real passive live assessment (enforces all authorization, expiry & SSRF checks)
    # Note: run_live_assessment automatically syncs remediations upon COMPLETED status.
    latest = run_live_assessment(target_uuid=target_uuid, path=path)
    remediations = get_remediations_for_target(target_uuid)

    comparison = compare_live_assessments(baseline, latest)

    log_live_audit(
        action='LIVE_RETEST_COMPLETED',
        outcome='SUCCESS',
        target_uuid=target_uuid,
        domain=latest['domain'],
        url=latest['target_url'],
        reason=(
            f"Retest {latest['assessment_uuid']} completed (score {latest['security_score']}/100, "
            f"delta {comparison['score_delta']:+d}, fixed={comparison['summary']['fixed_count']}, "
            f"remaining={comparison['summary']['remaining_count']})."
        ),
        actor='retest-engine'
    )

    return {
        'baseline_assessment': baseline,
        'latest_assessment': latest,
        'comparison': comparison,
        'remediations': remediations
    }


# ==============================================================================
# Downloadable Assessment Report Generators (HTML, Markdown, JSON)
# ==============================================================================

def _esc(val):
    return html.escape(str(val if val is not None else ''))


def generate_assessment_report_html(assessment, target=None, remediations=None, comparison=None):
    """Generates a self-contained, printable, downloadable HTML security assessment report."""
    remediations = remediations or []
    rem_by_key = {r['check_key']: r for r in remediations}
    meta = assessment.get('metadata') or {}
    findings = assessment.get('findings') or []

    # Before-and-after comparison section if available
    comp_html = ''
    if comparison and comparison.get('has_previous'):
        b = comparison['before']
        a = comparison['after']
        delta = comparison['score_delta']
        delta_str = f"+{delta}" if delta > 0 else str(delta)
        delta_color = '#059669' if delta > 0 else ('#dc2626' if delta < 0 else '#475569')
        fixed_list = ''.join(
            f"<li><strong>{_esc(f['title'])}</strong> ({_esc(f['affected_header'])}) — Confirmed Fixed</li>"
            for f in comparison['fixed_vulnerabilities']
        ) or "<li>None</li>"
        rem_list = ''.join(
            f"<li><strong>{_esc(f['title'])}</strong> ({_esc(f['affected_header'])}) — {_esc(f['severity'])}</li>"
            for f in comparison['remaining_vulnerabilities']
        ) or "<li>None</li>"

        comp_html = f"""
        <section class="card">
            <h2>Before-and-After Retest Comparison</h2>
            <div class="kpi-grid">
                <div class="kpi"><div class="label">Previous Score</div><div class="val">{_esc(b['security_score'])}/100 ({_esc(b['security_grade'])})</div><div class="sub">{_esc(b['assessment_uuid'])}</div></div>
                <div class="kpi"><div class="label">Latest Score</div><div class="val">{_esc(a['security_score'])}/100 ({_esc(a['security_grade'])})</div><div class="sub">{_esc(a['assessment_uuid'])}</div></div>
                <div class="kpi"><div class="label">Score Delta</div><div class="val" style="color:{delta_color};">{_esc(delta_str)}</div><div class="sub">{_esc(comparison['verdict'])}</div></div>
                <div class="kpi"><div class="label">Confirmed Fixed</div><div class="val" style="color:#059669;">{comparison['summary']['fixed_count']}</div><div class="sub">Remaining: {comparison['summary']['remaining_count']}</div></div>
            </div>
            <div class="two-col">
                <div><h3>Confirmed Fixed Vulnerabilities</h3><ul>{fixed_list}</ul></div>
                <div><h3>Remaining Vulnerabilities</h3><ul>{rem_list}</ul></div>
            </div>
        </section>
        """

    findings_rows = []
    for f in findings:
        key = f.get('check_key', '')
        rem = rem_by_key.get(key)
        header = get_affected_header(key)
        rem_status = rem['remediation_status'] if rem else ('Passed' if _is_passing_status(f.get('status')) else 'Open')
        rem_notes = (rem.get('remediation_notes') or '') if rem else ''
        instructions = get_remediation_instructions(key, f.get('remediation') or '')
        status_cls = 'pass' if _is_passing_status(f.get('status')) else 'fail'
        findings_rows.append(f"""
        <tr>
            <td><strong>{_esc(f.get('title'))}</strong><br><small>{_esc(f.get('category'))}</small></td>
            <td><code>{_esc(header)}</code></td>
            <td><span class="badge {status_cls}">{_esc(f.get('severity'))} / {_esc(f.get('status'))}</span></td>
            <td><span class="badge status">{_esc(rem_status)}</span></td>
            <td>
                <div><strong>Evidence:</strong> {_esc(f.get('evidence'))}</div>
                <div style="margin-top:6px;"><strong>Remediation:</strong> {_esc(instructions)}</div>
                {f'<div style="margin-top:6px;color:#0f766e;"><strong>Owner Notes:</strong> {_esc(rem_notes)}</div>' if rem_notes else ''}
            </td>
        </tr>
        """)

    auth_html = ''
    if target:
        auth_html = f"""
        <p><strong>Authorization Status:</strong> {_esc(target.get('auth_status'))} &bull;
           <strong>Verification Method:</strong> {_esc(target.get('verification_method'))} &bull;
           <strong>Approved By:</strong> {_esc(target.get('approved_by') or 'N/A')} &bull;
           <strong>Valid Window:</strong> {_esc(target.get('start_date'))} &rarr; {_esc(target.get('expiry_date'))}</p>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CyberFortify Live Security Assessment Report - {_esc(assessment.get('domain'))}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #0f172a; background: #f8fafc; margin: 0; padding: 24px; line-height: 1.5; }}
  .container {{ max-width: 1080px; margin: 0 auto; }}
  header {{ background: #0f172a; color: #fff; padding: 24px; border-radius: 10px; margin-bottom: 20px; }}
  header h1 {{ margin: 0 0 6px 0; font-size: 22px; }}
  header p {{ margin: 4px 0; color: #cbd5e1; font-size: 13px; }}
  .card {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 20px; margin-bottom: 20px; }}
  h2 {{ margin: 0 0 14px 0; font-size: 17px; color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px; }}
  h3 {{ font-size: 14px; margin: 12px 0 6px 0; }}
  .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 14px; }}
  .kpi {{ background: #f1f5f9; border-radius: 8px; padding: 12px; text-align: center; }}
  .kpi .label {{ font-size: 11px; text-transform: uppercase; color: #64748b; font-weight: 600; }}
  .kpi .val {{ font-size: 22px; font-weight: 700; margin-top: 4px; }}
  .kpi .sub {{ font-size: 11px; color: #64748b; margin-top: 2px; }}
  .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ text-align: left; padding: 10px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
  th {{ background: #f1f5f9; font-size: 11px; text-transform: uppercase; color: #475569; }}
  code {{ background: #f1f5f9; padding: 2px 5px; border-radius: 4px; font-size: 12px; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
  .badge.pass {{ background: #d1fae5; color: #065f46; }}
  .badge.fail {{ background: #fee2e2; color: #991b1b; }}
  .badge.status {{ background: #e0e7ff; color: #3730a3; }}
  footer {{ text-align: center; font-size: 12px; color: #64748b; margin-top: 24px; }}
</style>
</head>
<body>
<div class="container">
    <header>
        <h1>CyberFortify — Live Authorized Website Security Assessment Report</h1>
        <p><strong>Target:</strong> {_esc(assessment.get('target_url'))} &bull; <strong>Assessment ID:</strong> {_esc(assessment.get('assessment_uuid'))} &bull; <strong>Completed (UTC):</strong> {_esc(assessment.get('completed_at'))}</p>
        <p><strong>Resolved IP (Pinned):</strong> {_esc(meta.get('resolved_ip') or 'N/A')} &bull; <strong>TLS:</strong> {_esc(meta.get('tls_version') or 'N/A')} &bull; <strong>HTTP Status:</strong> {_esc(meta.get('https_status_code') or meta.get('http_status_code') or 'N/A')}</p>
        {auth_html}
    </header>

    <section class="card">
        <h2>Executive Security Score Summary</h2>
        <div class="kpi-grid">
            <div class="kpi"><div class="label">Security Score</div><div class="val">{_esc(assessment.get('security_score'))}/100</div><div class="sub">Grade {_esc(assessment.get('security_grade'))}</div></div>
            <div class="kpi"><div class="label">Passed Checks</div><div class="val" style="color:#059669;">{_esc(assessment.get('passed_checks'))}</div><div class="sub">of {_esc(assessment.get('total_checks'))} total</div></div>
            <div class="kpi"><div class="label">Failed / Warn</div><div class="val" style="color:#dc2626;">{_esc(assessment.get('failed_checks'))}</div><div class="sub">Actionable findings</div></div>
            <div class="kpi"><div class="label">Critical / High</div><div class="val">{_esc(assessment.get('critical_count'))} / {_esc(assessment.get('high_count'))}</div><div class="sub">Priority remediations</div></div>
            <div class="kpi"><div class="label">Medium / Low</div><div class="val">{_esc(assessment.get('medium_count'))} / {_esc(assessment.get('low_count'))}</div><div class="sub">Hardening items</div></div>
        </div>
    </section>

    {comp_html}

    <section class="card">
        <h2>Detailed Security Findings, Affected Headers &amp; Remediation</h2>
        <table>
            <thead>
                <tr>
                    <th>Finding</th>
                    <th>Affected Header / Surface</th>
                    <th>Severity &amp; Result</th>
                    <th>Remediation Status</th>
                    <th>Evidence, Instructions &amp; Notes</th>
                </tr>
            </thead>
            <tbody>
                {''.join(findings_rows)}
            </tbody>
        </table>
    </section>

    <footer>
        Generated by CyberFortify Live Authorized Website Security Assessment Platform &bull; Safe, Non-Invasive Passive Inspection Only
    </footer>
</div>
</body>
</html>"""


def generate_assessment_report_markdown(assessment, target=None, remediations=None, comparison=None):
    """Generates a downloadable Markdown assessment report."""
    remediations = remediations or []
    rem_by_key = {r['check_key']: r for r in remediations}
    meta = assessment.get('metadata') or {}
    lines = [
        f"# CyberFortify Live Security Assessment Report — {assessment.get('domain')}",
        "",
        f"- **Target URL:** {assessment.get('target_url')}",
        f"- **Assessment ID:** `{assessment.get('assessment_uuid')}`",
        f"- **Completed (UTC):** {assessment.get('completed_at')}",
        f"- **Resolved IP (Pinned):** `{meta.get('resolved_ip') or 'N/A'}`",
        f"- **TLS Protocol:** `{meta.get('tls_version') or 'N/A'}`",
        f"- **Security Score:** **{assessment.get('security_score')}/100 (Grade {assessment.get('security_grade')})**",
        f"- **Checks:** {assessment.get('passed_checks')} Passed / {assessment.get('failed_checks')} Failed or Warn ({assessment.get('total_checks')} Total)",
        f"- **Severity Breakdown:** Critical={assessment.get('critical_count')}, High={assessment.get('high_count')}, Medium={assessment.get('medium_count')}, Low={assessment.get('low_count')}",
    ]
    if target:
        lines.append(
            f"- **Authorization:** {target.get('auth_status')} (method: `{target.get('verification_method')}`, approved by: `{target.get('approved_by')}`)"
        )
    lines.append("")

    if comparison and comparison.get('has_previous'):
        b = comparison['before']
        a = comparison['after']
        lines.extend([
            "## Before-and-After Retest Comparison",
            "",
            f"- **Previous Assessment:** `{b['assessment_uuid']}` — **{b['security_score']}/100 (Grade {b['security_grade']})**",
            f"- **Latest Assessment:** `{a['assessment_uuid']}` — **{a['security_score']}/100 (Grade {a['security_grade']})**",
            f"- **Score Change:** `{comparison['score_delta']:+d}` ({comparison['verdict']})",
            f"- **Confirmed Fixed:** {comparison['summary']['fixed_count']} | **Remaining:** {comparison['summary']['remaining_count']} | **New/Regressed:** {comparison['summary']['new_or_regressed_count']}",
            ""
        ])

    lines.extend(["## Detailed Findings & Remediation", ""])
    for f in (assessment.get('findings') or []):
        key = f.get('check_key', '')
        rem = rem_by_key.get(key)
        header = get_affected_header(key)
        rem_status = rem['remediation_status'] if rem else ('Passed' if _is_passing_status(f.get('status')) else 'Open')
        lines.extend([
            f"### {f.get('title')} (`{f.get('severity')}` / `{f.get('status')}`)",
            f"- **Affected Header / Surface:** `{header}`",
            f"- **Remediation Status:** `{rem_status}`",
            f"- **Evidence:** {f.get('evidence')}",
            f"- **Remediation Instructions:** {get_remediation_instructions(key, f.get('remediation') or '')}",
        ])
        if rem and rem.get('remediation_notes'):
            lines.append(f"- **Owner Notes:** {rem['remediation_notes']}")
        lines.append("")

    return "\n".join(lines)
