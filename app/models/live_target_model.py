import json
import uuid
import secrets
import datetime
from app.database import get_db_connection

VALID_AUTH_STATUSES = {
    'PENDING_VERIFICATION',
    'PENDING_APPROVAL',
    'APPROVED',
    'REJECTED',
    'EXPIRED',
    'REVOKED'
}

VALID_VERIFICATION_METHODS = {
    'http_file',
    'dns_txt',
    'meta_tag',
    'signed_attestation'
}


def utc_now():
    """Returns current timezone-aware UTC datetime."""
    return datetime.datetime.now(datetime.timezone.utc)


def utc_now_iso():
    """Returns current UTC timestamp in ISO-8601 format."""
    return utc_now().isoformat()


def parse_iso_datetime(dt_str):
    """Parses ISO-8601 datetime string into timezone-aware UTC datetime."""
    if not dt_str or not isinstance(dt_str, str):
        return None
    s = dt_str.strip()
    if s.endswith('Z'):
        s = s[:-1] + '+00:00'
    try:
        dt = datetime.datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(datetime.timezone.utc)
    except ValueError:
        return None


def _hydrate_target(row):
    """Converts a SQLite Row from live_targets into a clean dictionary."""
    if not row:
        return None
    d = dict(row)
    try:
        d['approved_paths'] = json.loads(d.get('approved_paths') or '["/"]')
    except Exception:
        d['approved_paths'] = ['/']
    try:
        d['allowed_methods'] = json.loads(d.get('allowed_methods') or '["GET", "HEAD"]')
    except Exception:
        d['allowed_methods'] = ['GET', 'HEAD']
    d['owner_consent'] = bool(d.get('owner_consent'))
    d['is_verified'] = bool(d.get('is_verified'))

    # Compute real-time window flags
    now = utc_now()
    start_dt = parse_iso_datetime(d.get('start_date'))
    expiry_dt = parse_iso_datetime(d.get('expiry_date'))
    d['is_expired'] = bool(expiry_dt and now >= expiry_dt)
    d['is_before_start'] = bool(start_dt and now < start_dt)
    d['is_scannable'] = (
        d['auth_status'] == 'APPROVED'
        and d['is_verified']
        and d['owner_consent']
        and not d['is_expired']
        and not d['is_before_start']
    )
    return d


def log_live_audit(
    action,
    outcome,
    target_uuid=None,
    domain=None,
    url=None,
    http_method=None,
    resolved_ip=None,
    status_code=None,
    reason=None,
    actor='system'
):
    """Records a detailed security and compliance audit entry in SQLite."""
    conn = get_db_connection()
    cursor = conn.cursor()
    log_uuid = f"laudit-{uuid.uuid4().hex[:12]}"
    now = utc_now_iso()
    cursor.execute('''
        INSERT INTO live_audit_logs (
            log_uuid, timestamp, target_uuid, domain, action, url,
            http_method, resolved_ip, status_code, outcome, reason, actor
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        log_uuid,
        now,
        target_uuid,
        domain,
        action,
        url,
        http_method,
        resolved_ip,
        status_code,
        outcome,
        reason,
        actor
    ))
    conn.commit()
    conn.close()
    return log_uuid


def get_live_audit_logs(limit=100, target_uuid=None, outcome=None):
    """Retrieves recent live security testing audit logs."""
    conn = get_db_connection()
    cursor = conn.cursor()
    query = 'SELECT * FROM live_audit_logs WHERE 1=1'
    params = []
    if target_uuid:
        query += ' AND target_uuid = ?'
        params.append(target_uuid)
    if outcome:
        query += ' AND outcome = ?'
        params.append(outcome)
    query += ' ORDER BY id DESC LIMIT ?'
    params.append(int(limit))
    cursor.execute(query, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def expire_outdated_authorizations():
    """
    Automatically transitions any APPROVED (or pending) targets whose expiry_date has passed
    into EXPIRED status in SQLite, writing an audit log entry for each expired target.
    Returns count of newly expired targets.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    now = utc_now()
    now_iso = now.isoformat()

    cursor.execute('''
        SELECT target_uuid, domain, target_url, expiry_date, auth_status
        FROM live_targets
        WHERE auth_status IN ('APPROVED', 'PENDING_APPROVAL', 'PENDING_VERIFICATION')
    ''')
    rows = cursor.fetchall()
    expired_records = []

    for row in rows:
        exp_dt = parse_iso_datetime(row['expiry_date'])
        if exp_dt and now >= exp_dt:
            cursor.execute('''
                UPDATE live_targets
                SET auth_status = 'EXPIRED', updated_at = ?
                WHERE target_uuid = ?
            ''', (now_iso, row['target_uuid']))
            expired_records.append(dict(row))

    conn.commit()
    conn.close()

    for rec in expired_records:
        log_live_audit(
            action='AUTHORIZATION_AUTO_EXPIRED',
            outcome='EXPIRED',
            target_uuid=rec['target_uuid'],
            domain=rec['domain'],
            url=rec['target_url'],
            reason=f"Authorization expired automatically after validity end ({rec['expiry_date']}).",
            actor='system'
        )

    return len(expired_records)


def create_live_target(
    target_url,
    domain,
    owner_name,
    owner_email,
    owner_consent,
    verification_method,
    approved_paths,
    allowed_methods,
    start_date,
    expiry_date,
    max_request_rate=10,
    owner_user_id=None
):
    """Registers a new live website target with a unique ownership verification token."""
    target_uuid = f"target-{uuid.uuid4().hex[:12]}"
    verification_token = f"cyberfortify-verify={secrets.token_hex(16)}"
    now = utc_now_iso()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO live_targets (
            target_uuid, target_url, domain, auth_status,
            owner_name, owner_email, owner_consent,
            verification_method, verification_token, is_verified,
            approved_paths, allowed_methods,
            start_date, expiry_date, max_request_rate,
            owner_user_id, created_at, updated_at
        )
        VALUES (?, ?, ?, 'PENDING_VERIFICATION', ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        target_uuid,
        target_url,
        domain.lower(),
        owner_name.strip(),
        owner_email.strip(),
        1 if owner_consent else 0,
        verification_method,
        verification_token,
        json.dumps(approved_paths),
        json.dumps(allowed_methods),
        start_date,
        expiry_date,
        int(max_request_rate),
        owner_user_id,
        now,
        now
    ))
    conn.commit()
    conn.close()

    log_live_audit(
        action='TARGET_REGISTERED',
        outcome='SUCCESS',
        target_uuid=target_uuid,
        domain=domain.lower(),
        url=target_url,
        reason=f"Registered by {owner_name} ({owner_email}); verification method={verification_method}.",
        actor=owner_email.strip()
    )

    return get_live_target_by_uuid(target_uuid)


def get_live_target_by_uuid(target_uuid):
    """Fetches a single live target by UUID after enforcing automatic expiration."""
    expire_outdated_authorizations()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM live_targets WHERE target_uuid = ?', (target_uuid,))
    row = cursor.fetchone()
    conn.close()
    return _hydrate_target(row)


def get_all_live_targets(status_filter=None):
    """Lists all registered live targets after enforcing automatic expiration."""
    expire_outdated_authorizations()
    conn = get_db_connection()
    cursor = conn.cursor()
    if status_filter and status_filter.upper() in VALID_AUTH_STATUSES:
        cursor.execute(
            'SELECT * FROM live_targets WHERE auth_status = ? ORDER BY id DESC',
            (status_filter.upper(),)
        )
    else:
        cursor.execute('SELECT * FROM live_targets ORDER BY id DESC')
    rows = [_hydrate_target(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def get_approved_target_by_domain(domain):
    """Returns the most recent active APPROVED target matching a domain, if any."""
    expire_outdated_authorizations()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM live_targets
        WHERE domain = ? AND auth_status = 'APPROVED' AND is_verified = 1 AND owner_consent = 1
        ORDER BY id DESC LIMIT 1
    ''', (domain.lower(),))
    row = cursor.fetchone()
    conn.close()
    return _hydrate_target(row)


def mark_target_verified(target_uuid, verification_notes=None, actor='owner'):
    """Marks a target's website-owner authorization proof as verified and moves it to PENDING_APPROVAL."""
    target = get_live_target_by_uuid(target_uuid)
    if not target:
        return None, "Target not found."
    if target['auth_status'] in ('EXPIRED', 'REJECTED', 'REVOKED'):
        return None, f"Cannot verify target in '{target['auth_status']}' state."
    if not target['owner_consent']:
        return None, "Explicit website-owner authorization consent is required before verification."

    now = utc_now_iso()
    new_status = 'APPROVED' if target['auth_status'] == 'APPROVED' else 'PENDING_APPROVAL'

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE live_targets
        SET is_verified = 1, verified_at = ?, verification_notes = ?, auth_status = ?, updated_at = ?
        WHERE target_uuid = ?
    ''', (now, verification_notes or 'Ownership verification token confirmed.', new_status, now, target_uuid))
    conn.commit()
    conn.close()

    log_live_audit(
        action='AUTHORIZATION_VERIFIED',
        outcome='SUCCESS',
        target_uuid=target_uuid,
        domain=target['domain'],
        url=target['target_url'],
        reason=verification_notes or 'Ownership verification completed.',
        actor=actor
    )
    return get_live_target_by_uuid(target_uuid), None


def approve_live_target(target_uuid, approved_by='admin'):
    """Administrator approves a verified target for live authorized testing."""
    target = get_live_target_by_uuid(target_uuid)
    if not target:
        return None, "Target not found."
    if target['is_expired'] or target['auth_status'] == 'EXPIRED':
        return None, "Cannot approve target: testing expiry date has already passed."
    if not target['owner_consent']:
        return None, "Cannot approve target: explicit website-owner authorization consent is missing."
    if not target['is_verified']:
        return None, "Cannot approve target: ownership verification must be completed first."

    now = utc_now_iso()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE live_targets
        SET auth_status = 'APPROVED', approved_by = ?, approved_at = ?, rejection_reason = NULL, updated_at = ?
        WHERE target_uuid = ?
    ''', (approved_by, now, now, target_uuid))
    conn.commit()
    conn.close()

    log_live_audit(
        action='TARGET_APPROVED',
        outcome='APPROVED',
        target_uuid=target_uuid,
        domain=target['domain'],
        url=target['target_url'],
        reason=f"Approved by administrator '{approved_by}'. Valid until {target['expiry_date']}.",
        actor=approved_by
    )
    return get_live_target_by_uuid(target_uuid), None


def reject_live_target(target_uuid, reason='Rejected by administrator', rejected_by='admin'):
    """Administrator rejects or revokes a target registration."""
    target = get_live_target_by_uuid(target_uuid)
    if not target:
        return None, "Target not found."

    now = utc_now_iso()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE live_targets
        SET auth_status = 'REJECTED', rejection_reason = ?, approved_by = ?, updated_at = ?
        WHERE target_uuid = ?
    ''', (reason, rejected_by, now, target_uuid))
    conn.commit()
    conn.close()

    log_live_audit(
        action='TARGET_REJECTED',
        outcome='REJECTED',
        target_uuid=target_uuid,
        domain=target['domain'],
        url=target['target_url'],
        reason=reason,
        actor=rejected_by
    )
    return get_live_target_by_uuid(target_uuid), None


def check_target_authorization(target_uuid):
    """
    Strictly verifies whether a target is currently authorized for live testing.
    Returns (is_authorized: bool, error_code: str | None, error_message: str | None, target: dict | None).
    """
    target = get_live_target_by_uuid(target_uuid)
    if not target:
        return False, 'TARGET_NOT_FOUND', f"Target '{target_uuid}' is not registered.", None

    if not target['owner_consent']:
        return False, 'NO_OWNER_CONSENT', "Explicit website-owner authorization consent was not provided.", target

    if not target['is_verified']:
        return False, 'NOT_VERIFIED', "Target domain ownership has not been verified.", target

    if target['auth_status'] == 'EXPIRED' or target['is_expired']:
        return False, 'AUTHORIZATION_EXPIRED', (
            f"Authorization for '{target['domain']}' expired at {target['expiry_date']}. "
            "Testing is automatically blocked."
        ), target

    if target['auth_status'] != 'APPROVED':
        return False, 'NOT_APPROVED', (
            f"Target '{target['domain']}' is in status '{target['auth_status']}'. "
            "Administrator approval is required before live testing."
        ), target

    if target['is_before_start']:
        return False, 'NOT_YET_ACTIVE', (
            f"Testing window for '{target['domain']}' has not started yet (starts {target['start_date']})."
        ), target

    return True, None, None, target


# ==============================================================================
# Live Assessments Persistence
# ==============================================================================

def compute_security_score(findings):
    """
    Computes a transparent 0-100 security score and letter grade from real scan findings.
    Deductions apply only to failed/warning findings.
    """
    if not findings:
        return 0, 'F'

    score = 100
    penalties = {
        'CRITICAL': 25,
        'HIGH': 15,
        'MEDIUM': 8,
        'LOW': 3,
        'INFO': 0
    }
    for f in findings:
        status = (f.get('status') or '').upper()
        sev = (f.get('severity') or 'INFO').upper()
        if status in ('FAIL', 'VULNERABLE'):
            score -= penalties.get(sev, 5)
        elif status in ('WARN', 'WARNING'):
            score -= max(1, penalties.get(sev, 4) // 2)

    score = max(0, min(100, score))
    if score >= 90:
        grade = 'A'
    elif score >= 80:
        grade = 'B'
    elif score >= 70:
        grade = 'C'
    elif score >= 55:
        grade = 'D'
    else:
        grade = 'F'
    return score, grade


def create_live_assessment_record(target_uuid, target_url, domain):
    """Creates an initial RUNNING live assessment record to track progress."""
    assessment_uuid = f"live-{uuid.uuid4().hex[:12]}"
    now = utc_now_iso()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO live_assessments (
            assessment_uuid, target_uuid, target_url, domain,
            started_at, status, progress_percent, current_step
        )
        VALUES (?, ?, ?, ?, ?, 'RUNNING', 5, 'Validating authorization and target security')
    ''', (assessment_uuid, target_uuid, target_url, domain.lower(), now))
    conn.commit()
    conn.close()
    return assessment_uuid


def update_live_assessment_progress(assessment_uuid, progress_percent, current_step):
    """Updates progress percentage and current step during a live scan."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE live_assessments
        SET progress_percent = ?, current_step = ?
        WHERE assessment_uuid = ?
    ''', (int(progress_percent), current_step, assessment_uuid))
    conn.commit()
    conn.close()


def finalize_live_assessment(assessment_uuid, findings, metadata=None, status='COMPLETED', error_message=None):
    """Persists final scan findings, score, counts, and metadata into SQLite."""
    now = utc_now_iso()
    score, grade = compute_security_score(findings) if status == 'COMPLETED' else (0, 'N/A')

    passed = sum(1 for f in findings if (f.get('status') or '').upper() in ('PASS', 'DEFENDED'))
    failed = sum(1 for f in findings if (f.get('status') or '').upper() in ('FAIL', 'VULNERABLE', 'WARNING', 'WARN'))
    total = len(findings)

    def _count_sev(sev):
        return sum(
            1 for f in findings
            if (f.get('severity') or '').upper() == sev
            and (f.get('status') or '').upper() not in ('PASS', 'DEFENDED')
        )

    critical_count = _count_sev('CRITICAL')
    high_count = _count_sev('HIGH')
    medium_count = _count_sev('MEDIUM')
    low_count = _count_sev('LOW')
    info_count = sum(1 for f in findings if (f.get('status') or '').upper() in ('PASS', 'DEFENDED') or (f.get('severity') or '').upper() == 'INFO')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE live_assessments
        SET completed_at = ?, status = ?, progress_percent = ?, current_step = ?,
            security_score = ?, security_grade = ?,
            total_checks = ?, passed_checks = ?, failed_checks = ?,
            critical_count = ?, high_count = ?, medium_count = ?, low_count = ?, info_count = ?,
            findings_json = ?, metadata_json = ?, error_message = ?
        WHERE assessment_uuid = ?
    ''', (
        now,
        status,
        100 if status == 'COMPLETED' else 0,
        'Completed' if status == 'COMPLETED' else (error_message or 'Failed'),
        score,
        grade,
        total,
        passed,
        failed,
        critical_count,
        high_count,
        medium_count,
        low_count,
        info_count,
        json.dumps(findings),
        json.dumps(metadata or {}),
        error_message,
        assessment_uuid
    ))

    for f in findings:
        cursor.execute('''
            INSERT INTO live_assessment_findings (
                assessment_uuid, check_key, title, category, severity, status, evidence, remediation
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            assessment_uuid,
            f.get('check_key', 'unknown'),
            f.get('title', 'Untitled Check'),
            f.get('category', 'General'),
            f.get('severity', 'INFO'),
            f.get('status', 'FAIL'),
            f.get('evidence', ''),
            f.get('remediation', '')
        ))

    conn.commit()
    conn.close()
    return get_live_assessment_by_uuid(assessment_uuid)


def get_live_assessment_by_uuid(assessment_uuid):
    """Fetches a full live assessment record including parsed findings and metadata."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM live_assessments WHERE assessment_uuid = ?', (assessment_uuid,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None
    rec = dict(row)
    try:
        rec['findings'] = json.loads(rec.get('findings_json') or '[]')
    except Exception:
        rec['findings'] = []
    try:
        rec['metadata'] = json.loads(rec.get('metadata_json') or '{}')
    except Exception:
        rec['metadata'] = {}
    cursor.execute(
        'SELECT * FROM live_assessment_findings WHERE assessment_uuid = ? ORDER BY id ASC',
        (assessment_uuid,)
    )
    rec['granular_findings'] = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rec


def get_recent_live_assessments(limit=30, target_uuid=None):
    """Lists recent live website assessments."""
    conn = get_db_connection()
    cursor = conn.cursor()
    if target_uuid:
        cursor.execute('''
            SELECT id, assessment_uuid, target_uuid, target_url, domain,
                   started_at, completed_at, status, progress_percent, current_step,
                   security_score, security_grade, total_checks, passed_checks, failed_checks,
                   critical_count, high_count, medium_count, low_count, info_count, error_message
            FROM live_assessments
            WHERE target_uuid = ?
            ORDER BY id DESC LIMIT ?
        ''', (target_uuid, int(limit)))
    else:
        cursor.execute('''
            SELECT id, assessment_uuid, target_uuid, target_url, domain,
                   started_at, completed_at, status, progress_percent, current_step,
                   security_score, security_grade, total_checks, passed_checks, failed_checks,
                   critical_count, high_count, medium_count, low_count, info_count, error_message
            FROM live_assessments
            ORDER BY id DESC LIMIT ?
        ''', (int(limit),))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows
