import json
import uuid
import datetime
from app.database import get_db_connection

def save_assessment(target_url, scope_target, overall_status, findings, notes=None):
    """
    Persists a safe website security assessment and its granular findings to SQLite.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    assessment_uuid = f"assess-{uuid.uuid4().hex[:12]}"
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    passed_checks = sum(1 for f in findings if f.get('status') in ('DEFENDED', 'PASS'))
    failed_checks = sum(1 for f in findings if f.get('status') in ('VULNERABLE', 'FAIL', 'WARNING', 'WARN'))
    total_checks = len(findings)

    findings_json = json.dumps(findings)

    cursor.execute('''
    INSERT INTO assessments
    (assessment_uuid, timestamp, target_url, scope_target, overall_status, total_checks, passed_checks, failed_checks, findings_json, notes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        assessment_uuid,
        now,
        target_url,
        scope_target,
        overall_status,
        total_checks,
        passed_checks,
        failed_checks,
        findings_json,
        notes
    ))

    # Insert individual findings for detailed relational querying
    for f in findings:
        cursor.execute('''
        INSERT INTO assessment_findings
        (assessment_uuid, check_key, title, category, severity, status, evidence, remediation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            assessment_uuid,
            f.get('check_key', 'unknown'),
            f.get('title', 'Untitled Check'),
            f.get('category', 'General'),
            f.get('severity', 'MEDIUM'),
            f.get('status', 'VULNERABLE'),
            f.get('evidence', ''),
            f.get('remediation', '')
        ))

    conn.commit()
    conn.close()

    return get_assessment_by_uuid(assessment_uuid)

def get_assessment_by_uuid(assessment_uuid):
    """Retrieves full assessment record and findings by UUID."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM assessments WHERE assessment_uuid = ?', (assessment_uuid,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return None

    assessment = dict(row)
    try:
        assessment['findings'] = json.loads(assessment['findings_json'])
    except Exception:
        assessment['findings'] = []

    cursor.execute('SELECT * FROM assessment_findings WHERE assessment_uuid = ? ORDER BY id ASC', (assessment_uuid,))
    findings_rows = cursor.fetchall()
    assessment['granular_findings'] = [dict(r) for r in findings_rows]

    conn.close()
    return assessment

def get_recent_assessments(limit=25):
    """Retrieves recent assessment runs ordered by timestamp descending."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
    SELECT id, assessment_uuid, timestamp, target_url, scope_target, overall_status, total_checks, passed_checks, failed_checks, notes
    FROM assessments
    ORDER BY id DESC
    LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()
    conn.close()

    return [dict(r) for r in rows]

def get_latest_assessment():
    """Retrieves the single most recent assessment."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT assessment_uuid FROM assessments ORDER BY id DESC LIMIT 1')
    row = cursor.fetchone()
    conn.close()

    if row:
        return get_assessment_by_uuid(row['assessment_uuid'])
    return None

def get_assessment_summary():
    """Returns high-level statistics of all assessments conducted."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT count(*) as total FROM assessments')
    total = cursor.fetchone()['total']

    cursor.execute('''
    SELECT overall_status, count(*) as count
    FROM assessments
    GROUP BY overall_status
    ''')
    status_counts = {r['overall_status']: r['count'] for r in cursor.fetchall()}

    conn.close()
    return {
        'total_assessments': total,
        'status_breakdown': status_counts
    }
