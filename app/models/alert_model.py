import uuid
import datetime
from app.database import get_db_connection

def create_alert(
    rule_id,
    rule_name,
    severity,
    description,
    trigger_event_id=None,
    detection_latency_ms=0.0,
    simulation_run_id=None,
    timestamp=None
):
    """Inserts a detected security alert into the alerts table."""
    conn = get_db_connection()
    cursor = conn.cursor()
    alert_uuid = str(uuid.uuid4())
    if not timestamp:
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    cursor.execute('''
    INSERT INTO alerts (
        alert_uuid, timestamp, rule_id, rule_name, severity,
        description, trigger_event_id, detection_latency_ms,
        simulation_run_id, status
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'NEW')
    ''', (
        alert_uuid, timestamp, rule_id, rule_name, severity,
        description, trigger_event_id, detection_latency_ms,
        simulation_run_id
    ))
    alert_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return alert_id

def get_alerts(limit=50, offset=0, severity=None, status=None, rule_id=None, simulation_run_id=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    query = '''
    SELECT a.*, e.endpoint, e.payload_data, e.ip_address, e.user_identifier, e.attack_scenario
    FROM alerts a
    LEFT JOIN events e ON a.trigger_event_id = e.id
    WHERE 1=1
    '''
    params = []

    if severity:
        query += ' AND a.severity = ?'
        params.append(severity)
    if status:
        query += ' AND a.status = ?'
        params.append(status)
    if rule_id:
        query += ' AND a.rule_id = ?'
        params.append(rule_id)
    if simulation_run_id:
        query += ' AND a.simulation_run_id = ?'
        params.append(simulation_run_id)

    query += ' ORDER BY a.id DESC LIMIT ? OFFSET ?'
    params.extend([limit, offset])

    cursor.execute(query, params)
    rows = cursor.fetchall()

    # Total matching count
    count_query = 'SELECT COUNT(*) as total FROM alerts WHERE 1=1'
    count_params = []
    if severity:
        count_query += ' AND severity = ?'
        count_params.append(severity)
    if status:
        count_query += ' AND status = ?'
        count_params.append(status)
    if rule_id:
        count_query += ' AND rule_id = ?'
        count_params.append(rule_id)
    if simulation_run_id:
        count_query += ' AND simulation_run_id = ?'
        count_params.append(simulation_run_id)

    cursor.execute(count_query, count_params)
    total = cursor.fetchone()['total']
    conn.close()

    return [dict(r) for r in rows], total

def get_alert_by_id(alert_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
    SELECT a.*, e.endpoint, e.payload_data, e.ip_address, e.user_identifier, e.attack_scenario, e.http_method, e.status_code
    FROM alerts a
    LEFT JOIN events e ON a.trigger_event_id = e.id
    WHERE a.id = ?
    ''', (alert_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def update_alert_status(alert_id, status):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE alerts SET status = ? WHERE id = ?', (status, alert_id))
    conn.commit()
    conn.close()
    return get_alert_by_id(alert_id)

def get_alerts_by_simulation(simulation_run_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
    SELECT * FROM alerts 
    WHERE simulation_run_id = ?
    ORDER BY id ASC
    ''', (simulation_run_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_alerts_summary():
    """Returns alert counts grouped by severity."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
    SELECT severity, COUNT(*) as count 
    FROM alerts 
    GROUP BY severity
    ''')
    rows = cursor.fetchall()
    conn.close()
    summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for r in rows:
        summary[r['severity']] = r['count']
    return summary
