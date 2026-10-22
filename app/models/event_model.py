import uuid
import datetime
from app.database import get_db_connection

def log_event(
    endpoint,
    http_method,
    status_code,
    ip_address='127.0.0.1',
    user_identifier=None,
    payload_data=None,
    is_attack=0,
    attack_scenario=None,
    expected_rule=None,
    simulation_run_id=None,
    timestamp=None
):
    """Inserts a structured audit security event into the events table."""
    conn = get_db_connection()
    cursor = conn.cursor()
    event_uuid = str(uuid.uuid4())
    if not timestamp:
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    cursor.execute('''
    INSERT INTO events (
        event_uuid, timestamp, ip_address, endpoint, http_method,
        status_code, user_identifier, payload_data, is_attack,
        attack_scenario, expected_rule, simulation_run_id
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        event_uuid, timestamp, ip_address, endpoint, http_method,
        status_code, user_identifier, str(payload_data) if payload_data else None,
        1 if is_attack else 0, attack_scenario, expected_rule, simulation_run_id
    ))
    event_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return event_id

def get_event_by_id(event_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM events WHERE id = ?', (event_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_events(limit=50, offset=0, scenario=None, is_attack=None, search=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    query = 'SELECT * FROM events WHERE 1=1'
    params = []

    if scenario:
        query += ' AND attack_scenario = ?'
        params.append(scenario)
    if is_attack is not None:
        query += ' AND is_attack = ?'
        params.append(1 if is_attack else 0)
    if search:
        query += ' AND (payload_data LIKE ? OR endpoint LIKE ? OR user_identifier LIKE ?)'
        wildcard = f'%{search}%'
        params.extend([wildcard, wildcard, wildcard])

    query += ' ORDER BY id DESC LIMIT ? OFFSET ?'
    params.extend([limit, offset])

    cursor.execute(query, params)
    rows = cursor.fetchall()

    # Get total count matching same filters
    count_query = 'SELECT COUNT(*) as total FROM events WHERE 1=1'
    count_params = []
    if scenario:
        count_query += ' AND attack_scenario = ?'
        count_params.append(scenario)
    if is_attack is not None:
        count_query += ' AND is_attack = ?'
        count_params.append(1 if is_attack else 0)
    if search:
        count_query += ' AND (payload_data LIKE ? OR endpoint LIKE ? OR user_identifier LIKE ?)'
        wildcard = f'%{search}%'
        count_params.extend([wildcard, wildcard, wildcard])
    
    cursor.execute(count_query, count_params)
    total = cursor.fetchone()['total']
    conn.close()

    return [dict(r) for r in rows], total

def get_events_by_simulation(simulation_run_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM events WHERE simulation_run_id = ? ORDER BY id ASC', (simulation_run_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_recent_failed_logins(user_identifier=None, ip_address='127.0.0.1', window_seconds=60):
    """Retrieves recent failed login attempts within window_seconds."""
    conn = get_db_connection()
    cursor = conn.cursor()
    threshold_time = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=window_seconds)).isoformat()

    query = '''
    SELECT * FROM events 
    WHERE endpoint LIKE '%/login%'
    AND status_code IN (401, 429)
    AND timestamp >= ?
    '''
    params = [threshold_time]

    if user_identifier:
        query += ' AND user_identifier = ?'
        params.append(user_identifier)
    elif ip_address:
        query += ' AND ip_address = ?'
        params.append(ip_address)

    query += ' ORDER BY id DESC'
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]
