import datetime
from app.database import get_db_connection

def get_all_defenses():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM defense_settings ORDER BY id ASC')
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_defense(defense_key):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM defense_settings WHERE defense_key = ?', (defense_key,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def is_defense_enabled(defense_key):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT is_enabled FROM defense_settings WHERE defense_key = ?', (defense_key,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return bool(row['is_enabled'])
    return False

def set_defense_state(defense_key, is_enabled):
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cursor.execute('''
    UPDATE defense_settings
    SET is_enabled = ?, updated_at = ?
    WHERE defense_key = ?
    ''', (1 if is_enabled else 0, now, defense_key))
    conn.commit()
    conn.close()
    return get_defense(defense_key)

def get_defense_snapshot():
    defenses = get_all_defenses()
    return {d['defense_key']: bool(d['is_enabled']) for d in defenses}
