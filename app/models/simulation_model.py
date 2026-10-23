import uuid
import datetime
import json
from app.database import get_db_connection

def create_simulation_run(scenario_name, defense_config_snapshot=None, notes=None):
    """Creates a new simulation run entry and returns the generated run_uuid."""
    conn = get_db_connection()
    cursor = conn.cursor()
    run_uuid = str(uuid.uuid4())
    started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    snapshot_str = json.dumps(defense_config_snapshot) if defense_config_snapshot else '{}'

    cursor.execute('''
    INSERT INTO simulation_runs (
        run_uuid, started_at, scenario_name, defense_config_snapshot, notes
    )
    VALUES (?, ?, ?, ?, ?)
    ''', (run_uuid, started_at, scenario_name, snapshot_str, notes))
    conn.commit()
    conn.close()
    return run_uuid

def update_simulation_run(run_uuid, total_requests, attack_requests, benign_requests, blocked_by_defense, notes=None):
    """Marks a simulation run as completed and stores totals."""
    conn = get_db_connection()
    cursor = conn.cursor()
    completed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cursor.execute('''
    UPDATE simulation_runs
    SET completed_at = ?, total_requests = ?, attack_requests = ?,
        benign_requests = ?, blocked_by_defense = ?, notes = COALESCE(?, notes)
    WHERE run_uuid = ?
    ''', (completed_at, total_requests, attack_requests, benign_requests, blocked_by_defense, notes, run_uuid))
    conn.commit()
    conn.close()

def get_simulation_run(run_uuid):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM simulation_runs WHERE run_uuid = ?', (run_uuid,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    data = dict(row)
    if data.get('defense_config_snapshot'):
        try:
            data['defense_config'] = json.loads(data['defense_config_snapshot'])
        except Exception:
            data['defense_config'] = {}
    return data

def get_all_simulation_runs(limit=20):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM simulation_runs ORDER BY id DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()
    results = []
    for r in rows:
        d = dict(r)
        if d.get('defense_config_snapshot'):
            try:
                d['defense_config'] = json.loads(d['defense_config_snapshot'])
            except Exception:
                d['defense_config'] = {}
        results.append(d)
    return results

def record_evaluation(
    simulation_run_id,
    true_positives,
    false_positives,
    false_negatives,
    true_negatives,
    detection_rate,
    precision_rate,
    f1_score,
    avg_latency_ms,
    summary_json=None
):
    conn = get_db_connection()
    cursor = conn.cursor()
    evaluated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    summary_str = json.dumps(summary_json) if summary_json else '{}'

    cursor.execute('''
    INSERT INTO evaluations (
        simulation_run_id, evaluated_at, true_positives, false_positives,
        false_negatives, true_negatives, detection_rate, precision_rate,
        f1_score, avg_latency_ms, summary_json
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        simulation_run_id, evaluated_at, true_positives, false_positives,
        false_negatives, true_negatives, detection_rate, precision_rate,
        f1_score, avg_latency_ms, summary_str
    ))
    conn.commit()
    conn.close()

def get_latest_evaluation(simulation_run_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
    SELECT * FROM evaluations 
    WHERE simulation_run_id = ? 
    ORDER BY id DESC LIMIT 1
    ''', (simulation_run_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    data = dict(row)
    if data.get('summary_json'):
        try:
            data['summary'] = json.loads(data['summary_json'])
        except Exception:
            data['summary'] = {}
    return data

def get_overall_metrics():
    """Computes aggregate cybersecurity metrics across all simulations and evaluations."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Total runs
    cursor.execute('SELECT COUNT(*) as total_runs FROM simulation_runs')
    total_runs = cursor.fetchone()['total_runs']

    # Total events & total attacks
    cursor.execute('SELECT COUNT(*) as total_events, SUM(is_attack) as total_attacks FROM events')
    events_row = cursor.fetchone()
    total_events = events_row['total_events'] or 0
    total_attacks = events_row['total_attacks'] or 0

    # Total alerts
    cursor.execute('SELECT COUNT(*) as total_alerts FROM alerts')
    total_alerts = cursor.fetchone()['total_alerts'] or 0

    # Aggregate Evaluation numbers
    cursor.execute('''
    SELECT 
        AVG(detection_rate) as avg_det_rate,
        AVG(precision_rate) as avg_precision,
        AVG(f1_score) as avg_f1,
        AVG(avg_latency_ms) as avg_latency
    FROM evaluations
    ''')
    eval_row = cursor.fetchone()
    avg_det_rate = round(eval_row['avg_det_rate'] or 0.0, 1)
    avg_precision = round(eval_row['avg_precision'] or 0.0, 1)
    avg_f1 = round(eval_row['avg_f1'] or 0.0, 2)
    avg_latency = round(eval_row['avg_latency'] or 0.0, 2)

    # Scenario breakdown for live chart visualizations
    cursor.execute('''
    SELECT 
        e.attack_scenario,
        SUM(e.is_attack) as attacks,
        COUNT(DISTINCT CASE WHEN a.id IS NOT NULL AND e.is_attack = 1 THEN e.id END) as detected
    FROM events e
    LEFT JOIN alerts a ON a.trigger_event_id = e.id
    WHERE e.attack_scenario IS NOT NULL
    GROUP BY e.attack_scenario
    ''')
    scenario_rows = cursor.fetchall()
    scenario_breakdown = {}
    for r in scenario_rows:
        sc = r['attack_scenario']
        scenario_breakdown[sc] = {
            'attacks': r['attacks'] or 0,
            'detected': r['detected'] or 0
        }

    conn.close()
    return {
        'total_runs': total_runs,
        'total_events': total_events,
        'total_attacks': total_attacks,
        'total_alerts': total_alerts,
        'detection_rate': avg_det_rate,
        'precision_rate': avg_precision,
        'f1_score': avg_f1,
        'avg_latency_ms': avg_latency,
        'scenario_breakdown': scenario_breakdown
    }
