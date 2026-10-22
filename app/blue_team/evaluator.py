from app.models.event_model import get_events_by_simulation
from app.models.alert_model import get_alerts_by_simulation
from app.models.simulation_model import record_evaluation

def evaluate_simulation_run(simulation_run_id):
    """
    Evaluates Blue Team detection performance for a simulation run.
    Calculates Expected vs Actual Alerts, Missed Detections (FN),
    False Positives (FP), Detection Rate (Recall), Precision, F1-Score,
    and Detection Latency.
    """
    events = get_events_by_simulation(simulation_run_id)
    alerts = get_alerts_by_simulation(simulation_run_id)

    # Map alerts by trigger_event_id
    alerts_by_event = {}
    for a in alerts:
        eid = a['trigger_event_id']
        alerts_by_event.setdefault(eid, []).append(a)

    true_positives = 0
    false_positives = 0
    false_negatives = 0
    true_negatives = 0

    scenario_stats = {}

    for e in events:
        eid = e['id']
        is_attack = bool(e['is_attack'])
        scenario = e.get('attack_scenario') or 'unclassified'
        has_alert = eid in alerts_by_event and len(alerts_by_event[eid]) > 0

        # Initialize scenario grouping
        if scenario not in scenario_stats:
            scenario_stats[scenario] = {
                'total': 0,
                'attacks': 0,
                'benign': 0,
                'detected': 0,
                'missed': 0,
                'false_positives': 0,
                'alerts_count': 0
            }

        s_stat = scenario_stats[scenario]
        s_stat['total'] += 1
        if has_alert:
            s_stat['alerts_count'] += len(alerts_by_event[eid])

        if is_attack:
            s_stat['attacks'] += 1
            if has_alert:
                true_positives += 1
                s_stat['detected'] += 1
            else:
                false_negatives += 1
                s_stat['missed'] += 1
        else:
            s_stat['benign'] += 1
            if has_alert:
                false_positives += 1
                s_stat['false_positives'] += 1
            else:
                true_negatives += 1

    # Detection Rate (Recall) = TP / (TP + FN)
    total_attacks = true_positives + false_negatives
    if total_attacks > 0:
        detection_rate = round((true_positives / total_attacks) * 100, 2)
    else:
        detection_rate = 100.0

    # Precision = TP / (TP + FP)
    predicted_attacks = true_positives + false_positives
    if predicted_attacks > 0:
        precision_rate = round((true_positives / predicted_attacks) * 100, 2)
    else:
        precision_rate = 100.0 if false_negatives == 0 else 0.0

    # F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
    p_dec = precision_rate / 100.0
    r_dec = detection_rate / 100.0
    if (p_dec + r_dec) > 0:
        f1_score = round(2 * (p_dec * r_dec) / (p_dec + r_dec), 3)
    else:
        f1_score = 0.0

    # Latency calculation
    latencies = [a['detection_latency_ms'] for a in alerts if a.get('detection_latency_ms') is not None]
    avg_latency_ms = round(sum(latencies) / len(latencies), 2) if latencies else 0.0

    # Scenario detection percentages
    for sc, data in scenario_stats.items():
        if data['attacks'] > 0:
            data['detection_rate'] = round((data['detected'] / data['attacks']) * 100, 1)
        else:
            data['detection_rate'] = 100.0 if data['false_positives'] == 0 else 0.0

    summary = {
        'total_events': len(events),
        'total_alerts': len(alerts),
        'scenario_breakdown': scenario_stats,
        'confusion_matrix': {
            'true_positives': true_positives,
            'false_positives': false_positives,
            'false_negatives': false_negatives,
            'true_negatives': true_negatives
        }
    }

    # Persist in evaluations table
    record_evaluation(
        simulation_run_id=simulation_run_id,
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        true_negatives=true_negatives,
        detection_rate=detection_rate,
        precision_rate=precision_rate,
        f1_score=f1_score,
        avg_latency_ms=avg_latency_ms,
        summary_json=summary
    )

    return {
        'simulation_run_id': simulation_run_id,
        'true_positives': true_positives,
        'false_positives': false_positives,
        'false_negatives': false_negatives,
        'true_negatives': true_negatives,
        'detection_rate': detection_rate,
        'precision_rate': precision_rate,
        'f1_score': f1_score,
        'avg_latency_ms': avg_latency_ms,
        'summary': summary
    }
