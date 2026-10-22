import datetime
from app.models.event_model import get_events_by_simulation, get_events
from app.models.alert_model import create_alert, get_alerts_by_simulation
from app.blue_team.rules import (
    evaluate_brute_force_rule,
    evaluate_unauthorized_access_rule,
    evaluate_sqli_rule,
    evaluate_xss_rule,
    DETECTION_RULES
)

# Map rule IDs to rule metadata
RULE_META = {r['rule_id']: r for r in DETECTION_RULES}

def run_detection_pipeline(simulation_run_id=None):
    """
    Ingests events and evaluates detection rules.
    Computes detection latency and generates structured alerts.
    """
    if simulation_run_id:
        events = get_events_by_simulation(simulation_run_id)
    else:
        events, _ = get_events(limit=100)

    # Preload existing alerts to avoid duplicate alerts for the same event and rule
    existing_alerts = get_alerts_by_simulation(simulation_run_id) if simulation_run_id else []
    existing_pairs = set((a['trigger_event_id'], a['rule_id']) for a in existing_alerts)

    new_alerts = []

    for event in events:
        event_id = event['id']
        event_time_str = event['timestamp']
        
        # Calculate real-time detection latency
        try:
            event_dt = datetime.datetime.fromisoformat(event_time_str)
            now_dt = datetime.datetime.now(datetime.timezone.utc)
            latency_ms = max(round((now_dt - event_dt).total_seconds() * 1000, 2), 1.25)
        except Exception:
            latency_ms = 2.50

        # 1. Check Brute Force
        triggered, reason = evaluate_brute_force_rule(event, events)
        if triggered and (event_id, 'RULE_BRUTE_FORCE_01') not in existing_pairs:
            meta = RULE_META['RULE_BRUTE_FORCE_01']
            aid = create_alert(
                rule_id=meta['rule_id'],
                rule_name=meta['name'],
                severity=meta['severity'],
                description=reason,
                trigger_event_id=event_id,
                detection_latency_ms=latency_ms,
                simulation_run_id=simulation_run_id
            )
            new_alerts.append(aid)
            existing_pairs.add((event_id, 'RULE_BRUTE_FORCE_01'))

        # 2. Check Unauthorized Access
        triggered, reason = evaluate_unauthorized_access_rule(event)
        if triggered and (event_id, 'RULE_UNAUTHORIZED_ACCESS_01') not in existing_pairs:
            meta = RULE_META['RULE_UNAUTHORIZED_ACCESS_01']
            aid = create_alert(
                rule_id=meta['rule_id'],
                rule_name=meta['name'],
                severity=meta['severity'],
                description=reason,
                trigger_event_id=event_id,
                detection_latency_ms=latency_ms,
                simulation_run_id=simulation_run_id
            )
            new_alerts.append(aid)
            existing_pairs.add((event_id, 'RULE_UNAUTHORIZED_ACCESS_01'))

        # 3. Check SQL Injection
        triggered, reason = evaluate_sqli_rule(event)
        if triggered and (event_id, 'RULE_SQLI_DETECTED_01') not in existing_pairs:
            meta = RULE_META['RULE_SQLI_DETECTED_01']
            aid = create_alert(
                rule_id=meta['rule_id'],
                rule_name=meta['name'],
                severity=meta['severity'],
                description=reason,
                trigger_event_id=event_id,
                detection_latency_ms=latency_ms,
                simulation_run_id=simulation_run_id
            )
            new_alerts.append(aid)
            existing_pairs.add((event_id, 'RULE_SQLI_DETECTED_01'))

        # 4. Check XSS / Input Validation
        triggered, reason = evaluate_xss_rule(event)
        if triggered and (event_id, 'RULE_XSS_INPUT_01') not in existing_pairs:
            meta = RULE_META['RULE_XSS_INPUT_01']
            aid = create_alert(
                rule_id=meta['rule_id'],
                rule_name=meta['name'],
                severity=meta['severity'],
                description=reason,
                trigger_event_id=event_id,
                detection_latency_ms=latency_ms,
                simulation_run_id=simulation_run_id
            )
            new_alerts.append(aid)
            existing_pairs.add((event_id, 'RULE_XSS_INPUT_01'))

    return new_alerts
