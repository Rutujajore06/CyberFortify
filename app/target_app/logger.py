import json
from flask import request
from app.models.event_model import log_event

def log_target_request(status_code, user_identifier=None, custom_payload=None):
    """
    Extracts telemetry from current Flask request and logs it to the events table.
    Captures ground-truth metadata passed during Red Team simulations.
    """
    endpoint = request.path
    method = request.method
    ip_address = request.remote_addr or '127.0.0.1'

    # Extract simulation headers if sent by Red Team Engine
    simulation_run_id = request.headers.get('X-Simulation-Run-ID')
    attack_scenario = request.headers.get('X-Simulation-Scenario')
    is_attack_header = request.headers.get('X-Simulation-Is-Attack')
    expected_rule = request.headers.get('X-Simulation-Expected-Rule')

    is_attack = 1 if is_attack_header in ('1', 'true', 'True') else 0

    payload_data = custom_payload
    if payload_data is None:
        if request.is_json:
            try:
                payload_data = json.dumps(request.get_json(silent=True))
            except Exception:
                payload_data = str(request.data)
        elif request.form:
            payload_data = json.dumps(dict(request.form))
        elif request.args:
            payload_data = json.dumps(dict(request.args))
        elif request.data:
            payload_data = request.data.decode('utf-8', errors='ignore')

    event_id = log_event(
        endpoint=endpoint,
        http_method=method,
        status_code=status_code,
        ip_address=ip_address,
        user_identifier=user_identifier,
        payload_data=payload_data,
        is_attack=is_attack,
        attack_scenario=attack_scenario or ('benign' if is_attack == 0 else 'unknown'),
        expected_rule=expected_rule,
        simulation_run_id=simulation_run_id
    )

    return event_id
