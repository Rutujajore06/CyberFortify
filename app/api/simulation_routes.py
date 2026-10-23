from flask import request, jsonify, current_app
from app.api import api_bp
from app.models.simulation_model import (
    get_all_simulation_runs,
    get_simulation_run,
    get_latest_evaluation
)
from app.models.event_model import get_events_by_simulation
from app.models.alert_model import get_alerts_by_simulation
from app.red_team.runner import execute_simulation

@api_bp.route('/simulations', methods=['GET'])
def list_simulations():
    """Lists recent simulation runs with summary counts."""
    limit = int(request.args.get('limit', 25))
    runs = get_all_simulation_runs(limit=limit)
    return jsonify({
        'status': 'success',
        'count': len(runs),
        'runs': runs
    }), 200

@api_bp.route('/simulations/<run_uuid>', methods=['GET'])
def get_simulation_details(run_uuid):
    """Retrieves full details, events, alerts, and evaluation for a simulation run."""
    run = get_simulation_run(run_uuid)
    if not run:
        return jsonify({'status': 'error', 'message': 'Simulation run not found'}), 404

    events = get_events_by_simulation(run_uuid)
    alerts = get_alerts_by_simulation(run_uuid)
    evaluation = get_latest_evaluation(run_uuid)

    return jsonify({
        'status': 'success',
        'run': run,
        'events': events,
        'alerts': alerts,
        'evaluation': evaluation
    }), 200

@api_bp.route('/simulations/run', methods=['POST'])
def run_simulation_api():
    """Triggers an automated simulation run for a given scenario or test battery."""
    data = request.get_json(silent=True) or request.form or {}
    scenario_name = data.get('scenario', 'all')
    notes = data.get('notes', f'Triggered from CyberFortify API for scenario: {scenario_name}')

    valid_scenarios = ['brute_force', 'unauthorized_access', 'sql_injection', 'input_validation', 'benign', 'all', 'battery']
    if scenario_name not in valid_scenarios:
        return jsonify({
            'status': 'error',
            'message': f"Invalid scenario '{scenario_name}'. Valid options: {valid_scenarios}"
        }), 400

    # Execute simulation using Flask internal test client for instant, reliable execution
    with current_app.test_client() as client:
        result = execute_simulation(scenario_name=scenario_name, client=client, notes=notes)

    return jsonify({
        'status': 'success',
        'message': f"Simulation for scenario '{scenario_name}' completed successfully.",
        'data': result
    }), 200
