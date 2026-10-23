from flask import request, jsonify, current_app
from app.api import api_bp
from app.models.simulation_model import get_overall_metrics
from app.blue_team.rules import DETECTION_RULES
from app.remediation.retester import run_retest_experiment

@api_bp.route('/evaluations/overall', methods=['GET'])
def get_overall_evaluations():
    """Returns platform-wide evaluation metrics and KPI summary."""
    metrics = get_overall_metrics()
    return jsonify({
        'status': 'success',
        'metrics': metrics
    }), 200

@api_bp.route('/evaluations/rules', methods=['GET'])
def get_detection_rules():
    """Returns all active Blue Team detection rules and their signatures."""
    return jsonify({
        'status': 'success',
        'count': len(DETECTION_RULES),
        'rules': DETECTION_RULES
    }), 200

@api_bp.route('/retest/run', methods=['POST'])
def trigger_retest_experiment():
    """
    Executes an automated Before-and-After Retest Experiment:
    Tests Baseline (Defenses OFF) vs Fortified (Defenses ON) and
    produces a side-by-side comparison report with remediation actions.
    """
    data = request.get_json(silent=True) or request.form or {}
    scenario_name = data.get('scenario', 'all')

    with current_app.test_client() as client:
        retest_report = run_retest_experiment(scenario_name=scenario_name, client=client)

    return jsonify({
        'status': 'success',
        'message': 'Before-and-after retest evaluation successfully executed.',
        'data': retest_report
    }), 200
