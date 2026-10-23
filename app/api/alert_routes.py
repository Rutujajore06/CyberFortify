from flask import request, jsonify
from app.api import api_bp
from app.models.alert_model import (
    get_alerts,
    get_alert_by_id,
    update_alert_status,
    get_alerts_summary
)

@api_bp.route('/alerts', methods=['GET'])
def list_alerts():
    """Lists alerts with filtering by severity, status, rule, or simulation."""
    limit = int(request.args.get('limit', 50))
    offset = int(request.args.get('offset', 0))
    severity = request.args.get('severity')
    status = request.args.get('status')
    rule_id = request.args.get('rule_id')
    simulation_run_id = request.args.get('simulation_run_id')

    alerts, total = get_alerts(
        limit=limit,
        offset=offset,
        severity=severity,
        status=status,
        rule_id=rule_id,
        simulation_run_id=simulation_run_id
    )

    return jsonify({
        'status': 'success',
        'total': total,
        'count': len(alerts),
        'alerts': alerts
    }), 200

@api_bp.route('/alerts/summary', methods=['GET'])
def alert_summary():
    """Returns severity distribution of all alerts for dashboard widgets."""
    summary = get_alerts_summary()
    return jsonify({
        'status': 'success',
        'summary': summary
    }), 200

@api_bp.route('/alerts/<int:alert_id>', methods=['GET'])
def get_alert_detail(alert_id):
    """Retrieves full details of an individual alert including triggered payload."""
    alert = get_alert_by_id(alert_id)
    if not alert:
        return jsonify({'status': 'error', 'message': 'Alert not found'}), 404

    return jsonify({
        'status': 'success',
        'alert': alert
    }), 200

@api_bp.route('/alerts/<int:alert_id>/status', methods=['POST'])
def update_status(alert_id):
    """Updates the status of an alert (NEW, ACKNOWLEDGED, RESOLVED)."""
    data = request.get_json(silent=True) or request.form or {}
    new_status = data.get('status', 'ACKNOWLEDGED')

    if new_status not in ('NEW', 'ACKNOWLEDGED', 'RESOLVED'):
        return jsonify({'status': 'error', 'message': 'Invalid status'}), 400

    updated = update_alert_status(alert_id, new_status)
    if not updated:
        return jsonify({'status': 'error', 'message': 'Alert not found'}), 404

    return jsonify({
        'status': 'success',
        'message': f"Alert #{alert_id} status updated to {new_status}",
        'alert': updated
    }), 200
