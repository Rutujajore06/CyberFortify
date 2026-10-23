from flask import request, jsonify
from app.api import api_bp
from app.models.defense_model import (
    get_all_defenses,
    get_defense,
    set_defense_state
)

@api_bp.route('/defenses', methods=['GET'])
def list_defenses():
    """Lists all configurable defensive controls and their current states."""
    defenses = get_all_defenses()
    return jsonify({
        'status': 'success',
        'count': len(defenses),
        'defenses': defenses
    }), 200

@api_bp.route('/defenses/toggle', methods=['POST'])
def toggle_defense():
    """Toggles a specific defensive control on or off."""
    data = request.get_json(silent=True) or request.form or {}
    defense_key = data.get('defense_key')
    is_enabled = data.get('is_enabled')

    if not defense_key:
        return jsonify({'status': 'error', 'message': 'defense_key is required'}), 400

    updated = set_defense_state(defense_key, bool(is_enabled))
    if not updated:
        return jsonify({'status': 'error', 'message': f'Defense key {defense_key} not found'}), 404

    return jsonify({
        'status': 'success',
        'message': f"Defense '{defense_key}' is now {'ENABLED' if is_enabled else 'DISABLED'}",
        'defense': updated
    }), 200

@api_bp.route('/defenses/bulk-toggle', methods=['POST'])
def bulk_toggle_defenses():
    """Enables or disables all defensive controls simultaneously."""
    data = request.get_json(silent=True) or request.form or {}
    enable_all = bool(data.get('enable_all', False))

    keys = ['rate_limiting', 'rbac_enforcement', 'parameterized_queries', 'input_sanitization']
    for k in keys:
        set_defense_state(k, enable_all)

    return jsonify({
        'status': 'success',
        'message': f"All defenses have been {'ENABLED' if enable_all else 'DISABLED'}",
        'defenses': get_all_defenses()
    }), 200
