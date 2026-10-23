import csv
import io
from flask import request, jsonify, Response
from app.api import api_bp
from app.models.event_model import get_events, get_event_by_id

@api_bp.route('/events', methods=['GET'])
def list_events():
    """Lists security audit events with pagination, search, and scenario filtering."""
    limit = int(request.args.get('limit', 50))
    offset = int(request.args.get('offset', 0))
    scenario = request.args.get('scenario')
    is_attack_param = request.args.get('is_attack')
    search = request.args.get('search')

    is_attack = None
    if is_attack_param in ('1', 'true', 'True'):
        is_attack = True
    elif is_attack_param in ('0', 'false', 'False'):
        is_attack = False

    events, total = get_events(
        limit=limit,
        offset=offset,
        scenario=scenario,
        is_attack=is_attack,
        search=search
    )

    return jsonify({
        'status': 'success',
        'total': total,
        'count': len(events),
        'events': events
    }), 200

@api_bp.route('/events/<int:event_id>', methods=['GET'])
def get_single_event(event_id):
    """Retrieves full details of an individual security audit event."""
    event = get_event_by_id(event_id)
    if not event:
        return jsonify({'status': 'error', 'message': f'Security audit event #{event_id} not found'}), 404

    return jsonify({
        'status': 'success',
        'event': event
    }), 200

@api_bp.route('/events/export/csv', methods=['GET'])
def export_events_csv():
    """Exports all security audit events as a downloadable CSV file."""
    scenario = request.args.get('scenario')
    is_attack_param = request.args.get('is_attack')
    search = request.args.get('search')

    is_attack = None
    if is_attack_param in ('1', 'true', 'True'):
        is_attack = True
    elif is_attack_param in ('0', 'false', 'False'):
        is_attack = False

    # Fetch all matching events up to 5000 records
    events, total = get_events(
        limit=5000,
        offset=0,
        scenario=scenario,
        is_attack=is_attack,
        search=search
    )

    output = io.StringIO()
    writer = csv.writer(output)

    # Write CSV Header
    writer.writerow([
        'ID', 'Event UUID', 'Timestamp', 'IP Address', 'Endpoint',
        'HTTP Method', 'Status Code', 'User Identifier', 'Is Attack',
        'Scenario', 'Expected Rule', 'Simulation Run ID', 'Payload Data'
    ])

    for e in events:
        writer.writerow([
            e.get('id'),
            e.get('event_uuid'),
            e.get('timestamp'),
            e.get('ip_address'),
            e.get('endpoint'),
            e.get('http_method'),
            e.get('status_code'),
            e.get('user_identifier'),
            e.get('is_attack'),
            e.get('attack_scenario'),
            e.get('expected_rule'),
            e.get('simulation_run_id'),
            e.get('payload_data')
        ])

    csv_data = output.getvalue()
    return Response(
        csv_data,
        mimetype='text/csv',
        headers={
            'Content-Disposition': 'attachment; filename=cyberfortify_audit_events.csv',
            'Content-Type': 'text/csv; charset=utf-8'
        }
    )
