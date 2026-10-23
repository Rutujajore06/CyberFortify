from flask import request, jsonify, current_app
from app.api import api_bp
from app.assessment.validator import validate_target_url
from app.assessment.engine import run_demo_assessment
from app.models.assessment_model import (
    get_recent_assessments,
    get_assessment_by_uuid,
    get_latest_assessment,
    get_assessment_summary
)
from app.target_app.defenses import DEMO_VALID_ADMIN_TOKEN

def check_backend_auth():
    """
    Validates backend authentication consistent with platform configuration.
    If REQUIRE_AUTH is enabled, an Authorization header must be provided.
    If an Authorization header is provided, it is validated against valid tokens.
    """
    require_auth = current_app.config.get('REQUIRE_AUTH', False)
    auth_header = request.headers.get('Authorization')

    if require_auth:
        if not auth_header:
            return False, "Authentication required: Missing Authorization header"
        expected_secret = current_app.config.get('SECRET_KEY')
        valid_tokens = {
            f"Bearer {expected_secret}",
            DEMO_VALID_ADMIN_TOKEN,
            f"Bearer {DEMO_VALID_ADMIN_TOKEN.replace('Bearer ', '')}"
        }
        if auth_header.strip() not in valid_tokens:
            return False, "Unauthorized: Invalid Authorization token provided"

    elif auth_header:
        # If client voluntarily provides Authorization header, validate it
        expected_secret = current_app.config.get('SECRET_KEY')
        valid_tokens = {
            f"Bearer {expected_secret}",
            DEMO_VALID_ADMIN_TOKEN,
            f"Bearer {DEMO_VALID_ADMIN_TOKEN.replace('Bearer ', '')}"
        }
        if auth_header.strip() not in valid_tokens:
            return False, "Unauthorized: Invalid Authorization credentials"

    return True, None

@api_bp.route('/assessment/config', methods=['GET'])
def get_assessment_scope_config():
    """Returns the configured demo scope and target constraints."""
    from app.config import Config
    return jsonify({
        'status': 'success',
        'target_name': Config.TARGET_APP_NAME,
        'demo_origin': Config.DEMO_ORIGIN,
        'demo_host': Config.HOST,
        'demo_port': Config.DEMO_ALLOWED_PORT,
        'allowed_hosts': sorted(list(Config.DEMO_ALLOWED_HOSTS)),
        'allowed_schemes': sorted(list(Config.DEMO_ALLOWED_SCHEMES)),
        'scope_description': (
            "Strictly confined to the built-in Fortress Bank demo application. "
            "External URLs, arbitrary network requests, and active exploitation are blocked."
        )
    }), 200

@api_bp.route('/assessment/run', methods=['POST'])
def run_assessment_api():
    """
    Executes a safe, non-intrusive Website Security Assessment on the Fortress Bank demo.
    Enforces scope server-side. Rejects external URLs, invalid schemes, credentials, and ports.
    """
    # 1. Backend Authentication & Authorization Check
    is_auth_ok, auth_err = check_backend_auth()
    if not is_auth_ok:
        return jsonify({
            'status': 'error',
            'error_type': 'UNAUTHORIZED',
            'message': auth_err
        }), 401

    # 2. Extract and Validate Target URL
    data = request.get_json(silent=True) or request.form or {}
    raw_url = data.get('url') or ''
    notes = data.get('notes', 'Website Security Assessment for Fortress Bank demo')

    is_valid, error_msg, normalized_url = validate_target_url(raw_url)
    if not is_valid:
        return jsonify({
            'status': 'error',
            'error_type': 'SCOPE_VIOLATION',
            'message': error_msg
        }), 400

    # 3. Execute Safe Non-Intrusive Assessment Logic
    with current_app.test_client() as client:
        assessment_record = run_demo_assessment(
            target_url=normalized_url,
            client=client,
            notes=notes
        )

    return jsonify({
        'status': 'success',
        'message': 'Website Security Assessment completed successfully.',
        'assessment': assessment_record
    }), 200

@api_bp.route('/assessment/history', methods=['GET'])
def list_assessments_history():
    """Retrieves list of past website security assessments."""
    limit = int(request.args.get('limit', 25))
    history = get_recent_assessments(limit=limit)
    summary = get_assessment_summary()

    return jsonify({
        'status': 'success',
        'count': len(history),
        'summary': summary,
        'assessments': history
    }), 200

@api_bp.route('/assessment/<assessment_uuid>', methods=['GET'])
def get_assessment_detail(assessment_uuid):
    """Retrieves full details and findings for a specific assessment."""
    assessment = get_assessment_by_uuid(assessment_uuid)
    if not assessment:
        return jsonify({
            'status': 'error',
            'message': f"Assessment '{assessment_uuid}' not found"
        }), 404

    return jsonify({
        'status': 'success',
        'assessment': assessment
    }), 200
