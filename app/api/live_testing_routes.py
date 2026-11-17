import re
import json
import datetime
from flask import request, jsonify, Response, current_app
from app.api import api_bp
from app.models.user_model import ROLE_ADMIN, ROLE_OWNER, ROLE_VIEWER
from app.models.live_target_model import (
    VALID_VERIFICATION_METHODS,
    create_live_target,
    get_live_target_by_uuid,
    get_all_live_targets,
    approve_live_target,
    reject_live_target,
    get_recent_live_assessments,
    get_live_assessment_by_uuid,
    get_live_audit_logs,
    parse_iso_datetime,
    utc_now,
    log_live_audit
)
from app.auth.security import (
    enforce_rbac,
    user_owns_target,
    sanitize_target_for_user
)
from app.live_testing.security import (
    validate_registration_url,
    normalize_approved_paths,
    normalize_allowed_methods,
    LiveSecurityError,
    _cfg
)
from app.live_testing.scanner import (
    verify_target_ownership,
    run_live_assessment
)
from app.live_testing.remediation import (
    get_remediations_for_target,
    get_remediation_by_uuid,
    update_remediation_item,
    compare_live_assessments,
    get_previous_completed_assessment,
    run_live_retest,
    generate_assessment_report_html,
    generate_assessment_report_markdown
)

_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


def _sanitize_target_for_export(target):
    """Strips sensitive verification_token from target metadata before returning in reports or remediation views."""
    return sanitize_target_for_user(target, user=None, include_token=False)


def _rbac_error_response(code, err_code, err_msg):
    return jsonify({
        'status': 'error',
        'error_type': err_code,
        'message': err_msg
    }), code


@api_bp.route('/live/targets', methods=['GET'])
def list_live_targets_api():
    """
    Lists registered live website targets (auto-expiring outdated authorizations).
    - Admin: sees all targets.
    - Website Owner: sees ONLY their own targets (IDOR protection).
    - Viewer: read-only view with verification_token strictly stripped.
    """
    ok, code, err_code, err_msg, user = enforce_rbac(
        allowed_roles={ROLE_ADMIN, ROLE_OWNER, ROLE_VIEWER},
        require_csrf=False,
        action_name='LIST_LIVE_TARGETS'
    )
    if not ok:
        return _rbac_error_response(code, err_code, err_msg)

    status_filter = request.args.get('status')
    all_targets = get_all_live_targets(status_filter=None)

    # Scope targets for Website Owner to prevent cross-owner data exposure
    if user and user['role'] == ROLE_OWNER:
        all_targets = [t for t in all_targets if user_owns_target(user, t)]

    if status_filter:
        targets = [t for t in all_targets if t['auth_status'] == status_filter.upper()]
    else:
        targets = all_targets

    # Viewers NEVER see verification tokens
    include_token = not (user and user['role'] == ROLE_VIEWER)
    safe_targets = [sanitize_target_for_user(t, user=user, include_token=include_token) for t in targets]

    summary = {
        'total': len(all_targets),
        'approved': sum(1 for t in all_targets if t['auth_status'] == 'APPROVED'),
        'pending_verification': sum(1 for t in all_targets if t['auth_status'] == 'PENDING_VERIFICATION'),
        'pending_approval': sum(1 for t in all_targets if t['auth_status'] == 'PENDING_APPROVAL'),
        'rejected': sum(1 for t in all_targets if t['auth_status'] == 'REJECTED'),
        'expired': sum(1 for t in all_targets if t['auth_status'] == 'EXPIRED')
    }
    return jsonify({
        'status': 'success',
        'summary': summary,
        'targets': safe_targets
    }), 200


@api_bp.route('/live/targets', methods=['POST'])
def register_live_target_api():
    """
    Registers a new external website target for authorized live security testing.
    Permitted roles: Admin, Website Owner (Viewer blocked with 403).
    """
    ok, code, err_code, err_msg, user = enforce_rbac(
        allowed_roles={ROLE_ADMIN, ROLE_OWNER},
        require_csrf=True,
        action_name='REGISTER_TARGET'
    )
    if not ok:
        return _rbac_error_response(code, err_code, err_msg)

    data = request.get_json(silent=True) or request.form or {}

    raw_url = (data.get('target_url') or data.get('url') or '').strip()
    is_valid, err_msg_url, parsed = validate_registration_url(raw_url)
    if not is_valid:
        log_live_audit(
            action='TARGET_REGISTRATION_REJECTED',
            outcome='BLOCKED',
            url=raw_url,
            reason=err_msg_url,
            actor=user['username'] if user else 'system'
        )
        return jsonify({
            'status': 'error',
            'error_type': 'INVALID_TARGET_URL',
            'message': err_msg_url
        }), 400

    # Explicit Website-Owner Authorization Consent Check
    raw_consent = data.get('owner_consent')
    owner_consent = raw_consent is True or str(raw_consent).lower() in ('true', '1', 'yes', 'on')
    if not owner_consent:
        return jsonify({
            'status': 'error',
            'error_type': 'AUTHORIZATION_REQUIRED',
            'message': (
                "Explicit website-owner authorization confirmation is required before registering a target."
            )
        }), 400

    owner_name = (data.get('owner_name') or (user['username'] if user else '')).strip()
    owner_email = (data.get('owner_email') or (user['email'] if user else '')).strip()
    if len(owner_name) < 2:
        return jsonify({
            'status': 'error',
            'error_type': 'VALIDATION_ERROR',
            'message': "Website owner or authorized contact name is required."
        }), 400
    if not _EMAIL_RE.match(owner_email):
        return jsonify({
            'status': 'error',
            'error_type': 'VALIDATION_ERROR',
            'message': "A valid website owner contact email address is required."
        }), 400

    verification_method = (data.get('verification_method') or 'http_file').strip().lower()
    if verification_method not in VALID_VERIFICATION_METHODS:
        return jsonify({
            'status': 'error',
            'error_type': 'VALIDATION_ERROR',
            'message': (
                f"Invalid verification method '{verification_method}'. "
                f"Supported: {sorted(list(VALID_VERIFICATION_METHODS))}."
            )
        }), 400

    paths_ok, paths_err, approved_paths = normalize_approved_paths(data.get('approved_paths') or [parsed['path']])
    if not paths_ok:
        return jsonify({
            'status': 'error',
            'error_type': 'VALIDATION_ERROR',
            'message': paths_err
        }), 400

    methods_ok, methods_err, allowed_methods = normalize_allowed_methods(data.get('allowed_methods') or ['GET', 'HEAD'])
    if not methods_ok:
        return jsonify({
            'status': 'error',
            'error_type': 'VALIDATION_ERROR',
            'message': methods_err
        }), 400

    # Testing window validation
    now = utc_now()
    raw_start = data.get('start_date')
    raw_expiry = data.get('expiry_date')

    start_dt = parse_iso_datetime(raw_start) if raw_start else now
    if not start_dt:
        return jsonify({
            'status': 'error',
            'error_type': 'VALIDATION_ERROR',
            'message': "Invalid testing start date format. Use ISO-8601 format (e.g. 2026-11-18T00:00:00Z)."
        }), 400

    expiry_dt = parse_iso_datetime(raw_expiry) if raw_expiry else (start_dt + datetime.timedelta(days=7))
    if not expiry_dt:
        return jsonify({
            'status': 'error',
            'error_type': 'VALIDATION_ERROR',
            'message': "Invalid testing expiry date format. Use ISO-8601 format."
        }), 400

    if expiry_dt <= start_dt:
        return jsonify({
            'status': 'error',
            'error_type': 'VALIDATION_ERROR',
            'message': "Testing expiry date must be later than the testing start date."
        }), 400

    if expiry_dt <= now:
        return jsonify({
            'status': 'error',
            'error_type': 'VALIDATION_ERROR',
            'message': "Testing expiry date must be in the future."
        }), 400

    # Rate limit validation
    max_allowed_rate = int(_cfg('LIVE_MAX_RATE_LIMIT', 60))
    try:
        max_request_rate = int(data.get('max_request_rate', 10))
    except (ValueError, TypeError):
        return jsonify({
            'status': 'error',
            'error_type': 'VALIDATION_ERROR',
            'message': "Maximum request rate must be a positive integer."
        }), 400

    if max_request_rate < 1 or max_request_rate > max_allowed_rate:
        return jsonify({
            'status': 'error',
            'error_type': 'VALIDATION_ERROR',
            'message': f"Maximum request rate must be between 1 and {max_allowed_rate} requests/minute."
        }), 400

    owner_user_id = user['user_uuid'] if (user and user.get('user_uuid') != 'token-admin') else None

    target = create_live_target(
        target_url=parsed['normalized_url'],
        domain=parsed['domain'],
        owner_name=owner_name,
        owner_email=owner_email,
        owner_consent=owner_consent,
        verification_method=verification_method,
        approved_paths=approved_paths,
        allowed_methods=allowed_methods,
        start_date=start_dt.isoformat(),
        expiry_date=expiry_dt.isoformat(),
        max_request_rate=max_request_rate,
        owner_user_id=owner_user_id
    )

    return jsonify({
        'status': 'success',
        'message': (
            f"Target '{target['domain']}' registered. Complete ownership verification and administrator "
            "approval before running live security assessments."
        ),
        'target': target
    }), 201


@api_bp.route('/live/targets/<target_uuid>', methods=['GET'])
def get_live_target_detail_api(target_uuid):
    """Returns registration & authorization metadata for a specific live target (IDOR protected)."""
    ok, code, err_code, err_msg, user = enforce_rbac(
        allowed_roles={ROLE_ADMIN, ROLE_OWNER, ROLE_VIEWER},
        require_csrf=False,
        action_name='VIEW_TARGET'
    )
    if not ok:
        return _rbac_error_response(code, err_code, err_msg)

    target = get_live_target_by_uuid(target_uuid)
    if not target:
        return jsonify({
            'status': 'error',
            'message': f"Target '{target_uuid}' not found."
        }), 404

    ok2, code2, err_code2, err_msg2, user = enforce_rbac(
        allowed_roles={ROLE_ADMIN, ROLE_OWNER, ROLE_VIEWER},
        require_csrf=False,
        resource_target=target,
        action_name='VIEW_TARGET'
    )
    if not ok2:
        return _rbac_error_response(code2, err_code2, err_msg2)

    include_token = not (user and user['role'] == ROLE_VIEWER)
    return jsonify({
        'status': 'success',
        'target': sanitize_target_for_user(target, user=user, include_token=include_token)
    }), 200


@api_bp.route('/live/targets/<target_uuid>/verify', methods=['POST'])
def verify_live_target_api(target_uuid):
    """Executes the website-owner authorization verification workflow (Admin or owning Website Owner)."""
    ok, code, err_code, err_msg, user = enforce_rbac(
        allowed_roles={ROLE_ADMIN, ROLE_OWNER},
        require_csrf=True,
        action_name='VERIFY_TARGET'
    )
    if not ok:
        return _rbac_error_response(code, err_code, err_msg)

    target = get_live_target_by_uuid(target_uuid)
    if not target:
        return jsonify({
            'status': 'error',
            'message': f"Target '{target_uuid}' not found."
        }), 404

    ok2, code2, err_code2, err_msg2, user = enforce_rbac(
        allowed_roles={ROLE_ADMIN, ROLE_OWNER},
        require_csrf=False,  # Already validated above
        resource_target=target,
        action_name='VERIFY_TARGET'
    )
    if not ok2:
        return _rbac_error_response(code2, err_code2, err_msg2)

    data = request.get_json(silent=True) or request.form or {}
    provided_token = data.get('verification_token')
    attestation_note = data.get('attestation_note')
    actor = (user['username'] if user else (data.get('actor') or target['owner_email'])).strip()

    updated, err = verify_target_ownership(
        target=target,
        provided_token=provided_token,
        attestation_note=attestation_note,
        actor=actor
    )
    if err:
        return jsonify({
            'status': 'error',
            'error_type': 'VERIFICATION_FAILED',
            'message': err
        }), 400

    if updated['verification_method'] == 'signed_attestation':
        msg = (
            f"Signed authorization self-attestation recorded for '{updated['domain']}'. "
            "Awaiting administrator approval (self-attestation does not claim independent domain ownership proof)."
        )
    else:
        msg = f"Ownership authorization verified for '{updated['domain']}'. Awaiting administrator approval."

    return jsonify({
        'status': 'success',
        'message': msg,
        'target': updated
    }), 200


@api_bp.route('/live/targets/<target_uuid>/approve', methods=['POST'])
def approve_live_target_api(target_uuid):
    """Administrator ONLY: approves a verified target for authorized live security testing."""
    ok, code, err_code, err_msg, user = enforce_rbac(
        allowed_roles={ROLE_ADMIN},
        require_csrf=True,
        action_name='APPROVE_TARGET'
    )
    if not ok:
        return _rbac_error_response(code, err_code, err_msg)

    data = request.get_json(silent=True) or request.form or {}
    approved_by = (user['username'] if user else (data.get('approved_by') or 'admin')).strip()

    updated, err = approve_live_target(target_uuid, approved_by=approved_by)
    if err:
        status_code = 404 if 'not found' in err.lower() else 400
        return jsonify({
            'status': 'error',
            'error_type': 'APPROVAL_REJECTED',
            'message': err
        }), status_code

    return jsonify({
        'status': 'success',
        'message': f"Target '{updated['domain']}' approved for live security testing until {updated['expiry_date']}.",
        'target': updated
    }), 200


@api_bp.route('/live/targets/<target_uuid>/reject', methods=['POST'])
def reject_live_target_api(target_uuid):
    """Administrator ONLY: rejects or revokes a target registration."""
    ok, code, err_code, err_msg, user = enforce_rbac(
        allowed_roles={ROLE_ADMIN},
        require_csrf=True,
        action_name='REJECT_TARGET'
    )
    if not ok:
        return _rbac_error_response(code, err_code, err_msg)

    data = request.get_json(silent=True) or request.form or {}
    reason = (data.get('reason') or 'Rejected by administrator').strip()
    rejected_by = (user['username'] if user else (data.get('rejected_by') or 'admin')).strip()

    updated, err = reject_live_target(target_uuid, reason=reason, rejected_by=rejected_by)
    if err:
        return jsonify({
            'status': 'error',
            'message': err
        }), 404

    return jsonify({
        'status': 'success',
        'message': f"Target '{updated['domain']}' has been rejected.",
        'target': updated
    }), 200


@api_bp.route('/live/assessments/run', methods=['POST'])
def run_live_assessment_api():
    """
    Administrator ONLY: Executes a safe, non-invasive live website security assessment on an APPROVED target.
    Strictly blocks unauthenticated, non-admin, unapproved, expired, private-IP, SSRF, or rate-limited requests.
    """
    ok, code, err_code, err_msg, _ = enforce_rbac(
        allowed_roles={ROLE_ADMIN},
        require_csrf=True,
        action_name='RUN_LIVE_ASSESSMENT'
    )
    if not ok:
        return _rbac_error_response(code, err_code, err_msg)

    data = request.get_json(silent=True) or request.form or {}
    target_uuid = (data.get('target_uuid') or '').strip()
    path = data.get('path')

    if not target_uuid:
        return jsonify({
            'status': 'error',
            'error_type': 'VALIDATION_ERROR',
            'message': "A registered and approved 'target_uuid' is required to run a live assessment."
        }), 400

    try:
        assessment = run_live_assessment(target_uuid=target_uuid, path=path)
        return jsonify({
            'status': 'success',
            'message': f"Live website security assessment completed for '{assessment['domain']}'.",
            'assessment': assessment
        }), 200
    except LiveSecurityError as e:
        return jsonify({
            'status': 'error',
            'error_type': e.error_code,
            'message': e.message
        }), e.status_code
    except Exception:
        current_app.logger.exception("Unexpected error during live assessment for target_uuid=%s", target_uuid)
        return jsonify({
            'status': 'error',
            'error_type': 'ASSESSMENT_ERROR',
            'message': "Live assessment failed due to an internal error. Check server logs for details."
        }), 500


@api_bp.route('/live/assessments', methods=['GET'])
def list_live_assessments_api():
    """
    Retrieves live website assessment history.
    - Admin / Viewer: sees assessments (read-only).
    - Website Owner: sees ONLY assessments belonging to their own registered targets (IDOR protected).
    """
    ok, code, err_code, err_msg, user = enforce_rbac(
        allowed_roles={ROLE_ADMIN, ROLE_OWNER, ROLE_VIEWER},
        require_csrf=False,
        action_name='LIST_LIVE_ASSESSMENTS'
    )
    if not ok:
        return _rbac_error_response(code, err_code, err_msg)

    limit = int(request.args.get('limit', 30))
    target_uuid = (request.args.get('target_uuid') or '').strip() or None

    if user and user['role'] == ROLE_OWNER:
        if target_uuid:
            target = get_live_target_by_uuid(target_uuid)
            if not target:
                return jsonify({'status': 'error', 'message': f"Target '{target_uuid}' not found."}), 404
            ok2, code2, err_code2, err_msg2, _ = enforce_rbac(
                allowed_roles={ROLE_OWNER},
                require_csrf=False,
                resource_target=target,
                action_name='LIST_LIVE_ASSESSMENTS'
            )
            if not ok2:
                return _rbac_error_response(code2, err_code2, err_msg2)
            assessments = get_recent_live_assessments(limit=limit, target_uuid=target_uuid)
        else:
            owned_uuids = {
                t['target_uuid'] for t in get_all_live_targets() if user_owns_target(user, t)
            }
            all_recent = get_recent_live_assessments(limit=max(limit * 3, 100))
            assessments = [a for a in all_recent if a['target_uuid'] in owned_uuids][:limit]
    else:
        assessments = get_recent_live_assessments(limit=limit, target_uuid=target_uuid)

    return jsonify({
        'status': 'success',
        'count': len(assessments),
        'assessments': assessments
    }), 200


@api_bp.route('/live/assessments/compare', methods=['GET'])
def compare_live_assessments_api():
    """
    Compares two real completed live assessments (previous vs latest) for a target (IDOR protected).
    """
    ok, code, err_code, err_msg, user = enforce_rbac(
        allowed_roles={ROLE_ADMIN, ROLE_OWNER, ROLE_VIEWER},
        require_csrf=False,
        action_name='COMPARE_ASSESSMENTS'
    )
    if not ok:
        return _rbac_error_response(code, err_code, err_msg)

    target_uuid = (request.args.get('target_uuid') or '').strip()
    baseline_uuid = (request.args.get('baseline_uuid') or '').strip()
    latest_uuid = (request.args.get('latest_uuid') or '').strip()

    baseline = None
    latest = None

    if latest_uuid:
        latest = get_live_assessment_by_uuid(latest_uuid)
        if not latest:
            return jsonify({'status': 'error', 'message': f"Latest assessment '{latest_uuid}' not found."}), 404
        target_uuid = latest['target_uuid']

    if baseline_uuid:
        baseline = get_live_assessment_by_uuid(baseline_uuid)
        if not baseline:
            return jsonify({'status': 'error', 'message': f"Baseline assessment '{baseline_uuid}' not found."}), 404
        if not target_uuid:
            target_uuid = baseline['target_uuid']

    if not target_uuid:
        return jsonify({
            'status': 'error',
            'error_type': 'VALIDATION_ERROR',
            'message': "Provide 'target_uuid' (or 'baseline_uuid'/'latest_uuid') to compare assessments."
        }), 400

    target = get_live_target_by_uuid(target_uuid)
    if target:
        ok2, code2, err_code2, err_msg2, _ = enforce_rbac(
            allowed_roles={ROLE_ADMIN, ROLE_OWNER, ROLE_VIEWER},
            require_csrf=False,
            resource_target=target,
            action_name='COMPARE_ASSESSMENTS'
        )
        if not ok2:
            return _rbac_error_response(code2, err_code2, err_msg2)

    recent = get_recent_live_assessments(limit=25, target_uuid=target_uuid)
    completed = [r for r in recent if r.get('status') == 'COMPLETED']

    if latest is None and completed:
        latest = get_live_assessment_by_uuid(completed[0]['assessment_uuid'])
    if baseline is None and latest is not None:
        baseline = get_previous_completed_assessment(target_uuid, exclude_uuid=latest['assessment_uuid'])

    if not latest:
        return jsonify({
            'status': 'success',
            'has_assessments': False,
            'message': "No completed live assessments found for this target yet.",
            'comparison': None
        }), 200

    comparison = compare_live_assessments(baseline, latest)
    return jsonify({
        'status': 'success',
        'has_assessments': True,
        'comparison': comparison
    }), 200


@api_bp.route('/live/assessments/<assessment_uuid>/report', methods=['GET'])
def download_live_assessment_report_api(assessment_uuid):
    """Generates a downloadable assessment report (html, json, or md). IDOR protected; tokens redacted."""
    ok, code, err_code, err_msg, user = enforce_rbac(
        allowed_roles={ROLE_ADMIN, ROLE_OWNER, ROLE_VIEWER},
        require_csrf=False,
        action_name='DOWNLOAD_REPORT'
    )
    if not ok:
        return _rbac_error_response(code, err_code, err_msg)

    assessment = get_live_assessment_by_uuid(assessment_uuid)
    if not assessment:
        return jsonify({
            'status': 'error',
            'message': f"Live assessment '{assessment_uuid}' not found."
        }), 404

    target = get_live_target_by_uuid(assessment['target_uuid'])
    if target:
        ok2, code2, err_code2, err_msg2, _ = enforce_rbac(
            allowed_roles={ROLE_ADMIN, ROLE_OWNER, ROLE_VIEWER},
            require_csrf=False,
            resource_target=target,
            action_name='DOWNLOAD_REPORT'
        )
        if not ok2:
            return _rbac_error_response(code2, err_code2, err_msg2)

    fmt = (request.args.get('format') or 'html').strip().lower()
    remediations = get_remediations_for_target(assessment['target_uuid'])
    previous = get_previous_completed_assessment(assessment['target_uuid'], exclude_uuid=assessment_uuid)
    comparison = compare_live_assessments(previous, assessment) if previous else None

    safe_domain = re.sub(r'[^a-zA-Z0-9.-]+', '_', assessment.get('domain') or 'target')
    base_name = f"cyberfortify-report-{safe_domain}-{assessment_uuid}"
    safe_target = _sanitize_target_for_export(target)

    if fmt == 'json':
        payload = {
            'report_generated_at': utc_now().isoformat(),
            'assessment': assessment,
            'target': safe_target,
            'remediations': remediations,
            'comparison': comparison
        }
        return Response(
            json.dumps(payload, indent=2),
            status=200,
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment; filename="{base_name}.json"'}
        )

    if fmt in ('md', 'markdown'):
        md_content = generate_assessment_report_markdown(
            assessment=assessment,
            target=safe_target,
            remediations=remediations,
            comparison=comparison
        )
        return Response(
            md_content,
            status=200,
            mimetype='text/markdown; charset=utf-8',
            headers={'Content-Disposition': f'attachment; filename="{base_name}.md"'}
        )

    html_content = generate_assessment_report_html(
        assessment=assessment,
        target=safe_target,
        remediations=remediations,
        comparison=comparison
    )
    return Response(
        html_content,
        status=200,
        mimetype='text/html; charset=utf-8',
        headers={'Content-Disposition': f'attachment; filename="{base_name}.html"'}
    )


@api_bp.route('/live/assessments/<assessment_uuid>', methods=['GET'])
def get_live_assessment_detail_api(assessment_uuid):
    """Retrieves full details, findings, score, and remediation for a live assessment (IDOR protected)."""
    ok, code, err_code, err_msg, _ = enforce_rbac(
        allowed_roles={ROLE_ADMIN, ROLE_OWNER, ROLE_VIEWER},
        require_csrf=False,
        action_name='VIEW_ASSESSMENT'
    )
    if not ok:
        return _rbac_error_response(code, err_code, err_msg)

    rec = get_live_assessment_by_uuid(assessment_uuid)
    if not rec:
        return jsonify({
            'status': 'error',
            'message': f"Live assessment '{assessment_uuid}' not found."
        }), 404

    target = get_live_target_by_uuid(rec['target_uuid'])
    if target:
        ok2, code2, err_code2, err_msg2, _ = enforce_rbac(
            allowed_roles={ROLE_ADMIN, ROLE_OWNER, ROLE_VIEWER},
            require_csrf=False,
            resource_target=target,
            action_name='VIEW_ASSESSMENT'
        )
        if not ok2:
            return _rbac_error_response(code2, err_code2, err_msg2)

    return jsonify({
        'status': 'success',
        'assessment': rec
    }), 200


@api_bp.route('/live/remediations', methods=['GET'])
def list_live_remediations_api():
    """Lists tracked vulnerability remediations for a live target (IDOR protected; tokens redacted)."""
    ok, code, err_code, err_msg, _ = enforce_rbac(
        allowed_roles={ROLE_ADMIN, ROLE_OWNER, ROLE_VIEWER},
        require_csrf=False,
        action_name='LIST_REMEDIATIONS'
    )
    if not ok:
        return _rbac_error_response(code, err_code, err_msg)

    target_uuid = (request.args.get('target_uuid') or '').strip()
    status_filter = request.args.get('status')

    if not target_uuid:
        return jsonify({
            'status': 'error',
            'error_type': 'VALIDATION_ERROR',
            'message': "Query parameter 'target_uuid' is required."
        }), 400

    target = get_live_target_by_uuid(target_uuid)
    if not target:
        return jsonify({
            'status': 'error',
            'message': f"Target '{target_uuid}' not found."
        }), 404

    ok2, code2, err_code2, err_msg2, _ = enforce_rbac(
        allowed_roles={ROLE_ADMIN, ROLE_OWNER, ROLE_VIEWER},
        require_csrf=False,
        resource_target=target,
        action_name='LIST_REMEDIATIONS'
    )
    if not ok2:
        return _rbac_error_response(code2, err_code2, err_msg2)

    all_items = get_remediations_for_target(target_uuid)
    items = [r for r in all_items if not status_filter or r['remediation_status'] == status_filter]

    summary = {
        'total': len(all_items),
        'open': sum(1 for r in all_items if r['remediation_status'] == 'Open'),
        'in_progress': sum(1 for r in all_items if r['remediation_status'] == 'In Progress'),
        'fixed': sum(1 for r in all_items if r['remediation_status'] == 'Fixed'),
        'verified': sum(1 for r in all_items if r['remediation_status'] == 'Verified')
    }

    return jsonify({
        'status': 'success',
        'target': _sanitize_target_for_export(target),
        'summary': summary,
        'remediations': items
    }), 200


@api_bp.route('/live/remediations/<remediation_uuid>', methods=['PATCH', 'POST'])
def update_live_remediation_api(remediation_uuid):
    """
    Updates remediation status and owner notes.
    - Admin: any remediation.
    - Website Owner: ONLY remediations belonging to their own targets (IDOR protected).
    - Viewer: strictly denied (403).
    """
    ok, code, err_code, err_msg, user = enforce_rbac(
        allowed_roles={ROLE_ADMIN, ROLE_OWNER},
        require_csrf=True,
        action_name='UPDATE_REMEDIATION'
    )
    if not ok:
        return _rbac_error_response(code, err_code, err_msg)

    existing = get_remediation_by_uuid(remediation_uuid)
    if not existing:
        return jsonify({
            'status': 'error',
            'error_type': 'NOT_FOUND',
            'message': f"Remediation item '{remediation_uuid}' not found."
        }), 404

    target = get_live_target_by_uuid(existing['target_uuid'])
    if target:
        ok2, code2, err_code2, err_msg2, user = enforce_rbac(
            allowed_roles={ROLE_ADMIN, ROLE_OWNER},
            require_csrf=False,  # Already verified above
            resource_target=target,
            action_name='UPDATE_REMEDIATION'
        )
        if not ok2:
            return _rbac_error_response(code2, err_code2, err_msg2)

    data = request.get_json(silent=True) or request.form or {}
    new_status = data.get('remediation_status') if 'remediation_status' in data else data.get('status')
    notes = data.get('remediation_notes') if 'remediation_notes' in data else data.get('notes')
    actor = (user['username'] if user else (data.get('actor') or 'owner')).strip()

    updated, err_code_upd, err_msg_upd = update_remediation_item(
        remediation_uuid=remediation_uuid,
        new_status=new_status,
        notes=notes,
        actor=actor
    )
    if err_code_upd:
        http_code = 404 if err_code_upd == 'NOT_FOUND' else 400
        return jsonify({
            'status': 'error',
            'error_type': err_code_upd,
            'message': err_msg_upd
        }), http_code

    return jsonify({
        'status': 'success',
        'message': f"Remediation '{updated['title']}' updated (status: {updated['remediation_status']}).",
        'remediation': updated
    }), 200


@api_bp.route('/live/retest/run', methods=['POST'])
def run_live_retest_api():
    """
    Administrator ONLY: Executes a safe live retest on an approved target, compares previous vs latest results,
    confirms fixed vs remaining vulnerabilities, and preserves full assessment history & audit logs.
    """
    ok, code, err_code, err_msg, _ = enforce_rbac(
        allowed_roles={ROLE_ADMIN},
        require_csrf=True,
        action_name='RUN_LIVE_RETEST'
    )
    if not ok:
        return _rbac_error_response(code, err_code, err_msg)

    data = request.get_json(silent=True) or request.form or {}
    target_uuid = (data.get('target_uuid') or '').strip()
    path = data.get('path')
    baseline_uuid = data.get('baseline_assessment_uuid')

    if not target_uuid:
        return jsonify({
            'status': 'error',
            'error_type': 'VALIDATION_ERROR',
            'message': "An approved 'target_uuid' is required to run a live retest."
        }), 400

    try:
        result = run_live_retest(
            target_uuid=target_uuid,
            path=path,
            baseline_assessment_uuid=baseline_uuid
        )
        return jsonify({
            'status': 'success',
            'message': (
                f"Live retest completed for '{result['latest_assessment']['domain']}'. "
                f"Score: {result['latest_assessment']['security_score']}/100 "
                f"(delta: {result['comparison']['score_delta']:+d})."
            ),
            'data': result
        }), 200
    except LiveSecurityError as e:
        return jsonify({
            'status': 'error',
            'error_type': e.error_code,
            'message': e.message
        }), e.status_code
    except Exception:
        current_app.logger.exception("Unexpected error during live retest for target_uuid=%s", target_uuid)
        return jsonify({
            'status': 'error',
            'error_type': 'RETEST_ERROR',
            'message': "Live retest failed due to an internal error. Check server logs for details."
        }), 500


@api_bp.route('/live/audit-logs', methods=['GET'])
def list_live_audit_logs_api():
    """
    Retrieves live testing security & compliance audit logs.
    - Admin: all audit logs.
    - Website Owner: ONLY logs belonging to their own registered targets (IDOR protected).
    - Viewer: denied (403).
    """
    ok, code, err_code, err_msg, user = enforce_rbac(
        allowed_roles={ROLE_ADMIN, ROLE_OWNER},
        require_csrf=False,
        action_name='VIEW_AUDIT_LOGS'
    )
    if not ok:
        return _rbac_error_response(code, err_code, err_msg)

    limit = int(request.args.get('limit', 100))
    target_uuid = (request.args.get('target_uuid') or '').strip() or None
    outcome = request.args.get('outcome')

    if user and user['role'] == ROLE_OWNER:
        if target_uuid:
            target = get_live_target_by_uuid(target_uuid)
            if not target:
                return jsonify({'status': 'error', 'message': f"Target '{target_uuid}' not found."}), 404
            ok2, code2, err_code2, err_msg2, _ = enforce_rbac(
                allowed_roles={ROLE_OWNER},
                require_csrf=False,
                resource_target=target,
                action_name='VIEW_AUDIT_LOGS'
            )
            if not ok2:
                return _rbac_error_response(code2, err_code2, err_msg2)
            logs = get_live_audit_logs(limit=limit, target_uuid=target_uuid, outcome=outcome)
        else:
            owned_uuids = {
                t['target_uuid'] for t in get_all_live_targets() if user_owns_target(user, t)
            }
            all_logs = get_live_audit_logs(limit=max(limit * 3, 200), outcome=outcome)
            logs = [l for l in all_logs if l.get('target_uuid') in owned_uuids][:limit]
    else:
        logs = get_live_audit_logs(limit=limit, target_uuid=target_uuid, outcome=outcome)

    return jsonify({
        'status': 'success',
        'count': len(logs),
        'logs': logs
    }), 200
