import hmac
from flask import Blueprint, request, jsonify, session, current_app
from app.models.user_model import (
    ROLE_ADMIN,
    ROLE_OWNER,
    ROLE_VIEWER,
    VALID_ROLES,
    has_admin_user,
    create_user,
    create_initial_admin_atomic,
    authenticate_user,
    list_users
)
from app.models.live_target_model import log_live_audit
from app.auth.security import (
    is_auth_enforced,
    is_public_deployment,
    get_current_user,
    get_or_create_csrf_token,
    validate_csrf_token,
    enforce_rbac,
    auth_rate_limiter,
    get_client_ip
)

auth_bp = Blueprint('auth_bp', __name__, url_prefix='/api/auth')


@auth_bp.route('/me', methods=['GET'])
def auth_me_api():
    """Returns current session user (if logged in), CSRF token, auth mode, and admin setup status."""
    user = get_current_user()
    csrf_tok = get_or_create_csrf_token()
    return jsonify({
        'status': 'success',
        'authenticated': user is not None,
        'user': user,
        'csrf_token': csrf_tok,
        'has_admin': has_admin_user(),
        'auth_enforced': is_auth_enforced(),
        'public_deployment': is_public_deployment()
    }), 200


@auth_bp.route('/setup-admin', methods=['POST'])
def setup_initial_admin_api():
    """
    One-time initial Administrator bootstrap when zero Admin accounts exist.
    - Uses SQLite BEGIN IMMEDIATE atomic lock to prevent concurrent setup race conditions.
    - On public/production deployments, requires CYBERFORTIFY_BOOTSTRAP_TOKEN (otherwise disabled).
    - Rate limited per IP. Permanently locked once an Admin exists.
    """
    client_ip = get_client_ip()
    max_att = int(current_app.config.get('AUTH_REGISTER_MAX_ATTEMPTS', 5))
    win_sec = int(current_app.config.get('AUTH_REGISTER_WINDOW_SECONDS', 600))
    ok_rl, retry_after = auth_rate_limiter.check_and_record(f"setup:{client_ip}", max_att, win_sec)
    if not ok_rl:
        log_live_audit(
            action='AUTH_RATE_LIMIT_BLOCKED',
            outcome='BLOCKED',
            reason=f"Admin setup rate limit exceeded for IP {client_ip}.",
            actor=client_ip
        )
        return jsonify({
            'status': 'error',
            'error_type': 'RATE_LIMIT_EXCEEDED',
            'message': f"Too many admin setup attempts. Try again in {retry_after} seconds."
        }), 429

    data = request.get_json(silent=True) or request.form or {}

    # On public/production deployments, block unauthenticated remote admin takeover
    if is_public_deployment():
        expected_boot = current_app.config.get('CYBERFORTIFY_BOOTSTRAP_TOKEN')
        provided_boot = request.headers.get('X-Bootstrap-Token') or data.get('bootstrap_token') or ''
        if not expected_boot or not hmac.compare_digest(str(expected_boot), str(provided_boot)):
            log_live_audit(
                action='ADMIN_BOOTSTRAP_BLOCKED',
                outcome='BLOCKED',
                reason=f"Blocked unauthorized public /setup-admin attempt from IP {client_ip}.",
                actor=client_ip
            )
            return jsonify({
                'status': 'error',
                'error_type': 'BOOTSTRAP_DISABLED_IN_PRODUCTION',
                'message': (
                    "Public admin bootstrap requires a valid CYBERFORTIFY_BOOTSTRAP_TOKEN "
                    "(or provision Admin via CYBERFORTIFY_ADMIN_* environment variables)."
                )
            }), 403

    user, err_code, err_msg = create_initial_admin_atomic(
        username=data.get('username'),
        email=data.get('email'),
        password=data.get('password')
    )
    if err_code:
        http_code = 403 if err_code == 'ADMIN_ALREADY_EXISTS' else 400
        return jsonify({
            'status': 'error',
            'error_type': err_code,
            'message': err_msg
        }), http_code

    # Sign in the newly provisioned Admin with fresh session + CSRF token
    session.clear()
    session.permanent = True
    session['user_uuid'] = user['user_uuid']
    csrf_tok = get_or_create_csrf_token()

    log_live_audit(
        action='ADMIN_ACCOUNT_INITIALIZED',
        outcome='SUCCESS',
        reason=f"Initial Admin account '{user['username']}' provisioned via atomic first-time setup.",
        actor=user['username']
    )

    return jsonify({
        'status': 'success',
        'message': f"Administrator account '{user['username']}' created and signed in.",
        'user': user,
        'csrf_token': csrf_tok
    }), 201


@auth_bp.route('/register', methods=['POST'])
def register_account_api():
    """
    Self-registration for Website Owner or Viewer accounts ONLY.
    Attempting to self-register as ADMIN is strictly rejected (403).
    Rate limited per client IP to prevent registration abuse.
    """
    client_ip = get_client_ip()
    max_att = int(current_app.config.get('AUTH_REGISTER_MAX_ATTEMPTS', 5))
    win_sec = int(current_app.config.get('AUTH_REGISTER_WINDOW_SECONDS', 600))
    ok_rl, retry_after = auth_rate_limiter.check_and_record(f"register:{client_ip}", max_att, win_sec)
    if not ok_rl:
        log_live_audit(
            action='AUTH_RATE_LIMIT_BLOCKED',
            outcome='BLOCKED',
            reason=f"Registration rate limit exceeded for IP {client_ip}.",
            actor=client_ip
        )
        return jsonify({
            'status': 'error',
            'error_type': 'RATE_LIMIT_EXCEEDED',
            'message': f"Too many registration attempts. Please try again in {retry_after} seconds."
        }), 429

    data = request.get_json(silent=True) or request.form or {}
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role = (data.get('role') or ROLE_OWNER).strip().upper()

    if role == ROLE_ADMIN:
        return jsonify({
            'status': 'error',
            'error_type': 'FORBIDDEN',
            'message': "Administrator accounts cannot be self-registered."
        }), 403

    if role not in (ROLE_OWNER, ROLE_VIEWER):
        return jsonify({
            'status': 'error',
            'error_type': 'VALIDATION_ERROR',
            'message': "Role must be 'WEBSITE_OWNER' or 'VIEWER'."
        }), 400

    user, err = create_user(username=username, email=email, password=password, role=role)
    if err:
        return jsonify({
            'status': 'error',
            'error_type': 'VALIDATION_ERROR',
            'message': err
        }), 400

    session.clear()
    session.permanent = True
    session['user_uuid'] = user['user_uuid']
    csrf_tok = get_or_create_csrf_token()

    log_live_audit(
        action='USER_REGISTERED',
        outcome='SUCCESS',
        reason=f"Registered user '{user['username']}' with role '{user['role']}'.",
        actor=user['username']
    )

    return jsonify({
        'status': 'success',
        'message': f"Account '{user['username']}' ({user['role_label']}) created and signed in.",
        'user': user,
        'csrf_token': csrf_tok
    }), 201


@auth_bp.route('/login', methods=['POST'])
def login_api():
    """Authenticates a user by username or email + password with rate limiting and session regeneration."""
    data = request.get_json(silent=True) or request.form or {}
    identifier = (data.get('username') or data.get('email') or data.get('identifier') or '').strip()
    password = data.get('password') or ''

    client_ip = get_client_ip()
    max_att = int(current_app.config.get('AUTH_LOGIN_MAX_ATTEMPTS', 10))
    win_sec = int(current_app.config.get('AUTH_LOGIN_WINDOW_SECONDS', 300))
    ok_rl, retry_after = auth_rate_limiter.check_and_record(
        f"login:{client_ip}:{identifier.lower()}", max_att, win_sec
    )
    if not ok_rl:
        log_live_audit(
            action='AUTH_RATE_LIMIT_BLOCKED',
            outcome='BLOCKED',
            reason=f"Login rate limit exceeded for '{identifier}' from IP {client_ip}.",
            actor=identifier or client_ip
        )
        return jsonify({
            'status': 'error',
            'error_type': 'RATE_LIMIT_EXCEEDED',
            'message': f"Too many login attempts. Please wait {retry_after} seconds before retrying."
        }), 429

    user = authenticate_user(identifier, password)
    if not user:
        log_live_audit(
            action='USER_LOGIN_FAILED',
            outcome='FAILED',
            reason=f"Invalid login attempt for identifier '{identifier}'.",
            actor=identifier or 'anonymous'
        )
        return jsonify({
            'status': 'error',
            'error_type': 'INVALID_CREDENTIALS',
            'message': "Invalid username/email or password."
        }), 401

    # Regenerate session to prevent session fixation
    session.clear()
    session.permanent = True
    session['user_uuid'] = user['user_uuid']
    csrf_tok = get_or_create_csrf_token()

    log_live_audit(
        action='USER_LOGIN_SUCCESS',
        outcome='SUCCESS',
        reason=f"User '{user['username']}' ({user['role']}) signed in.",
        actor=user['username']
    )

    return jsonify({
        'status': 'success',
        'message': f"Signed in as {user['username']} ({user['role_label']}).",
        'user': user,
        'csrf_token': csrf_tok
    }), 200


@auth_bp.route('/logout', methods=['POST'])
def logout_api():
    """Clears the user session (CSRF-protected when signed in)."""
    user = get_current_user()
    if user:
        csrf_ok, csrf_err = validate_csrf_token()
        if not csrf_ok:
            return jsonify({
                'status': 'error',
                'error_type': 'CSRF_FAILED',
                'message': csrf_err
            }), 403
        log_live_audit(
            action='USER_LOGOUT',
            outcome='SUCCESS',
            reason=f"User '{user['username']}' signed out.",
            actor=user['username']
        )

    session.clear()
    csrf_tok = get_or_create_csrf_token()
    return jsonify({
        'status': 'success',
        'message': "Signed out successfully.",
        'csrf_token': csrf_tok
    }), 200


@auth_bp.route('/users', methods=['GET'])
def list_users_api():
    """Admin-only: lists platform accounts (password hashes strictly excluded)."""
    ok, code, err_code, err_msg, _ = enforce_rbac(
        allowed_roles={ROLE_ADMIN},
        require_csrf=False,
        action_name='LIST_USERS'
    )
    if not ok:
        return jsonify({'status': 'error', 'error_type': err_code, 'message': err_msg}), code

    # Even in local demo mode, require an actual Admin session to view user directory if users exist
    user = get_current_user()
    if user is None:
        return jsonify({
            'status': 'error',
            'error_type': 'AUTHENTICATION_REQUIRED',
            'message': "Administrator sign-in is required to view platform users."
        }), 401

    return jsonify({
        'status': 'success',
        'users': list_users()
    }), 200


@auth_bp.route('/users', methods=['POST'])
def admin_create_user_api():
    """Admin-only: provisions a new Admin, Website Owner, or Viewer account."""
    user = get_current_user()
    if user is None:
        return jsonify({
            'status': 'error',
            'error_type': 'AUTHENTICATION_REQUIRED',
            'message': "Administrator sign-in is required to manage users."
        }), 401

    ok, code, err_code, err_msg, actor_user = enforce_rbac(
        allowed_roles={ROLE_ADMIN},
        require_csrf=True,
        action_name='CREATE_USER'
    )
    if not ok:
        return jsonify({'status': 'error', 'error_type': err_code, 'message': err_msg}), code

    data = request.get_json(silent=True) or request.form or {}
    new_user, err = create_user(
        username=data.get('username'),
        email=data.get('email'),
        password=data.get('password'),
        role=data.get('role', ROLE_VIEWER)
    )
    if err:
        return jsonify({'status': 'error', 'error_type': 'VALIDATION_ERROR', 'message': err}), 400

    log_live_audit(
        action='ADMIN_CREATED_USER',
        outcome='SUCCESS',
        reason=f"Admin '{actor_user['username']}' created user '{new_user['username']}' ({new_user['role']}).",
        actor=actor_user['username']
    )

    return jsonify({
        'status': 'success',
        'message': f"User '{new_user['username']}' ({new_user['role_label']}) created.",
        'user': new_user
    }), 201
