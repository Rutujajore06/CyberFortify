import hmac
import time
import secrets
import threading
from collections import deque
from flask import session, request, current_app, has_app_context
from app.config import Config
from app.models.user_model import (
    ROLE_ADMIN,
    ROLE_OWNER,
    ROLE_VIEWER,
    get_user_by_uuid
)
from app.models.live_target_model import log_live_audit
from app.target_app.defenses import DEMO_VALID_ADMIN_TOKEN

_LOOPBACK_HOSTS = {'127.0.0.1', 'localhost', '::1'}


def _cfg(key, default=None):
    if has_app_context() and key in current_app.config:
        return current_app.config[key]
    return getattr(Config, key, default)


def is_public_deployment():
    """
    Returns True if the application is configured for a public or production deployment
    (e.g., Render, Vercel, FLASK_ENV=production, non-loopback HOST, or LOCAL_DEMO_MODE=False).
    Public deployments NEVER allow unauthenticated access to protected endpoints.
    """
    if _cfg('IS_RENDER', False) or _cfg('IS_VERCEL', False):
        return True
    if str(_cfg('FLASK_ENV', 'development')).lower() == 'production':
        return True
    host = str(_cfg('HOST', '127.0.0.1')).strip().lower()
    if host not in _LOOPBACK_HOSTS:
        return True
    if not _cfg('LOCAL_DEMO_MODE', True):
        return True
    return False


def is_auth_enforced():
    """
    Authentication is strictly enforced whenever REQUIRE_AUTH=True OR the app is running
    in a public/production deployment.
    """
    return bool(_cfg('REQUIRE_AUTH', False)) or is_public_deployment()


def get_current_user():
    """Returns the currently authenticated session user dict (sanitized), or None."""
    user_uuid = session.get('user_uuid')
    if not user_uuid:
        return None
    user = get_user_by_uuid(user_uuid)
    if not user:
        session.pop('user_uuid', None)
        return None
    return user


def get_or_create_csrf_token():
    """Returns the current session's CSRF token, generating a cryptographic token if absent."""
    token = session.get('csrf_token')
    if not token:
        token = secrets.token_hex(32)
        session['csrf_token'] = token
    return token


def validate_csrf_token():
    """
    Validates CSRF token from X-CSRF-Token header, form field, or JSON body against session['csrf_token'].
    Returns (is_valid: bool, error_message: str | None).
    """
    if not _cfg('CSRF_ENABLED', True):
        return True, None

    expected = session.get('csrf_token')
    if not expected:
        return False, "Missing session CSRF token. Refresh the page and try again."

    provided = request.headers.get('X-CSRF-Token') or request.headers.get('X-CSRFToken')
    if not provided:
        if request.is_json:
            body = request.get_json(silent=True) or {}
            provided = body.get('csrf_token')
        else:
            provided = request.form.get('csrf_token')

    if not provided or not isinstance(provided, str):
        return False, "CSRF token missing from request."

    if not hmac.compare_digest(expected, provided.strip()):
        return False, "Invalid CSRF token."

    return True, None


class AuthRateLimiter:
    """Thread-safe sliding-window rate limiter protecting login, registration, and admin setup."""
    def __init__(self):
        self._lock = threading.Lock()
        self._buckets = {}

    def check_and_record(self, key, max_attempts, window_seconds):
        now = time.monotonic()
        cutoff = now - float(window_seconds)
        with self._lock:
            dq = self._buckets.setdefault(key, deque())
            while dq and dq[0] <= cutoff:
                dq.popleft()
            if len(dq) >= int(max_attempts):
                retry_after = max(1, int(window_seconds - (now - dq[0])))
                return False, retry_after
            dq.append(now)
            return True, 0

    def reset(self):
        with self._lock:
            self._buckets.clear()


auth_rate_limiter = AuthRateLimiter()


def get_client_ip():
    """Returns client IP address (honors ProxyFix when behind a trusted reverse proxy)."""
    return (request.remote_addr or '127.0.0.1').strip()


def user_owns_target(user, target):
    """
    Strict IDOR ownership check for Website Owner accounts.
    - Admin owns/manages all targets (including legacy unassigned targets where owner_user_id is NULL).
    - Website Owner ONLY owns targets explicitly bound to their user_uuid (owner_user_id).
      Unassigned legacy targets (owner_user_id IS NULL) cannot be claimed by matching an unverified email.
    """
    if not user or not target:
        return False
    if user['role'] == ROLE_ADMIN:
        return True
    if user['role'] != ROLE_OWNER:
        return False

    target_owner_id = target.get('owner_user_id')
    if not target_owner_id:
        return False
    return target_owner_id == user['user_uuid']


def sanitize_target_for_user(target, user=None, include_token=False):
    """
    Strips sensitive verification_token unless explicitly permitted.
    - Viewers NEVER see verification_token.
    - Reports & remediation views NEVER include verification_token.
    - Only Admin or the owning Website Owner receives verification_token when include_token=True.
    """
    if not target:
        return None
    sanitized = dict(target)
    if not include_token:
        sanitized.pop('verification_token', None)
        return sanitized

    if user is not None:
        if user['role'] == ROLE_VIEWER:
            sanitized.pop('verification_token', None)
        elif user['role'] == ROLE_OWNER and not user_owns_target(user, target):
            sanitized.pop('verification_token', None)

    return sanitized


def _validate_bearer_header(auth_header):
    """Validates optional Bearer Authorization header for programmatic/admin API access."""
    expected_secret = current_app.config.get('SECRET_KEY')
    live_admin_token = current_app.config.get('LIVE_ADMIN_TOKEN', expected_secret)
    valid_tokens = {
        f"Bearer {expected_secret}",
        f"Bearer {live_admin_token}",
        DEMO_VALID_ADMIN_TOKEN,
        f"Bearer {DEMO_VALID_ADMIN_TOKEN.replace('Bearer ', '')}"
    }
    return auth_header.strip() in valid_tokens


def enforce_rbac(
    allowed_roles,
    require_csrf=False,
    resource_target=None,
    action_name='ACCESS_CHECK'
):
    """
    Central backend RBAC, CSRF, and IDOR enforcement gate.

    Rules:
    1. If a session user IS logged in:
       - Enforces CSRF on state-changing requests (when require_csrf=True).
       - Enforces user['role'] in allowed_roles -> 403 FORBIDDEN otherwise.
       - Enforces IDOR ownership when role == WEBSITE_OWNER and resource_target is given -> 403 IDOR_BLOCKED.
    2. If NO session user is logged in:
       - If an Authorization Bearer header is provided, validates it (invalid -> 401).
       - If auth is enforced (REQUIRE_AUTH=True OR public deployment), rejects with 401 AUTHENTICATION_REQUIRED.
       - Only in explicit local loopback demo mode (not public, REQUIRE_AUTH=False), allows demo fallback.

    Returns (allowed: bool, status_code: int, error_code: str | None, error_msg: str | None, user: dict | None).
    """
    user = get_current_user()

    if user is not None:
        # 1. CSRF check for session-authenticated state-changing requests
        if require_csrf:
            csrf_ok, csrf_err = validate_csrf_token()
            if not csrf_ok:
                log_live_audit(
                    action='CSRF_VALIDATION_FAILED',
                    outcome='BLOCKED',
                    target_uuid=resource_target['target_uuid'] if resource_target else None,
                    domain=resource_target['domain'] if resource_target else None,
                    reason=f"[{action_name}] {csrf_err}",
                    actor=user['username']
                )
                return False, 403, 'CSRF_FAILED', csrf_err, user

        # 2. Role check
        if user['role'] not in allowed_roles:
            msg = (
                f"Forbidden: role '{user['role_label']}' does not have permission for '{action_name}'."
            )
            log_live_audit(
                action='RBAC_ACCESS_DENIED',
                outcome='BLOCKED',
                target_uuid=resource_target['target_uuid'] if resource_target else None,
                domain=resource_target['domain'] if resource_target else None,
                reason=msg,
                actor=user['username']
            )
            return False, 403, 'FORBIDDEN', msg, user

        # 3. IDOR ownership check for Website Owner accessing a specific target/assessment/remediation
        if resource_target is not None and user['role'] == ROLE_OWNER:
            if not user_owns_target(user, resource_target):
                msg = "Forbidden: Website Owners may only access their own registered targets and assessments."
                log_live_audit(
                    action='IDOR_ACCESS_BLOCKED',
                    outcome='BLOCKED',
                    target_uuid=resource_target['target_uuid'],
                    domain=resource_target['domain'],
                    reason=f"[{action_name}] Blocked cross-owner access by '{user['username']}'.",
                    actor=user['username']
                )
                return False, 403, 'IDOR_BLOCKED', msg, user

        return True, 200, None, None, user

    # No session user: check Bearer Authorization header if provided
    auth_header = request.headers.get('Authorization')
    if auth_header:
        if _validate_bearer_header(auth_header):
            # Programmatic admin token carries ADMIN role
            if ROLE_ADMIN in allowed_roles:
                return True, 200, None, None, {
                    'user_uuid': 'token-admin',
                    'username': 'api-admin',
                    'email': 'api-admin@local',
                    'role': ROLE_ADMIN,
                    'role_label': 'Admin'
                }
            return False, 403, 'FORBIDDEN', "Forbidden for token role.", None
        return False, 401, 'UNAUTHORIZED', "Unauthorized: Invalid Authorization credentials.", None

    # No session and no valid Bearer header: enforce strict authentication on public/auth-enforced deployments
    if is_auth_enforced():
        msg = "Authentication required. Please sign in to access this CyberFortify endpoint."
        log_live_audit(
            action='UNAUTHENTICATED_ACCESS_BLOCKED',
            outcome='BLOCKED',
            target_uuid=resource_target['target_uuid'] if resource_target else None,
            domain=resource_target['domain'] if resource_target else None,
            reason=f"[{action_name}] Blocked unauthenticated request (auth enforced).",
            actor='anonymous'
        )
        return False, 401, 'AUTHENTICATION_REQUIRED', msg, None

    # Explicit local loopback demo mode only (never reachable on public deployments)
    return True, 200, None, None, None
