import datetime
import sqlite3
from flask import request, jsonify
from app.target_app import target_bp
from app.target_app.logger import log_target_request
from app.target_app.defenses import (
    check_rate_limit,
    check_rbac_authorization,
    is_parameterized_active,
    sanitize_user_input,
    DEMO_VALID_ADMIN_TOKEN
)
from app.database import get_db_connection
from app.models.defense_model import get_defense_snapshot

@target_bp.route('/status', methods=['GET'])
def target_status():
    """Health check and active defense status for the demo target app."""
    return jsonify({
        'status': 'online',
        'target_name': 'Fortress Demo Banking Portal',
        'active_defenses': get_defense_snapshot()
    }), 200

@target_bp.route('/login', methods=['POST'])
def target_login():
    """
    Demo Target Login Endpoint.
    Subject to Brute Force simulation.
    Protected by Rate Limiting defense.
    """
    data = request.get_json(silent=True) or request.form or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    ip_address = request.remote_addr or '127.0.0.1'

    # Check Rate Limiting Defensive Control
    rate_allowed, rate_msg = check_rate_limit(user_identifier=username, ip_address=ip_address)
    if not rate_allowed:
        log_target_request(status_code=429, user_identifier=username, custom_payload=f"username={username}")
        return jsonify({
            'status': 'blocked',
            'error': 'Too Many Requests',
            'message': rate_msg
        }), 429

    # Verify credentials in database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM target_users WHERE username = ? AND password = ?', (username, password))
    user = cursor.fetchone()
    conn.close()

    if user:
        token = DEMO_VALID_ADMIN_TOKEN if user['role'] == 'ADMIN' else f"Bearer token-user-{user['username']}"
        log_target_request(status_code=200, user_identifier=username, custom_payload=f"username={username}&login=success")
        return jsonify({
            'status': 'success',
            'message': f"Welcome back, {user['username']}!",
            'role': user['role'],
            'token': token,
            'account_number': user['account_number']
        }), 200
    else:
        log_target_request(status_code=401, user_identifier=username, custom_payload=f"username={username}&login=failed")
        return jsonify({
            'status': 'failed',
            'error': 'Invalid credentials provided'
        }), 401

@target_bp.route('/admin/secrets', methods=['GET'])
def target_admin_secrets():
    """
    Protected Admin Resource Endpoint.
    Subject to Broken Access Control / Forced Browsing simulation.
    Protected by RBAC defense.
    """
    auth_header = request.headers.get('Authorization')
    allowed, rbac_msg = check_rbac_authorization(auth_header)

    if not allowed:
        log_target_request(status_code=403, user_identifier='anonymous', custom_payload=f"auth_header={auth_header}")
        return jsonify({
            'status': 'denied',
            'error': 'Forbidden - Administrative Privilege Required',
            'details': rbac_msg
        }), 403

    # If allowed (either valid admin token OR defense is disabled / vulnerable):
    log_target_request(
        status_code=200,
        user_identifier='admin_viewer' if auth_header == DEMO_VALID_ADMIN_TOKEN else 'unauthorized_accessor',
        custom_payload=f"auth_header={auth_header}&access=granted"
    )
    return jsonify({
        'status': 'granted',
        'message': 'Access to administrative treasury secrets granted.',
        'secrets': {
            'vault_master_key': 'CYBERFORTIFY-VAULT-KEY-994821',
            'reserve_vault_balance': '$45,892,100.00',
            'encryption_standard': 'AES-256-GCM',
            'debug_mode': True
        }
    }), 200

@target_bp.route('/search', methods=['GET'])
def target_search():
    """
    Demo Target Search Endpoint.
    Subject to SQL Injection simulation.
    Protected by Parameterized Query defense.
    """
    query = request.args.get('q', '').strip()
    conn = get_db_connection()
    cursor = conn.cursor()
    results = []

    try:
        if is_parameterized_active():
            # Fortified Defense: Parameterized query & SQLi filter
            from app.blue_team.rules import SQLI_PATTERNS
            is_sqli = any(p.search(query) for p in SQLI_PATTERNS)
            if is_sqli:
                conn.close()
                log_target_request(status_code=400, custom_payload=f"q={query}&blocked=sqli_guard")
                return jsonify({
                    'status': 'blocked',
                    'error': 'Defensive Control: SQL injection pattern detected and neutralized.',
                    'query': query,
                    'results_count': 0,
                    'results': []
                }), 400

            cursor.execute(
                "SELECT id, username, role, account_number FROM target_users WHERE username LIKE ?",
                (f"%{query}%",)
            )
            rows = cursor.fetchall()
            results = [dict(r) for r in rows]
        else:
            # Vulnerable Baseline: Raw string interpolation enables SQL injection!
            # e.g., ' OR 1=1 --
            raw_sql = f"SELECT id, username, role, account_number FROM target_users WHERE username = '{query}'"
            cursor.execute(raw_sql)
            rows = cursor.fetchall()
            results = [dict(r) for r in rows]

        conn.close()
        log_target_request(status_code=200, custom_payload=f"q={query}")
        return jsonify({
            'status': 'success',
            'query': query,
            'results_count': len(results),
            'results': results
        }), 200

    except sqlite3.OperationalError as e:
        conn.close()
        log_target_request(status_code=500, custom_payload=f"q={query}&error={str(e)}")
        return jsonify({
            'status': 'error',
            'error': f"Database query execution error: {str(e)}",
            'hint': 'SQL syntax anomaly detected'
        }), 500

@target_bp.route('/feedback', methods=['POST', 'GET'])
def target_feedback():
    """
    Demo Target Feedback Endpoint.
    Subject to Input Validation & XSS simulation.
    Protected by Input Sanitization defense.
    """
    if request.method == 'GET':
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM target_feedback ORDER BY id DESC LIMIT 20')
        rows = cursor.fetchall()
        conn.close()
        return jsonify([dict(r) for r in rows]), 200

    data = request.get_json(silent=True) or request.form or {}
    author = data.get('author', 'Anonymous')
    raw_content = data.get('content', '')

    sanitized_content, is_malicious = sanitize_user_input(raw_content)

    # If defense is active and payload contains dangerous tags, reject or sanitize
    if is_malicious and sanitize_user_input.__name__:
        from app.target_app.defenses import is_sanitization_active
        if is_sanitization_active():
            # Block or sanitize
            log_target_request(
                status_code=400,
                user_identifier=author,
                custom_payload=f"author={author}&content={raw_content}"
            )
            return jsonify({
                'status': 'blocked',
                'error': 'Input validation violation: Disallowed HTML / script content detected.',
                'sanitized_preview': sanitized_content
            }), 400

    # Save to database (in vulnerable mode, saves unescaped raw string!)
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cursor.execute('''
    INSERT INTO target_feedback (author, content, submitted_at)
    VALUES (?, ?, ?)
    ''', (author, sanitized_content, now))
    conn.commit()
    conn.close()

    log_target_request(
        status_code=201,
        user_identifier=author,
        custom_payload=f"author={author}&content={raw_content}"
    )

    return jsonify({
        'status': 'stored',
        'message': 'Feedback successfully received and stored.',
        'stored_content': sanitized_content
    }), 201
