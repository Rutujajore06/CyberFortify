from flask import current_app
from app.database import get_db_connection
from app.models.defense_model import get_all_defenses
from app.models.assessment_model import save_assessment

def run_demo_assessment(target_url, client=None, notes=None):
    """
    Executes a safe, non-intrusive security posture assessment for the local Fortress Bank demo.
    
    Inspects:
    1. Defensive controls configuration state in SQLite (Rate Limiting, RBAC, Parameterization, Sanitization).
    2. HTTP security response headers via local test client (X-Content-Type-Options, X-Frame-Options, CSP).
    3. Security audit logging & SIEM telemetry in SQLite events table.
    4. Application debug configuration and secret key hygiene.
    
    Persists the assessment and all granular findings in SQLite.
    Does NOT execute offensive attack payloads or arbitrary network requests.
    """
    findings = []

    # 1. Inspect Defensive Controls Configuration
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM defense_settings ORDER BY id ASC')
    defenses = {row['defense_key']: dict(row) for row in cursor.fetchall()}

    # Check 1: Authentication Rate Limiting
    rl = defenses.get('rate_limiting', {})
    if rl.get('is_enabled'):
        findings.append({
            'check_key': 'rate_limiting',
            'title': 'Authentication Rate Limiting & Account Lockout',
            'category': 'Authentication',
            'severity': 'INFO',
            'status': 'DEFENDED',
            'evidence': (
                f"defense_settings: is_enabled=1 for 'rate_limiting' (updated {rl.get('updated_at')}). "
                "The login endpoint (/api/target/login) enforces throttling and lockout after 3 consecutive failed attempts."
            ),
            'remediation': (
                "Rate limiting is active. Continue monitoring brute-force alert telemetry and review lockout thresholds periodically."
            )
        })
    else:
        findings.append({
            'check_key': 'rate_limiting',
            'title': 'Authentication Rate Limiting & Account Lockout',
            'category': 'Authentication',
            'severity': 'HIGH',
            'status': 'VULNERABLE',
            'evidence': (
                f"defense_settings: is_enabled=0 for 'rate_limiting'. "
                "The login endpoint (/api/target/login) does not restrict login attempt velocity, leaving the portal vulnerable to brute force and credential stuffing."
            ),
            'remediation': (
                rl.get('remediation_guidance') or
                "Enable 'Authentication Rate Limiting' in the Remediation Lab to enforce account lockout and HTTP 429 throttling after 3 failed attempts."
            )
        })

    # Check 2: Role-Based Access Control (RBAC)
    rbac = defenses.get('rbac_enforcement', {})
    if rbac.get('is_enabled'):
        findings.append({
            'check_key': 'rbac_enforcement',
            'title': 'Role-Based Access Control & Token Authorization',
            'category': 'Access Control',
            'severity': 'INFO',
            'status': 'DEFENDED',
            'evidence': (
                f"defense_settings: is_enabled=1 for 'rbac_enforcement' (updated {rbac.get('updated_at')}). "
                "Administrative secrets endpoint (/api/target/admin/secrets) enforces cryptographic Bearer token validation and ADMIN role verification."
            ),
            'remediation': (
                "RBAC enforcement is active. Maintain strict role boundaries and enforce token expiration/rotation mechanisms."
            )
        })
    else:
        findings.append({
            'check_key': 'rbac_enforcement',
            'title': 'Role-Based Access Control & Token Authorization',
            'category': 'Access Control',
            'severity': 'CRITICAL',
            'status': 'VULNERABLE',
            'evidence': (
                f"defense_settings: is_enabled=0 for 'rbac_enforcement'. "
                "Administrative secrets endpoint (/api/target/admin/secrets) permits forced browsing without requiring valid Bearer authorization."
            ),
            'remediation': (
                rbac.get('remediation_guidance') or
                "Enable 'Role-Based Access Control & Strict Token Validation' in the Remediation Lab to protect administrative resources with server-side authorization checks."
            )
        })

    # Check 3: Parameterized Queries (SQLi Prevention)
    sqli = defenses.get('parameterized_queries', {})
    if sqli.get('is_enabled'):
        findings.append({
            'check_key': 'parameterized_queries',
            'title': 'Prepared Statements & SQL Injection Prevention',
            'category': 'Injection Defense',
            'severity': 'INFO',
            'status': 'DEFENDED',
            'evidence': (
                f"defense_settings: is_enabled=1 for 'parameterized_queries' (updated {sqli.get('updated_at')}). "
                "Customer search queries utilize parameterized SQL placeholders (?) and input syntax anomaly filtering."
            ),
            'remediation': (
                "Parameterized queries are active. Ensure all existing and future database operations utilize prepared statements rather than string formatting."
            )
        })
    else:
        findings.append({
            'check_key': 'parameterized_queries',
            'title': 'Prepared Statements & SQL Injection Prevention',
            'category': 'Injection Defense',
            'severity': 'CRITICAL',
            'status': 'VULNERABLE',
            'evidence': (
                f"defense_settings: is_enabled=0 for 'parameterized_queries'. "
                "Search endpoint (/api/target/search) performs raw string interpolation into database query strings, exposing user accounts to SQL injection."
            ),
            'remediation': (
                sqli.get('remediation_guidance') or
                "Enable 'Prepared Statements & SQL Injection Prevention' in the Remediation Lab to bind search terms safely using query placeholders."
            )
        })

    # Check 4: Input Validation & HTML Output Encoding (XSS)
    xss = defenses.get('input_sanitization', {})
    if xss.get('is_enabled'):
        findings.append({
            'check_key': 'input_sanitization',
            'title': 'Input Validation & HTML Output Encoding (XSS)',
            'category': 'Input Validation & XSS',
            'severity': 'INFO',
            'status': 'DEFENDED',
            'evidence': (
                f"defense_settings: is_enabled=1 for 'input_sanitization' (updated {xss.get('updated_at')}). "
                "Feedback submissions undergo HTML entity encoding and executable script tag interception."
            ),
            'remediation': (
                "Input sanitization is active. Supplement output encoding with a strict Content Security Policy (CSP) for defense-in-depth."
            )
        })
    else:
        findings.append({
            'check_key': 'input_sanitization',
            'title': 'Input Validation & HTML Output Encoding (XSS)',
            'category': 'Input Validation & XSS',
            'severity': 'HIGH',
            'status': 'VULNERABLE',
            'evidence': (
                f"defense_settings: is_enabled=0 for 'input_sanitization'. "
                "Feedback endpoint (/api/target/feedback) stores unescaped raw user content directly into SQLite without HTML entity encoding."
            ),
            'remediation': (
                xss.get('remediation_guidance') or
                "Enable 'Input Validation & HTML Output Encoding' in the Remediation Lab to escape HTML special characters (<, >, &, \", ') before persistence or rendering."
            )
        })

    # 2. Inspect HTTP Security Response Headers via local test client
    test_client = client or current_app.test_client()
    try:
        res = test_client.get('/api/target/status')
        headers = dict(res.headers)
        missing_sec_headers = []
        if 'X-Content-Type-Options' not in headers:
            missing_sec_headers.append('X-Content-Type-Options')
        if 'X-Frame-Options' not in headers:
            missing_sec_headers.append('X-Frame-Options')
        if 'Content-Security-Policy' not in headers:
            missing_sec_headers.append('Content-Security-Policy')

        if missing_sec_headers:
            findings.append({
                'check_key': 'http_security_headers',
                'title': 'HTTP Security Response Headers',
                'category': 'HTTP Security Headers',
                'severity': 'MEDIUM',
                'status': 'VULNERABLE',
                'evidence': (
                    f"HTTP response from local target /api/target/status returned status {res.status_code}. "
                    f"Missing recommended security headers: {', '.join(missing_sec_headers)}. "
                    f"Observed headers: {list(headers.keys())}."
                ),
                'remediation': (
                    "Add an after_request hook to attach 'X-Content-Type-Options: nosniff', "
                    "'X-Frame-Options: SAMEORIGIN', and 'Content-Security-Policy: default-src 'self'' to all HTTP responses."
                )
            })
        else:
            findings.append({
                'check_key': 'http_security_headers',
                'title': 'HTTP Security Response Headers',
                'category': 'HTTP Security Headers',
                'severity': 'INFO',
                'status': 'DEFENDED',
                'evidence': f"Security headers verified: {', '.join(headers.keys())}.",
                'remediation': "Security headers are configured appropriately."
            })
    except Exception as e:
        findings.append({
            'check_key': 'http_security_headers',
            'title': 'HTTP Security Response Headers',
            'category': 'HTTP Security Headers',
            'severity': 'LOW',
            'status': 'WARNING',
            'evidence': f"Could not inspect local target headers via test client: {str(e)}",
            'remediation': "Ensure the demo application status endpoint is reachable via test client."
        })

    # 3. Inspect Audit Logging & SIEM Telemetry
    cursor.execute('SELECT count(*) as total_events, max(timestamp) as latest_ts FROM events')
    events_row = cursor.fetchone()
    conn.close()

    total_events = events_row['total_events'] if events_row else 0
    latest_ts = events_row['latest_ts'] if events_row else None

    if total_events > 0:
        findings.append({
            'check_key': 'audit_logging',
            'title': 'Security Audit Logging & Telemetry Health',
            'category': 'Audit Logging & SIEM',
            'severity': 'INFO',
            'status': 'DEFENDED',
            'evidence': (
                f"SQLite 'events' table contains {total_events} recorded audit events. "
                f"Most recent security event recorded at: {latest_ts or 'N/A'}. "
                "Audit pipeline actively logs endpoint access and payload telemetry."
            ),
            'remediation': (
                "Audit logging pipeline is operational. Ensure event retention schedules and continuous alert rule evaluation."
            )
        })
    else:
        findings.append({
            'check_key': 'audit_logging',
            'title': 'Security Audit Logging & Telemetry Health',
            'category': 'Audit Logging & SIEM',
            'severity': 'LOW',
            'status': 'WARNING',
            'evidence': (
                "SQLite 'events' table is currently empty (0 records). No security telemetry has been logged yet."
            ),
            'remediation': (
                "Generate baseline traffic or execute a test simulation from the Red Team Console to verify SIEM audit ingestion."
            )
        })

    # 4. Inspect Application Configuration (Debug Mode & Secrets)
    is_debug = current_app.config.get('DEBUG', False)
    secret_key = current_app.config.get('SECRET_KEY', '')
    is_default_secret = 'cyberfortify-secret-key-btech-2026' in secret_key

    if is_debug or is_default_secret:
        findings.append({
            'check_key': 'app_environment',
            'title': 'Application Runtime Environment & Secrets',
            'category': 'Application Configuration',
            'severity': 'MEDIUM',
            'status': 'WARNING',
            'evidence': (
                f"DEBUG mode: {is_debug}. Default development secret key in use: {is_default_secret}. "
                "Running in debug mode with known development keys exposes interactive debugger and token spoofing risks in production."
            ),
            'remediation': (
                "In production environments, set DEBUG=False in app/config.py and configure a secure random SECRET_KEY via environment variable."
            )
        })
    else:
        findings.append({
            'check_key': 'app_environment',
            'title': 'Application Runtime Environment & Secrets',
            'category': 'Application Configuration',
            'severity': 'INFO',
            'status': 'DEFENDED',
            'evidence': "DEBUG mode is disabled and custom production SECRET_KEY is detected.",
            'remediation': "Application runtime environment matches production hardening guidelines."
        })

    # Compute Overall Status
    has_critical_or_high_vuln = any(
        f['severity'] in ('CRITICAL', 'HIGH') and f['status'] == 'VULNERABLE'
        for f in findings
    )
    has_medium_or_low_vuln = any(
        f['severity'] in ('MEDIUM', 'LOW') and f['status'] in ('VULNERABLE', 'WARNING')
        for f in findings
    )

    if has_critical_or_high_vuln:
        overall_status = 'VULNERABLE'
    elif has_medium_or_low_vuln:
        overall_status = 'PARTIALLY_FORTIFIED'
    else:
        overall_status = 'FORTIFIED'

    # Persist to SQLite
    record = save_assessment(
        target_url=target_url,
        scope_target='Fortress Bank Demo',
        overall_status=overall_status,
        findings=findings,
        notes=notes or 'Conducted safe non-intrusive Website Security Assessment on Fortress Bank demo.'
    )

    return record
