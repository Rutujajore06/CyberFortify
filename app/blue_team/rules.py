import re
import datetime

# Precompiled detection regex patterns
SQLI_PATTERNS = [
    re.compile(r"('|\")?\s*OR\s+('|\")?1('|\")?\s*=\s*('|\")?1", re.IGNORECASE),
    re.compile(r"('|\")?\s*OR\s+('|\")?[a-zA-Z0-9]+('|\")?\s*=\s*('|\")?[a-zA-Z0-9]+", re.IGNORECASE),
    re.compile(r"\bUNION\b\s+(\bALL\b\s+)?\bSELECT\b", re.IGNORECASE),
    re.compile(r"(--|#|/\*|\*/)", re.IGNORECASE),
    re.compile(r"\b(information_schema|sqlite_master|xp_cmdshell|drop\s+table)\b", re.IGNORECASE),
    re.compile(r"admin'\s*--", re.IGNORECASE)
]

XSS_PATTERNS = [
    re.compile(r"<script\b[^>]*>(.*?)<\/script>", re.IGNORECASE),
    re.compile(r"<\w+[^>]*\bon[a-zA-Z]+\s*=", re.IGNORECASE),
    re.compile(r"<svg[^>]*\/onload", re.IGNORECASE),
    re.compile(r"javascript:\s*[a-zA-Z0-9_\.]+", re.IGNORECASE),
    re.compile(r"<iframe\b[^>]*>", re.IGNORECASE)
]

DETECTION_RULES = [
    {
        "rule_id": "RULE_BRUTE_FORCE_01",
        "name": "High-Frequency Authentication Failure Anomaly",
        "severity": "HIGH",
        "category": "Credential Attack",
        "description": "Triggered when 3 or more failed login attempts occur within a rolling 60-second window."
    },
    {
        "rule_id": "RULE_UNAUTHORIZED_ACCESS_01",
        "name": "Unauthorized Administrative Resource Access Attempt",
        "severity": "CRITICAL",
        "category": "Broken Access Control",
        "description": "Triggered when access to restricted administrative endpoints is attempted without valid credentials or authorization."
    },
    {
        "rule_id": "RULE_SQLI_DETECTED_01",
        "name": "SQL Injection Syntax and Signature Anomaly",
        "severity": "CRITICAL",
        "category": "Injection",
        "description": "Triggered when request parameters or payload contain known SQL injection syntax or tautologies."
    },
    {
        "rule_id": "RULE_XSS_INPUT_01",
        "name": "Malicious Script and Tag Injection in User Input",
        "severity": "HIGH",
        "category": "Cross-Site Scripting",
        "description": "Triggered when user form submissions contain unencoded HTML tags, JavaScript event handlers, or script probes."
    }
]

def evaluate_brute_force_rule(event, all_events_window):
    """
    Evaluates RULE_BRUTE_FORCE_01 against a given event and context window.
    """
    if '/login' not in event.get('endpoint', ''):
        return False, None

    status_code = event.get('status_code')
    if status_code not in (401, 429):
        return False, None

    user = event.get('user_identifier')
    ip = event.get('ip_address')

    # Count recent failed attempts for same user or IP within 60s
    matches = 0
    event_time = event.get('timestamp')
    try:
        t_event = datetime.datetime.fromisoformat(event_time)
    except Exception:
        t_event = datetime.datetime.now(datetime.timezone.utc)

    for other in all_events_window:
        if '/login' in other.get('endpoint', '') and other.get('status_code') in (401, 429):
            if other.get('user_identifier') == user or other.get('ip_address') == ip:
                try:
                    t_other = datetime.datetime.fromisoformat(other.get('timestamp'))
                    diff = abs((t_event - t_other).total_seconds())
                    if diff <= 60:
                        matches += 1
                except Exception:
                    matches += 1

    if matches >= 3:
        reason = f"Detected {matches} failed login attempts for user '{user}' from IP '{ip}' within 60 seconds."
        return True, reason

    return False, None

def evaluate_unauthorized_access_rule(event):
    """
    Evaluates RULE_UNAUTHORIZED_ACCESS_01 against a given event.
    Triggers if an admin/secrets endpoint is accessed without valid admin credentials,
    or returns 401/403.
    """
    endpoint = event.get('endpoint', '')
    if '/admin' in endpoint or '/secrets' in endpoint:
        status_code = event.get('status_code')
        payload = (event.get('payload_data') or '').lower()
        has_valid_admin_token = 'cyberfortify-admin-token-valid-2026' in payload
        user = event.get('user_identifier')

        # Trigger if blocked with 401/403 OR if accessing without valid admin token
        if status_code in (401, 403) or not has_valid_admin_token or user != 'admin_viewer':
            reason = f"Unauthorized access attempt to administrative endpoint '{endpoint}' (Status {status_code}, User: {user})."
            return True, reason

    return False, None

def evaluate_sqli_rule(event):
    """
    Evaluates RULE_SQLI_DETECTED_01 against payload data or query params.
    """
    payload = event.get('payload_data') or ''
    endpoint = event.get('endpoint', '')

    for pattern in SQLI_PATTERNS:
        if pattern.search(payload) or pattern.search(endpoint):
            matched = pattern.search(payload) or pattern.search(endpoint)
            reason = f"SQL injection signature pattern '{matched.group(0)}' detected in request payload/query."
            return True, reason

    return False, None

def evaluate_xss_rule(event):
    """
    Evaluates RULE_XSS_INPUT_01 against payload data.
    """
    payload = event.get('payload_data') or ''
    for pattern in XSS_PATTERNS:
        if pattern.search(payload):
            matched = pattern.search(payload)
            reason = f"Malicious script / HTML injection pattern '{matched.group(0)}' detected in input payload."
            return True, reason

    return False, None
