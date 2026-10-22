import html
import re
from app.models.defense_model import is_defense_enabled
from app.models.event_model import get_recent_failed_logins

# Token constant for demo admin access
DEMO_VALID_ADMIN_TOKEN = "Bearer cyberfortify-admin-token-valid-2026"

def is_rate_limiting_active():
    return is_defense_enabled('rate_limiting')

def is_rbac_active():
    return is_defense_enabled('rbac_enforcement')

def is_parameterized_active():
    return is_defense_enabled('parameterized_queries')

def is_sanitization_active():
    return is_defense_enabled('input_sanitization')

def check_rate_limit(user_identifier, ip_address='127.0.0.1', max_attempts=3, window_seconds=60):
    """
    Checks if rate limiting should block the login attempt.
    If defense is disabled: returns (True, 'Rate limiting disabled (Vulnerable)').
    If defense is enabled: checks failed login attempts in the past window_seconds.
    """
    if not is_rate_limiting_active():
        return True, "Rate limiting disabled: allow attempt"

    failed_attempts = get_recent_failed_logins(user_identifier=user_identifier, ip_address=ip_address, window_seconds=window_seconds)
    if len(failed_attempts) >= max_attempts:
        return False, f"Account or IP locked: exceeded {max_attempts} failed login attempts in {window_seconds}s"
    
    return True, "Rate limit check passed"

def check_rbac_authorization(auth_header):
    """
    Checks if request is authorized to view protected admin resources.
    If defense is disabled: returns True (Vulnerable broken access control).
    If defense is enabled: checks for valid Bearer token.
    """
    if not is_rbac_active():
        # Broken Access Control vulnerability present:
        # endpoint allows request even without proper auth!
        return True, "RBAC disabled: vulnerable unauthorized access allowed"

    if not auth_header:
        return False, "Access Denied: Missing Authorization header"

    if auth_header.strip() != DEMO_VALID_ADMIN_TOKEN:
        return False, "Access Denied: Invalid or unauthorized token credentials"

    return True, "Access Granted: Valid Admin Credentials"

def sanitize_user_input(text):
    """
    Sanitizes user input.
    If defense is disabled: returns raw text unmodified (vulnerable to XSS / injection).
    If defense is enabled: encodes HTML entities and detects dangerous tags.
    """
    if not text:
        return text, False

    malicious_pattern = re.compile(r'(<script.*?>.*?</script>|<.*?onload=.*?|<.*?onerror=.*?|javascript:)', re.IGNORECASE)
    is_malicious = bool(malicious_pattern.search(text))

    if not is_sanitization_active():
        # Vulnerable mode: reflection without sanitization
        return text, is_malicious

    # Sanitized mode: HTML escape
    sanitized = html.escape(text)
    return sanitized, is_malicious
