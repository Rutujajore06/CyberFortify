"""
Safe, non-destructive security test payloads for CyberFortify Red Team simulations.
All payloads are strictly bounded to test detection rules against the local target demo app.
"""

BRUTE_FORCE_CREDENTIALS = [
    {"username": "admin", "password": "password123", "is_attack": True, "expected_rule": "RULE_BRUTE_FORCE_01"},
    {"username": "admin", "password": "12345678", "is_attack": True, "expected_rule": "RULE_BRUTE_FORCE_01"},
    {"username": "admin", "password": "admin2026", "is_attack": True, "expected_rule": "RULE_BRUTE_FORCE_01"},
    {"username": "admin", "password": "qwerty123", "is_attack": True, "expected_rule": "RULE_BRUTE_FORCE_01"},
    {"username": "admin", "password": "letmeinnow", "is_attack": True, "expected_rule": "RULE_BRUTE_FORCE_01"}
]

UNAUTHORIZED_ACCESS_PROBES = [
    {
        "endpoint": "/api/target/admin/secrets",
        "headers": {},
        "description": "Direct forced browsing without Authorization header",
        "is_attack": True,
        "expected_rule": "RULE_UNAUTHORIZED_ACCESS_01"
    },
    {
        "endpoint": "/api/target/admin/secrets",
        "headers": {"Authorization": "Bearer forged-fake-token-xyz"},
        "description": "Unauthorized access attempt with forged token",
        "is_attack": True,
        "expected_rule": "RULE_UNAUTHORIZED_ACCESS_01"
    },
    {
        "endpoint": "/api/target/admin/secrets",
        "headers": {"Authorization": "Bearer token-user-alice"},
        "description": "Privilege escalation probe using standard customer token",
        "is_attack": True,
        "expected_rule": "RULE_UNAUTHORIZED_ACCESS_01"
    }
]

SQL_INJECTION_PROBES = [
    {
        "query": "' OR '1'='1",
        "description": "Classic SQL tautology probe",
        "is_attack": True,
        "expected_rule": "RULE_SQLI_DETECTED_01"
    },
    {
        "query": "' OR 1=1 --",
        "description": "SQL inline comment bypass probe",
        "is_attack": True,
        "expected_rule": "RULE_SQLI_DETECTED_01"
    },
    {
        "query": "admin' --",
        "description": "Admin username truncation probe",
        "is_attack": True,
        "expected_rule": "RULE_SQLI_DETECTED_01"
    },
    {
        "query": "' UNION SELECT 1, 'cyberfortify_probe', 'TEST', '0' --",
        "description": "Harmless union-based fingerprint probe",
        "is_attack": True,
        "expected_rule": "RULE_SQLI_DETECTED_01"
    }
]

INPUT_VALIDATION_PROBES = [
    {
        "author": "tester_redteam",
        "content": "<script>console.log('cyberfortify-probe-1')</script>",
        "description": "Basic script tag injection probe",
        "is_attack": True,
        "expected_rule": "RULE_XSS_INPUT_01"
    },
    {
        "author": "tester_redteam",
        "content": "<img src=x onerror=console.log('probe-img')>",
        "description": "Event-handler attribute injection probe",
        "is_attack": True,
        "expected_rule": "RULE_XSS_INPUT_01"
    },
    {
        "author": "tester_redteam",
        "content": "\"><svg/onload=console.log('svg-probe')>",
        "description": "SVG vector event payload probe",
        "is_attack": True,
        "expected_rule": "RULE_XSS_INPUT_01"
    },
    {
        "author": "tester_redteam",
        "content": "javascript:console.log('uri_scheme')",
        "description": "Pseudo-protocol URI injection probe",
        "is_attack": True,
        "expected_rule": "RULE_XSS_INPUT_01"
    }
]

BENIGN_ACTIVITY = [
    {
        "type": "search",
        "query": "alice",
        "is_attack": False,
        "description": "Normal search for customer Alice"
    },
    {
        "type": "search",
        "query": "bob",
        "is_attack": False,
        "description": "Normal search for customer Bob"
    },
    {
        "type": "feedback",
        "author": "alice",
        "content": "Thank you for the quick transfer process! Really clean UI.",
        "is_attack": False,
        "description": "Standard harmless customer feedback"
    },
    {
        "type": "login",
        "username": "alice",
        "password": "AliceSecure123#",
        "is_attack": False,
        "description": "Legitimate login by authenticated customer Alice"
    }
]
