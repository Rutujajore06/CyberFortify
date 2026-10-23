import urllib.parse
from app.config import Config

def validate_target_url(raw_url):
    """
    Validates the target URL server-side to strictly enforce Fortress Bank demo scope.
    
    Enforcement rules:
    1. Rejects empty, whitespace-only, or excessively long strings.
    2. Rejects malformed or unparseable URLs.
    3. Rejects unsupported schemes (only Config.DEMO_ALLOWED_SCHEMES, e.g. http).
    4. Rejects credentials embedded in the URL (userinfo: username / password).
    5. Rejects unexpected hosts (only Config.DEMO_ALLOWED_HOSTS, e.g. 127.0.0.1, localhost).
    6. Rejects unexpected ports (must match Config.DEMO_ALLOWED_PORT).
    7. Rejects path traversal and out-of-scope endpoint paths.
    
    Returns:
        (is_valid: bool, error_message: str | None, normalized_url: str | None)
    """
    if not raw_url or not isinstance(raw_url, str):
        return False, "Target URL is required. Please provide the Fortress Bank demo URL.", None

    url_str = raw_url.strip()
    if not url_str:
        return False, "Target URL cannot be empty.", None

    if len(url_str) > 2048:
        return False, "URL exceeds maximum allowable length of 2048 characters.", None

    try:
        parsed = urllib.parse.urlsplit(url_str)
    except Exception as e:
        return False, f"Malformed URL syntax: {str(e)}", None

    # 1. Scheme Check
    scheme = (parsed.scheme or '').lower()
    if not scheme:
        return False, (
            "Missing URL scheme. Only HTTP is supported for the local demo "
            f"(e.g., http://127.0.0.1:{Config.DEMO_ALLOWED_PORT})."
        ), None

    if scheme not in Config.DEMO_ALLOWED_SCHEMES:
        allowed = ', '.join(sorted(Config.DEMO_ALLOWED_SCHEMES))
        return False, (
            f"Unsupported URL scheme '{scheme}'. Only [{allowed}] is permitted for the local Fortress Bank demo."
        ), None

    # 2. Credentials in URL Check
    if parsed.username or parsed.password:
        return False, "URL credentials (userinfo) are not permitted in the assessment target.", None

    # 3. Host Check
    hostname = (parsed.hostname or '').lower()
    if not hostname:
        return False, "Invalid URL: Missing target hostname.", None

    if hostname not in Config.DEMO_ALLOWED_HOSTS:
        allowed_hosts = ', '.join(sorted(Config.DEMO_ALLOWED_HOSTS))
        return False, (
            f"Out-of-scope host '{hostname}'. Website Security Assessment is strictly restricted to the "
            f"Fortress Bank demo application ({allowed_hosts}). External targets are strictly prohibited."
        ), None

    # 4. Port Check
    port = parsed.port
    if port is None:
        if Config.DEMO_ALLOWED_PORT != 80:
            return False, (
                f"Missing or mismatched port. The Fortress Bank demo runs on port {Config.DEMO_ALLOWED_PORT}. "
                f"Please specify http://{hostname}:{Config.DEMO_ALLOWED_PORT}"
            ), None
        port = 80
    elif port != Config.DEMO_ALLOWED_PORT:
        return False, (
            f"Unexpected port '{port}'. Assessment is strictly restricted to demo port {Config.DEMO_ALLOWED_PORT}."
        ), None

    # 5. Path Check
    path = parsed.path or '/'
    if '..' in path or '%2e%2e' in path.lower():
        return False, "Invalid URL: Directory traversal sequences are forbidden.", None

    # Ensure path is within demo scope
    normalized_path = path if path.startswith('/') else f"/{path}"
    allowed_prefixes = ('/', '/api/target', '/api/target/')
    is_allowed_path = (
        normalized_path == '/' or
        normalized_path.startswith('/api/target') or
        normalized_path in ('/dashboard', '/simulations', '/alerts', '/logs', '/defenses', '/report', '/assessment')
    )
    if not is_allowed_path:
        return False, (
            f"Unexpected path '{normalized_path}'. Assessment target path must be root ('/') or within "
            "the Fortress Bank demo endpoints ('/api/target/*')."
        ), None

    normalized_url = f"{scheme}://{hostname}:{port}{normalized_path}"
    return True, None, normalized_url
