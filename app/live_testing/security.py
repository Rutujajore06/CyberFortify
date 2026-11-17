import re
import ssl
import time
import socket
import threading
import ipaddress
import http.client
import urllib.parse
from collections import deque
from flask import has_app_context, current_app
from app.config import Config
from app.models.live_target_model import log_live_audit


class LiveSecurityError(Exception):
    """Base exception for live website target security violations."""
    def __init__(self, message, error_code='SECURITY_VIOLATION', status_code=403):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code


class SSRFBlockedError(LiveSecurityError):
    """Raised when a URL, hostname, IP, or redirect triggers SSRF protection."""
    def __init__(self, message, error_code='SSRF_BLOCKED'):
        super().__init__(message, error_code=error_code, status_code=403)


class ScopeViolationError(LiveSecurityError):
    """Raised when domain, path, method, port, or protocol violates approved scope."""
    def __init__(self, message, error_code='SCOPE_VIOLATION'):
        super().__init__(message, error_code=error_code, status_code=403)


class RateLimitExceededError(LiveSecurityError):
    """Raised when a target exceeds its configured maximum request rate."""
    def __init__(self, message):
        super().__init__(message, error_code='RATE_LIMIT_EXCEEDED', status_code=429)


def _cfg(key, default=None):
    if has_app_context() and key in current_app.config:
        return current_app.config[key]
    return getattr(Config, key, default)


_NAT64_WELL_KNOWN_PREFIX = ipaddress.ip_network('64:ff9b::/96')

# Blocked non-public IPv4 / IPv6 special ranges (in addition to ipaddress flags)
_EXTRA_BLOCKED_NETWORKS = [
    ipaddress.ip_network('100.64.0.0/10'),     # Carrier-grade NAT (RFC 6598)
    ipaddress.ip_network('169.254.0.0/16'),    # Link-local / Cloud Metadata (AWS/GCP/Azure)
    ipaddress.ip_network('192.0.0.0/24'),      # IETF Protocol Assignments
    ipaddress.ip_network('192.0.2.0/24'),      # TEST-NET-1
    ipaddress.ip_network('198.18.0.0/15'),     # Network Interconnect Device Benchmark
    ipaddress.ip_network('198.51.100.0/24'),   # TEST-NET-2
    ipaddress.ip_network('203.0.113.0/24'),    # TEST-NET-3
    ipaddress.ip_network('240.0.0.0/4'),       # Reserved for future use
    ipaddress.ip_network('fc00::/7'),          # IPv6 Unique Local
    ipaddress.ip_network('fe80::/10'),         # IPv6 Link-Local
    ipaddress.ip_network('2001:db8::/32'),     # IPv6 Documentation
]

_BLOCKED_HOSTNAMES = {
    'localhost',
    'localhost.localdomain',
    'ip6-localhost',
    'ip6-loopback',
    'metadata.google.internal',
    'metadata',
    'instance-data',
}

_BLOCKED_SUFFIXES = (
    '.localhost',
    '.local',
    '.internal',
    '.localdomain',
    '.home.arpa',
    '.lan',
)

_HOSTNAME_LABEL_RE = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')

_SENSITIVE_HEADERS = {
    'cookie',
    'authorization',
    'proxy-authorization',
    'x-api-key',
    'x-auth-token',
}


def is_ip_blocked(ip_str):
    """
    Returns (blocked: bool, reason: str | None) for an IPv4 or IPv6 address string.
    Strictly blocks localhost, private, link-local, metadata, multicast, reserved,
    unspecified, CGNAT, and IPv4-mapped IPv6 private addresses.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return True, f"Invalid IP address format: '{ip_str}'"

    # Unwrap IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 or ::ffff:169.254.169.254)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        return is_ip_blocked(str(ip_obj.ipv4_mapped))

    # Unwrap RFC 6052 NAT64/DNS64 well-known prefix (64:ff9b::/96) and validate embedded IPv4
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj in _NAT64_WELL_KNOWN_PREFIX:
        embedded_v4 = ipaddress.IPv4Address(int(ip_obj) & 0xFFFFFFFF)
        blocked, reason = is_ip_blocked(str(embedded_v4))
        if blocked:
            return True, f"NAT64 address '{ip_obj}' wraps blocked IPv4 '{embedded_v4}': {reason}"
        return False, None

    if ip_obj.is_loopback:
        return True, f"Loopback IP address '{ip_obj}' is blocked."
    if ip_obj.is_private:
        return True, f"Private IP address '{ip_obj}' is blocked."
    if ip_obj.is_link_local:
        return True, f"Link-local / cloud metadata IP address '{ip_obj}' is blocked."
    if ip_obj.is_multicast:
        return True, f"Multicast IP address '{ip_obj}' is blocked."
    if ip_obj.is_reserved:
        return True, f"Reserved IP address '{ip_obj}' is blocked."
    if ip_obj.is_unspecified:
        return True, f"Unspecified IP address '{ip_obj}' is blocked."

    for net in _EXTRA_BLOCKED_NETWORKS:
        if ip_obj.version == net.version and ip_obj in net:
            return True, f"Non-public IP address '{ip_obj}' ({net}) is blocked."

    if not ip_obj.is_global:
        return True, f"Non-global IP address '{ip_obj}' is blocked."

    return False, None


def is_hostname_ip_literal_or_obfuscated(hostname):
    """
    Detects IPv4/IPv6 literals as well as integer/hex/octal IP obfuscations
    (e.g. 2130706433, 0x7f000001, 0177.0.0.1).
    """
    h = hostname.strip('[]')
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass

    # Pure numeric or hex single-label host (e.g. 2130706433 or 0x7f000001)
    if re.fullmatch(r'(?:0x[0-9a-f]+|[0-9]+)', h, re.IGNORECASE):
        return True

    # Dotted numeric/octal/hex parts (e.g. 0177.0.0.1 or 127.1)
    parts = h.split('.')
    if parts and all(re.fullmatch(r'(?:0x[0-9a-f]+|0[0-7]*|[0-9]+)', p, re.IGNORECASE) for p in parts):
        return True

    return False


def validate_public_hostname(hostname):
    """
    Validates that a hostname is a syntactically valid public domain name
    and not localhost, internal, or a raw/obfuscated IP literal.
    Returns (is_valid: bool, error_message: str | None).
    """
    if not hostname or not isinstance(hostname, str):
        return False, "Missing hostname in URL."

    host = hostname.strip().lower().rstrip('.')
    if not host or len(host) > 253:
        return False, "Invalid hostname length."

    if host in _BLOCKED_HOSTNAMES:
        return False, f"Host '{host}' is a blocked local/internal hostname."

    for suffix in _BLOCKED_SUFFIXES:
        if host.endswith(suffix):
            return False, f"Host '{host}' uses a blocked local/internal domain suffix ({suffix})."

    if is_hostname_ip_literal_or_obfuscated(host):
        return False, (
            f"Raw or obfuscated IP address targets ('{host}') are not allowed. "
            "Provide a public domain name."
        )

    labels = host.split('.')
    if len(labels) < 2:
        return False, f"Hostname '{host}' must be a fully qualified public domain name."

    # TLD must not be all numeric
    if labels[-1].isdigit():
        return False, f"Invalid top-level domain in hostname '{host}'."

    for label in labels:
        if not _HOSTNAME_LABEL_RE.match(label):
            return False, f"Invalid domain label '{label}' in hostname '{host}'."

    return True, None


def validate_registration_url(raw_url):
    """
    Validates a URL submitted for Live Website Target registration.
    Enforces protocol (http/https), port (80/443), no embedded credentials,
    public domain name, and clean path.
    Returns (is_valid: bool, error_message: str | None, parsed_info: dict | None).
    """
    if not raw_url or not isinstance(raw_url, str):
        return False, "Target URL is required.", None

    url_str = raw_url.strip()
    if not url_str:
        return False, "Target URL cannot be empty.", None

    if len(url_str) > 2048:
        return False, "Target URL exceeds maximum allowed length (2048 chars).", None

    if any(c in url_str for c in ('\r', '\n', '\x00')):
        return False, "Target URL contains forbidden control characters.", None

    try:
        parsed = urllib.parse.urlsplit(url_str)
    except Exception as e:
        return False, f"Malformed URL syntax: {str(e)}", None

    allowed_schemes = _cfg('LIVE_ALLOWED_SCHEMES', {'http', 'https'})
    allowed_ports = _cfg('LIVE_ALLOWED_PORTS', {80, 443})

    scheme = (parsed.scheme or '').lower()
    if scheme not in allowed_schemes:
        return False, (
            f"Unsupported URL scheme '{scheme or '(none)'}'. "
            f"Only {', '.join(sorted(allowed_schemes))} are permitted."
        ), None

    if parsed.username or parsed.password:
        return False, "Embedded credentials (userinfo) are strictly forbidden in target URLs.", None

    hostname = (parsed.hostname or '').lower().rstrip('.')
    host_ok, host_err = validate_public_hostname(hostname)
    if not host_ok:
        return False, host_err, None

    try:
        port = parsed.port
    except ValueError:
        return False, "Invalid port specification in URL.", None

    effective_port = port if port is not None else (443 if scheme == 'https' else 80)
    if effective_port not in allowed_ports:
        return False, (
            f"Port {effective_port} is restricted. Only standard web ports {sorted(list(allowed_ports))} are permitted."
        ), None
    if scheme == 'http' and effective_port != 80:
        return False, "HTTP scheme is restricted to port 80.", None
    if scheme == 'https' and effective_port != 443:
        return False, "HTTPS scheme is restricted to port 443.", None

    path = parsed.path or '/'
    if '..' in path or '%2e%2e' in path.lower() or '\\' in path:
        return False, "Directory traversal sequences are forbidden in URL paths.", None

    if not path.startswith('/'):
        path = '/' + path

    # Normalize URL without default port clutter
    normalized_url = f"{scheme}://{hostname}{path}"
    if parsed.query:
        normalized_url += f"?{parsed.query}"

    return True, None, {
        'normalized_url': normalized_url,
        'scheme': scheme,
        'domain': hostname,
        'port': effective_port,
        'path': path,
        'query': parsed.query
    }


def normalize_approved_paths(paths_input):
    """
    Validates and normalizes approved testing paths.
    Accepts list or comma/newline separated string.
    """
    if isinstance(paths_input, str):
        raw_list = [p.strip() for p in re.split(r'[\n,]+', paths_input) if p.strip()]
    elif isinstance(paths_input, (list, tuple)):
        raw_list = [str(p).strip() for p in paths_input if str(p).strip()]
    else:
        raw_list = ['/']

    if not raw_list:
        raw_list = ['/']

    cleaned = []
    for p in raw_list:
        if '..' in p or '%2e%2e' in p.lower() or '\\' in p or '\x00' in p:
            return False, f"Invalid approved path '{p}': traversal characters are forbidden.", None
        if not p.startswith('/'):
            p = '/' + p
        if p not in cleaned:
            cleaned.append(p)
    return True, None, cleaned


def normalize_allowed_methods(methods_input):
    """
    Validates allowed HTTP methods against global safe non-invasive methods (GET, HEAD, OPTIONS).
    """
    global_safe = _cfg('LIVE_ALLOWED_METHODS', {'GET', 'HEAD', 'OPTIONS'})
    if isinstance(methods_input, str):
        raw_list = [m.strip().upper() for m in re.split(r'[\n,\s]+', methods_input) if m.strip()]
    elif isinstance(methods_input, (list, tuple)):
        raw_list = [str(m).strip().upper() for m in methods_input if str(m).strip()]
    else:
        raw_list = ['GET', 'HEAD']

    if not raw_list:
        raw_list = ['GET', 'HEAD']

    disallowed = [m for m in raw_list if m not in global_safe]
    if disallowed:
        return False, (
            f"Disallowed HTTP method(s): {', '.join(disallowed)}. "
            f"Only safe non-invasive methods {sorted(list(global_safe))} are permitted."
        ), None

    deduped = []
    for m in raw_list:
        if m not in deduped:
            deduped.append(m)
    return True, None, deduped


def is_path_approved(request_path, approved_paths):
    """
    Checks whether a request path is permitted under the target's approved_paths list.
    Supports exact match and trailing wildcard prefix (e.g., '/app/*').
    """
    if not request_path:
        request_path = '/'
    if '..' in request_path or '%2e%2e' in request_path.lower() or '\\' in request_path:
        return False

    norm_req = request_path if request_path.startswith('/') else '/' + request_path
    # Strip trailing slash for comparison except root
    req_cmp = norm_req.rstrip('/') or '/'

    for allowed in (approved_paths or ['/']):
        if allowed == '/*':
            return True
        if allowed.endswith('/*'):
            prefix = allowed[:-1]  # keeps trailing '/'
            if norm_req.startswith(prefix) or norm_req == prefix.rstrip('/'):
                return True
        else:
            allowed_cmp = allowed.rstrip('/') or '/'
            if req_cmp == allowed_cmp:
                return True
    return False


def is_method_approved(method, allowed_methods):
    """Verifies HTTP method is globally safe AND permitted for this target."""
    m = (method or '').upper()
    global_safe = _cfg('LIVE_ALLOWED_METHODS', {'GET', 'HEAD', 'OPTIONS'})
    target_allowed = {x.upper() for x in (allowed_methods or [])}
    return m in global_safe and m in target_allowed


def _resolve_dns_with_timeout(hostname, port, timeout):
    """
    Executes socket.getaddrinfo inside a daemon thread with a strict wall-clock timeout.
    Prevents indefinite OS resolver hangs when network/DNS is unreachable.
    """
    result = {'addr_info': None, 'error': None}

    def _worker():
        try:
            result['addr_info'] = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except Exception as exc:
            result['error'] = exc

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    t.join(timeout=timeout)
    if t.is_alive():
        raise TimeoutError(f"DNS resolution timed out after {timeout:.1f}s for '{hostname}'.")
    if result['error'] is not None:
        raise result['error']
    return result['addr_info']


def resolve_and_validate_host(hostname, port, target_uuid=None, dns_timeout=None):
    """
    Resolves DNS for `hostname` with a strict timeout and validates EVERY resolved IP address
    against the private/loopback/link-local/metadata/reserved IP blocklist.
    Returns list of validated public IP strings (for DNS-rebinding-safe IP pinning).
    Raises SSRFBlockedError if DNS fails, times out, or ANY resolved IP is non-public.
    """
    host_ok, host_err = validate_public_hostname(hostname)
    if not host_ok:
        log_live_audit(
            action='DNS_VALIDATION_BLOCKED',
            outcome='BLOCKED',
            target_uuid=target_uuid,
            domain=hostname,
            reason=host_err
        )
        raise SSRFBlockedError(host_err, error_code='INVALID_HOST')

    effective_dns_timeout = float(
        dns_timeout if dns_timeout is not None else _cfg('LIVE_DNS_TIMEOUT', 3.0)
    )

    try:
        addr_info = _resolve_dns_with_timeout(hostname, port, timeout=effective_dns_timeout)
    except TimeoutError as e:
        msg = str(e)
        log_live_audit(
            action='DNS_RESOLUTION_TIMEOUT',
            outcome='ERROR',
            target_uuid=target_uuid,
            domain=hostname,
            reason=msg
        )
        raise SSRFBlockedError(msg, error_code='DNS_RESOLUTION_TIMEOUT')
    except (socket.gaierror, OSError) as e:
        msg = f"DNS resolution failed for '{hostname}': {str(e)}"
        log_live_audit(
            action='DNS_RESOLUTION_FAILED',
            outcome='ERROR',
            target_uuid=target_uuid,
            domain=hostname,
            reason=msg
        )
        raise SSRFBlockedError(msg, error_code='DNS_RESOLUTION_FAILED')

    if not addr_info:
        msg = f"DNS resolution returned no addresses for '{hostname}'."
        log_live_audit(
            action='DNS_RESOLUTION_EMPTY',
            outcome='BLOCKED',
            target_uuid=target_uuid,
            domain=hostname,
            reason=msg
        )
        raise SSRFBlockedError(msg, error_code='DNS_RESOLUTION_FAILED')

    validated_ips = []
    for family, socktype, proto, canonname, sockaddr in addr_info:
        ip_str = sockaddr[0]
        blocked, block_reason = is_ip_blocked(ip_str)
        if blocked:
            msg = (
                f"SSRF Protection Blocked: Host '{hostname}' resolved to disallowed address '{ip_str}'. "
                f"{block_reason}"
            )
            log_live_audit(
                action='SSRF_IP_BLOCKED',
                outcome='BLOCKED',
                target_uuid=target_uuid,
                domain=hostname,
                resolved_ip=ip_str,
                reason=msg
            )
            raise SSRFBlockedError(msg, error_code='PRIVATE_IP_BLOCKED')
        if ip_str not in validated_ips:
            validated_ips.append(ip_str)

    return validated_ips


# ==============================================================================
# Per-Target Thread-Safe Sliding Window Rate Limiter
# ==============================================================================

class TargetRateLimiter:
    """Enforces per-target maximum requests-per-minute limits using a 60s sliding window."""

    def __init__(self):
        self._lock = threading.Lock()
        self._windows = {}  # target_uuid -> deque of monotonic timestamps

    def acquire(self, target_uuid, max_per_minute, domain=None, url=None):
        """
        Records a request if under the limit; raises RateLimitExceededError otherwise.
        """
        limit = max(1, min(int(max_per_minute), int(_cfg('LIVE_MAX_RATE_LIMIT', 60))))
        now = time.monotonic()
        cutoff = now - 60.0

        with self._lock:
            dq = self._windows.setdefault(target_uuid, deque())
            while dq and dq[0] <= cutoff:
                dq.popleft()

            if len(dq) >= limit:
                msg = (
                    f"Rate limit exceeded for target '{domain or target_uuid}': "
                    f"maximum {limit} requests/minute permitted."
                )
                log_live_audit(
                    action='RATE_LIMIT_BLOCKED',
                    outcome='BLOCKED',
                    target_uuid=target_uuid,
                    domain=domain,
                    url=url,
                    reason=msg
                )
                raise RateLimitExceededError(msg)

            dq.append(now)

    def reset(self, target_uuid=None):
        """Clears rate limiter state (useful for unit tests)."""
        with self._lock:
            if target_uuid:
                self._windows.pop(target_uuid, None)
            else:
                self._windows.clear()


rate_limiter = TargetRateLimiter()


# ==============================================================================
# DNS-Rebinding-Safe Pinned-IP HTTP / HTTPS Connections
# ==============================================================================

class PinnedHTTPConnection(http.client.HTTPConnection):
    """
    HTTPConnection that connects directly to a pre-validated IP address
    while preserving the original domain in Host headers. Prevents DNS rebinding.
    Enforces strict connect and read timeouts.
    """
    def __init__(self, host, port, pinned_ip, timeout=5.0, read_timeout=None):
        super().__init__(host, port=port, timeout=timeout)
        self.pinned_ip = pinned_ip
        self.read_timeout = float(read_timeout if read_timeout is not None else timeout)

    def connect(self):
        self.sock = socket.create_connection((self.pinned_ip, self.port), self.timeout)
        self.sock.settimeout(self.read_timeout)


def create_verified_ssl_context():
    """
    Creates a strict TLS verification context using the certifi Mozilla CA bundle
    when available (important on Windows/MSYS2 where OpenSSL default CA paths may be missing).
    """
    try:
        import certifi
        ctx = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """
    HTTPSConnection that connects directly to a pre-validated IP address,
    wraps the socket in TLS with SNI set to the original hostname, and verifies
    the TLS certificate against the original hostname. Prevents DNS rebinding.
    Enforces strict connect, TLS handshake, and read timeouts.
    """
    def __init__(self, host, port, pinned_ip, timeout=5.0, read_timeout=None, context=None):
        ctx = context or create_verified_ssl_context()
        super().__init__(host, port=port, timeout=timeout, context=ctx)
        self.pinned_ip = pinned_ip
        self.read_timeout = float(read_timeout if read_timeout is not None else timeout)
        self.peer_cert = None
        self.tls_version = None
        self.tls_cipher = None

    def connect(self):
        raw_sock = socket.create_connection((self.pinned_ip, self.port), self.timeout)
        raw_sock.settimeout(self.read_timeout)
        try:
            self.sock = self._context.wrap_socket(raw_sock, server_hostname=self.host)
            self.sock.settimeout(self.read_timeout)
            self.peer_cert = self.sock.getpeercert()
            self.tls_version = self.sock.version()
            self.tls_cipher = self.sock.cipher()
        except Exception:
            raw_sock.close()
            raise


def _sanitize_request_headers(custom_headers):
    """Strips any credentials, cookies, or authorization tokens from outgoing headers."""
    safe = {
        'User-Agent': 'CyberFortify-SafeAudit/1.0 (+authorized-passive-assessment)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Connection': 'close'
    }
    if custom_headers:
        for k, v in custom_headers.items():
            if k.lower() not in _SENSITIVE_HEADERS:
                safe[k] = v
    return safe


def safe_http_request(
    url,
    target,
    method='GET',
    follow_redirects=False,
    max_redirects=None,
    headers=None,
    timeout=None,
    skip_path_check=False
):
    """
    Executes a single or redirect-validated safe HTTP/HTTPS request against an APPROVED target.

    Protections enforced on EVERY request and EVERY redirect hop:
    1. Scheme restricted to http/https; ports restricted to 80/443; no embedded credentials.
    2. Domain strictly matched against the approved target's domain.
    3. Path strictly matched against target's approved_paths (unless internal redirect/well-known verify).
    4. HTTP method strictly matched against safe passive methods & target's allowed_methods.
    5. DNS resolved and EVERY IP validated against private/loopback/metadata/reserved ranges.
    6. TCP socket pinned to the validated IP (prevents DNS rebinding).
    7. Strict connect/read timeout and maximum response body byte cap.
    8. Per-target rate limit enforced on every outgoing hop.
    9. Credentials & cookies stripped; never forwarded to any destination.
    10. Detailed SQLite audit logging of every hop and any blocked attempt.

    Returns dict with:
      url, final_url, status_code, headers (case-insensitive dict + raw list),
      set_cookies (list), body (bytes), resolved_ip, redirect_chain (list),
      tls_info (dict | None)
    """
    target_uuid = target['target_uuid']
    approved_domain = target['domain'].lower()
    approved_paths = target.get('approved_paths') or ['/']
    allowed_methods = target.get('allowed_methods') or ['GET', 'HEAD']
    max_rate = target.get('max_request_rate', 10)

    req_timeout = float(timeout if timeout is not None else _cfg('LIVE_REQUEST_TIMEOUT', 5.0))
    hop_limit = int(max_redirects if max_redirects is not None else _cfg('LIVE_MAX_REDIRECTS', 5))
    max_bytes = int(_cfg('LIVE_MAX_RESPONSE_BYTES', 524288))

    method_upper = (method or 'GET').upper()
    if not is_method_approved(method_upper, allowed_methods):
        msg = (
            f"HTTP method '{method_upper}' is not allowed for target '{approved_domain}'. "
            f"Approved methods: {allowed_methods}."
        )
        log_live_audit(
            action='HTTP_METHOD_BLOCKED',
            outcome='BLOCKED',
            target_uuid=target_uuid,
            domain=approved_domain,
            url=url,
            http_method=method_upper,
            reason=msg
        )
        raise ScopeViolationError(msg, error_code='METHOD_NOT_ALLOWED')

    current_url = url
    redirect_chain = []
    safe_headers = _sanitize_request_headers(headers)

    for hop in range(hop_limit + 1):
        # 1. Validate URL syntax, scheme, port, hostname, credentials
        is_valid, err_msg, parsed = validate_registration_url(current_url)
        if not is_valid:
            log_live_audit(
                action='REQUEST_URL_BLOCKED',
                outcome='BLOCKED',
                target_uuid=target_uuid,
                domain=approved_domain,
                url=current_url,
                http_method=method_upper,
                reason=err_msg
            )
            raise SSRFBlockedError(err_msg, error_code='INVALID_URL')

        req_domain = parsed['domain']
        req_scheme = parsed['scheme']
        req_port = parsed['port']
        req_path = parsed['path']
        req_query = parsed['query']

        # 2. Enforce Approved Domain Match
        if req_domain != approved_domain:
            msg = (
                f"Unauthorized domain '{req_domain}' blocked. "
                f"Only approved domain '{approved_domain}' may be contacted."
            )
            log_live_audit(
                action='UNAUTHORIZED_DOMAIN_BLOCKED',
                outcome='BLOCKED',
                target_uuid=target_uuid,
                domain=req_domain,
                url=current_url,
                http_method=method_upper,
                reason=msg
            )
            raise ScopeViolationError(msg, error_code='UNAUTHORIZED_DOMAIN')

        # 3. Enforce Approved Path
        if not skip_path_check and not is_path_approved(req_path, approved_paths):
            msg = (
                f"Path '{req_path}' is outside approved testing paths {approved_paths} "
                f"for '{approved_domain}'."
            )
            log_live_audit(
                action='UNAPPROVED_PATH_BLOCKED',
                outcome='BLOCKED',
                target_uuid=target_uuid,
                domain=req_domain,
                url=current_url,
                http_method=method_upper,
                reason=msg
            )
            raise ScopeViolationError(msg, error_code='UNAPPROVED_PATH')

        # 4. Enforce Rate Limit
        rate_limiter.acquire(target_uuid, max_rate, domain=req_domain, url=current_url)

        # 5. Resolve DNS & Validate All IPs (SSRF Protection)
        validated_ips = resolve_and_validate_host(req_domain, req_port, target_uuid=target_uuid)
        pinned_ip = validated_ips[0]

        # 6. Execute Pinned-IP Connection (DNS Rebinding Protection)
        full_path = f"{req_path}?{req_query}" if req_query else req_path
        conn = None
        tls_info = None
        try:
            if req_scheme == 'https':
                conn = PinnedHTTPSConnection(req_domain, req_port, pinned_ip=pinned_ip, timeout=req_timeout)
            else:
                conn = PinnedHTTPConnection(req_domain, req_port, pinned_ip=pinned_ip, timeout=req_timeout)

            # Never forward cookies or auth headers across hops
            hop_headers = _sanitize_request_headers(safe_headers)
            conn.request(method_upper, full_path, headers=hop_headers)
            resp = conn.getresponse()

            status_code = resp.status
            raw_headers = resp.getheaders()
            headers_lower = {}
            set_cookies = []
            for hk, hv in raw_headers:
                kl = hk.lower()
                if kl == 'set-cookie':
                    set_cookies.append(hv)
                if kl in headers_lower:
                    headers_lower[kl] = f"{headers_lower[kl]}, {hv}"
                else:
                    headers_lower[kl] = hv

            # Read capped body for non-HEAD requests
            body = b''
            if method_upper != 'HEAD':
                body = resp.read(max_bytes)

            if isinstance(conn, PinnedHTTPSConnection):
                tls_info = {
                    'version': conn.tls_version,
                    'cipher': conn.tls_cipher,
                    'cert': conn.peer_cert
                }

            log_live_audit(
                action='LIVE_HTTP_REQUEST',
                outcome='ALLOWED',
                target_uuid=target_uuid,
                domain=req_domain,
                url=current_url,
                http_method=method_upper,
                resolved_ip=pinned_ip,
                status_code=status_code,
                reason=f"Safe passive {method_upper} completed (hop {hop})."
            )

        except (socket.timeout, TimeoutError) as e:
            log_live_audit(
                action='LIVE_HTTP_TIMEOUT',
                outcome='ERROR',
                target_uuid=target_uuid,
                domain=req_domain,
                url=current_url,
                http_method=method_upper,
                resolved_ip=pinned_ip,
                reason=f"HTTP request timed out after {req_timeout:.1f}s: {str(e)}"
            )
            raise
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

        # 7. Handle Redirects Manually with Full Revalidation
        if status_code in (301, 302, 303, 307, 308) and 'location' in headers_lower:
            location = headers_lower['location'].strip()
            next_url = urllib.parse.urljoin(current_url, location)
            redirect_chain.append({
                'from_url': current_url,
                'status_code': status_code,
                'location': location,
                'resolved_next_url': next_url,
                'resolved_ip': pinned_ip
            })
            if follow_redirects:
                if hop >= hop_limit:
                    raise SSRFBlockedError(
                        f"Maximum redirect limit ({hop_limit}) exceeded.",
                        error_code='TOO_MANY_REDIRECTS'
                    )
                # Loop continues and strictly re-validates next_url (scheme, port, domain, path, DNS, IP)
                current_url = next_url
                continue

        return {
            'url': url,
            'final_url': current_url,
            'status_code': status_code,
            'headers': headers_lower,
            'raw_headers': raw_headers,
            'set_cookies': set_cookies,
            'body': body,
            'resolved_ip': pinned_ip,
            'redirect_chain': redirect_chain,
            'tls_info': tls_info
        }

    raise SSRFBlockedError(f"Maximum redirect limit ({hop_limit}) exceeded.", error_code='TOO_MANY_REDIRECTS')
