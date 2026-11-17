import re
import ssl
import socket
import datetime
import urllib.parse
from app.models.live_target_model import (
    check_target_authorization,
    create_live_assessment_record,
    update_live_assessment_progress,
    finalize_live_assessment,
    mark_target_verified,
    log_live_audit,
    utc_now
)
from app.live_testing.security import (
    safe_http_request,
    resolve_and_validate_host,
    create_verified_ssl_context,
    rate_limiter,
    LiveSecurityError,
    SSRFBlockedError,
    ScopeViolationError,
    RateLimitExceededError,
    _cfg
)


def parse_tls_not_after(not_after_str):
    """Parses OpenSSL certificate notAfter timestamp (e.g. 'Nov 17 23:59:59 2026 GMT') into UTC datetime."""
    if not not_after_str:
        return None
    for fmt in ('%b %d %H:%M:%S %Y %Z', '%b  %d %H:%M:%S %Y %Z'):
        try:
            dt = datetime.datetime.strptime(not_after_str.strip(), fmt)
            return dt.replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            continue
    return None


def inspect_tls_certificate(domain, target_uuid, max_request_rate, timeout=None):
    """
    Performs a safe, pinned-IP TLS handshake on port 443 to inspect real certificate validity,
    expiry, protocol version, issuer, and subject.
    Prevents SSRF and DNS rebinding by pinning the validated public IP.
    """
    req_timeout = float(timeout if timeout is not None else _cfg('LIVE_REQUEST_TIMEOUT', 5.0))
    rate_limiter.acquire(target_uuid, max_request_rate, domain=domain, url=f"https://{domain}:443")
    validated_ips = resolve_and_validate_host(domain, 443, target_uuid=target_uuid)
    pinned_ip = validated_ips[0]

    ctx = create_verified_ssl_context()

    raw_sock = None
    tls_sock = None
    try:
        raw_sock = socket.create_connection((pinned_ip, 443), timeout=req_timeout)
        raw_sock.settimeout(req_timeout)
        tls_sock = ctx.wrap_socket(raw_sock, server_hostname=domain)
        tls_sock.settimeout(req_timeout)
        cert = tls_sock.getpeercert()
        tls_version = tls_sock.version()
        cipher = tls_sock.cipher()

        log_live_audit(
            action='LIVE_TLS_HANDSHAKE',
            outcome='ALLOWED',
            target_uuid=target_uuid,
            domain=domain,
            url=f"https://{domain}:443",
            http_method='TLS',
            resolved_ip=pinned_ip,
            reason=f"TLS handshake verified ({tls_version})."
        )
        return {
            'reachable': True,
            'verified': True,
            'resolved_ip': pinned_ip,
            'tls_version': tls_version,
            'cipher': cipher[0] if cipher else None,
            'cert': cert,
            'error': None
        }
    except ssl.SSLCertVerificationError as e:
        log_live_audit(
            action='LIVE_TLS_CERT_ERROR',
            outcome='WARNING',
            target_uuid=target_uuid,
            domain=domain,
            url=f"https://{domain}:443",
            http_method='TLS',
            resolved_ip=pinned_ip,
            reason=f"TLS certificate verification failed: {str(e)}"
        )
        return {
            'reachable': True,
            'verified': False,
            'resolved_ip': pinned_ip,
            'tls_version': None,
            'cipher': None,
            'cert': None,
            'error': str(e)
        }
    except (ssl.SSLError, socket.timeout, OSError) as e:
        log_live_audit(
            action='LIVE_TLS_CONNECT_ERROR',
            outcome='ERROR',
            target_uuid=target_uuid,
            domain=domain,
            url=f"https://{domain}:443",
            http_method='TLS',
            resolved_ip=pinned_ip,
            reason=f"TLS connection failed: {str(e)}"
        )
        return {
            'reachable': False,
            'verified': False,
            'resolved_ip': pinned_ip,
            'tls_version': None,
            'cipher': None,
            'cert': None,
            'error': str(e)
        }
    finally:
        if tls_sock:
            try:
                tls_sock.close()
            except Exception:
                pass
        elif raw_sock:
            try:
                raw_sock.close()
            except Exception:
                pass


def analyze_tls_certificate(tls_result, domain, now=None):
    """
    Analyzes real TLS handshake results and returns findings for:
    - HTTPS availability
    - TLS certificate validity, expiry, and protocol version
    """
    now_dt = now or utc_now()
    findings = []

    if not tls_result.get('reachable'):
        findings.append({
            'check_key': 'https_availability',
            'title': 'HTTPS Availability',
            'category': 'Transport Security',
            'severity': 'CRITICAL',
            'status': 'FAIL',
            'evidence': (
                f"HTTPS connection to {domain}:443 failed. "
                f"Error: {tls_result.get('error') or 'Connection refused or timed out'}."
            ),
            'remediation': (
                "Enable HTTPS on port 443 using a valid TLS certificate issued by a trusted Certificate Authority (e.g., Let's Encrypt)."
            )
        })
        findings.append({
            'check_key': 'tls_certificate',
            'title': 'TLS Certificate Validity & Expiry',
            'category': 'Transport Security',
            'severity': 'HIGH',
            'status': 'FAIL',
            'evidence': f"Unable to validate TLS certificate because HTTPS handshake failed: {tls_result.get('error')}.",
            'remediation': "Configure TLS 1.2+ with a valid, trusted, unexpired X.509 certificate matching the domain."
        })
        return findings

    # HTTPS is reachable
    findings.append({
        'check_key': 'https_availability',
        'title': 'HTTPS Availability',
        'category': 'Transport Security',
        'severity': 'INFO',
        'status': 'PASS',
        'evidence': (
            f"HTTPS is reachable on {domain}:443 (resolved IP: {tls_result.get('resolved_ip')}, "
            f"protocol: {tls_result.get('tls_version') or 'TLS'})."
        ),
        'remediation': "HTTPS is enabled and reachable. Maintain TLS 1.2/1.3 configuration."
    })

    if not tls_result.get('verified'):
        findings.append({
            'check_key': 'tls_certificate',
            'title': 'TLS Certificate Validity & Expiry',
            'category': 'Transport Security',
            'severity': 'CRITICAL',
            'status': 'FAIL',
            'evidence': f"TLS certificate verification failed for {domain}: {tls_result.get('error')}.",
            'remediation': (
                "Replace the invalid, self-signed, hostname-mismatched, or expired certificate with a valid certificate from a trusted CA."
            )
        })
        return findings

    cert = tls_result.get('cert') or {}
    tls_version = tls_result.get('tls_version') or 'Unknown'
    not_after_raw = cert.get('notAfter')
    not_after_dt = parse_tls_not_after(not_after_raw)
    issuer_tuples = cert.get('issuer', ())
    issuer_str = ', '.join(f"{k}={v}" for rdn in issuer_tuples for (k, v) in rdn) or 'Unknown Issuer'

    # Check weak protocol version
    weak_protocols = {'SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.0', 'TLSv1.1'}
    is_weak_proto = tls_version in weak_protocols

    if not_after_dt:
        days_remaining = (not_after_dt - now_dt).days
        if days_remaining < 0:
            findings.append({
                'check_key': 'tls_certificate',
                'title': 'TLS Certificate Validity & Expiry',
                'category': 'Transport Security',
                'severity': 'CRITICAL',
                'status': 'FAIL',
                'evidence': (
                    f"TLS certificate expired {abs(days_remaining)} day(s) ago (notAfter: {not_after_raw}). "
                    f"Issuer: {issuer_str}. Protocol: {tls_version}."
                ),
                'remediation': "Renew and deploy the TLS certificate immediately and configure automated certificate renewal."
            })
        elif days_remaining <= 30:
            findings.append({
                'check_key': 'tls_certificate',
                'title': 'TLS Certificate Validity & Expiry',
                'category': 'Transport Security',
                'severity': 'MEDIUM',
                'status': 'WARNING',
                'evidence': (
                    f"TLS certificate is valid but expires soon in {days_remaining} day(s) (notAfter: {not_after_raw}). "
                    f"Issuer: {issuer_str}. Protocol: {tls_version}."
                ),
                'remediation': "Renew the TLS certificate before expiration and automate renewal (e.g., ACME / Certbot)."
            })
        elif is_weak_proto:
            findings.append({
                'check_key': 'tls_certificate',
                'title': 'TLS Certificate Validity & Expiry',
                'category': 'Transport Security',
                'severity': 'HIGH',
                'status': 'FAIL',
                'evidence': (
                    f"Deprecated TLS protocol negotiated: {tls_version}. "
                    f"Certificate expires in {days_remaining} day(s) (notAfter: {not_after_raw})."
                ),
                'remediation': "Disable SSLv3, TLS 1.0, and TLS 1.1 on the web server; enforce TLS 1.2 and TLS 1.3 only."
            })
        else:
            findings.append({
                'check_key': 'tls_certificate',
                'title': 'TLS Certificate Validity & Expiry',
                'category': 'Transport Security',
                'severity': 'INFO',
                'status': 'PASS',
                'evidence': (
                    f"Valid TLS certificate verified for {domain}. Expires in {days_remaining} day(s) "
                    f"(notAfter: {not_after_raw}). Protocol: {tls_version}. Cipher: {tls_result.get('cipher')}. "
                    f"Issuer: {issuer_str}."
                ),
                'remediation': "TLS certificate and protocol are healthy. Monitor expiration thresholds."
            })
    else:
        findings.append({
            'check_key': 'tls_certificate',
            'title': 'TLS Certificate Validity & Expiry',
            'category': 'Transport Security',
            'severity': 'LOW',
            'status': 'WARNING',
            'evidence': f"TLS handshake succeeded ({tls_version}), but certificate expiration timestamp could not be parsed.",
            'remediation': "Verify certificate metadata on the server directly."
        })

    return findings


def analyze_https_redirect(http_response, domain):
    """Analyzes whether plain HTTP (port 80) redirects safely to HTTPS."""
    if not http_response:
        return {
            'check_key': 'http_to_https_redirect',
            'title': 'HTTP to HTTPS Redirection',
            'category': 'Transport Security',
            'severity': 'INFO',
            'status': 'PASS',
            'evidence': f"Plain HTTP (port 80) on {domain} did not serve unencrypted content (unreachable or closed).",
            'remediation': "If port 80 is intentionally closed, ensure HSTS is enabled on HTTPS."
        }

    status = http_response.get('status_code')
    location = (http_response.get('headers') or {}).get('location', '')
    if status in (301, 302, 307, 308) and location.lower().startswith('https://'):
        parsed_loc = urllib.parse.urlsplit(location)
        loc_host = (parsed_loc.hostname or '').lower()
        return {
            'check_key': 'http_to_https_redirect',
            'title': 'HTTP to HTTPS Redirection',
            'category': 'Transport Security',
            'severity': 'INFO',
            'status': 'PASS',
            'evidence': (
                f"HTTP request returned {status} redirecting to '{location}' (destination host: {loc_host})."
            ),
            'remediation': "HTTP to HTTPS redirection is properly enforced. Prefer 301 Permanent Redirect combined with HSTS."
        }

    return {
        'check_key': 'http_to_https_redirect',
        'title': 'HTTP to HTTPS Redirection',
        'category': 'Transport Security',
        'severity': 'HIGH',
        'status': 'FAIL',
        'evidence': (
            f"HTTP request to http://{domain} returned HTTP {status} "
            f"(Location: '{location or 'none'}') instead of redirecting to HTTPS."
        ),
        'remediation': (
            "Configure the web server or reverse proxy to redirect all HTTP (port 80) requests "
            "to HTTPS (port 443) using HTTP 301 Permanent Redirect."
        )
    }


def analyze_security_headers(headers, is_https=True):
    """
    Inspects real HTTP response headers for required security headers:
    - Content-Security-Policy
    - Strict-Transport-Security
    - X-Content-Type-Options
    - X-Frame-Options
    - Referrer-Policy
    - Overall HTTP security headers summary
    """
    h = {k.lower(): v for k, v in (headers or {}).items()}
    findings = []

    # 1. Content-Security-Policy (CSP)
    csp = h.get('content-security-policy')
    if not csp:
        findings.append({
            'check_key': 'header_csp',
            'title': 'Content-Security-Policy (CSP)',
            'category': 'HTTP Security Headers',
            'severity': 'HIGH',
            'status': 'FAIL',
            'evidence': "Header 'Content-Security-Policy' is missing from HTTP response.",
            'remediation': (
                "Add a strong Content-Security-Policy header (e.g., \"default-src 'self'; "
                "object-src 'none'; base-uri 'self'; frame-ancestors 'self'\") to mitigate XSS and injection attacks."
            )
        })
    else:
        weak_tokens = []
        csp_lower = csp.lower()
        if "'unsafe-inline'" in csp_lower:
            weak_tokens.append("'unsafe-inline'")
        if "'unsafe-eval'" in csp_lower:
            weak_tokens.append("'unsafe-eval'")
        if re.search(r'(?:default-src|script-src)\s+[^;]*\*', csp_lower):
            weak_tokens.append("wildcard '*'")

        if weak_tokens:
            findings.append({
                'check_key': 'header_csp',
                'title': 'Content-Security-Policy (CSP)',
                'category': 'HTTP Security Headers',
                'severity': 'MEDIUM',
                'status': 'WARNING',
                'evidence': f"Content-Security-Policy is present but uses permissive directive(s) ({', '.join(weak_tokens)}): {csp[:240]}",
                'remediation': (
                    "Tighten CSP by removing 'unsafe-inline', 'unsafe-eval', and wildcard sources; "
                    "adopt cryptographic nonces or hashes for inline scripts."
                )
            })
        else:
            findings.append({
                'check_key': 'header_csp',
                'title': 'Content-Security-Policy (CSP)',
                'category': 'HTTP Security Headers',
                'severity': 'INFO',
                'status': 'PASS',
                'evidence': f"Content-Security-Policy header detected: {csp[:240]}",
                'remediation': "CSP is configured. Periodically audit directives as application assets evolve."
            })

    # 2. Strict-Transport-Security (HSTS)
    hsts = h.get('strict-transport-security')
    if not hsts:
        findings.append({
            'check_key': 'header_hsts',
            'title': 'Strict-Transport-Security (HSTS)',
            'category': 'HTTP Security Headers',
            'severity': 'HIGH' if is_https else 'MEDIUM',
            'status': 'FAIL',
            'evidence': "Header 'Strict-Transport-Security' is missing from HTTPS response.",
            'remediation': (
                "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on all HTTPS responses "
                "to prevent SSL stripping and protocol downgrade attacks."
            )
        })
    else:
        m = re.search(r'max-age\s*=\s*(\d+)', hsts, re.IGNORECASE)
        max_age = int(m.group(1)) if m else 0
        if max_age < 15768000:  # < 6 months
            findings.append({
                'check_key': 'header_hsts',
                'title': 'Strict-Transport-Security (HSTS)',
                'category': 'HTTP Security Headers',
                'severity': 'LOW',
                'status': 'WARNING',
                'evidence': f"HSTS header is present ('{hsts}') but max-age ({max_age}s) is below recommended 15768000s (6 months).",
                'remediation': "Increase HSTS max-age to at least 31536000 (1 year) and consider adding 'includeSubDomains'."
            })
        else:
            findings.append({
                'check_key': 'header_hsts',
                'title': 'Strict-Transport-Security (HSTS)',
                'category': 'HTTP Security Headers',
                'severity': 'INFO',
                'status': 'PASS',
                'evidence': f"Strict-Transport-Security header properly configured: {hsts}",
                'remediation': "HSTS is properly configured."
            })

    # 3. X-Content-Type-Options
    xcto = h.get('x-content-type-options')
    if xcto and xcto.strip().lower() == 'nosniff':
        findings.append({
            'check_key': 'header_x_content_type_options',
            'title': 'X-Content-Type-Options',
            'category': 'HTTP Security Headers',
            'severity': 'INFO',
            'status': 'PASS',
            'evidence': f"X-Content-Type-Options is set to '{xcto}'.",
            'remediation': "MIME-sniffing protection is active."
        })
    else:
        findings.append({
            'check_key': 'header_x_content_type_options',
            'title': 'X-Content-Type-Options',
            'category': 'HTTP Security Headers',
            'severity': 'MEDIUM',
            'status': 'FAIL',
            'evidence': (
                f"Header 'X-Content-Type-Options' is {'missing' if not xcto else f'misconfigured ({xcto})'}."
            ),
            'remediation': "Set 'X-Content-Type-Options: nosniff' on all responses to prevent MIME-type confusion attacks."
        })

    # 4. X-Frame-Options (or CSP frame-ancestors)
    xfo = h.get('x-frame-options')
    has_csp_frame_ancestors = bool(csp and 'frame-ancestors' in csp.lower())
    if xfo and xfo.strip().upper() in ('DENY', 'SAMEORIGIN'):
        findings.append({
            'check_key': 'header_x_frame_options',
            'title': 'X-Frame-Options (Clickjacking Protection)',
            'category': 'HTTP Security Headers',
            'severity': 'INFO',
            'status': 'PASS',
            'evidence': f"X-Frame-Options is set to '{xfo}'.",
            'remediation': "Clickjacking protection is active."
        })
    elif has_csp_frame_ancestors:
        findings.append({
            'check_key': 'header_x_frame_options',
            'title': 'X-Frame-Options (Clickjacking Protection)',
            'category': 'HTTP Security Headers',
            'severity': 'INFO',
            'status': 'PASS',
            'evidence': (
                "X-Frame-Options header is absent, but clickjacking protection is enforced via CSP 'frame-ancestors'."
            ),
            'remediation': "Optionally also include 'X-Frame-Options: SAMEORIGIN' for legacy browser compatibility."
        })
    else:
        findings.append({
            'check_key': 'header_x_frame_options',
            'title': 'X-Frame-Options (Clickjacking Protection)',
            'category': 'HTTP Security Headers',
            'severity': 'MEDIUM',
            'status': 'FAIL',
            'evidence': (
                f"Header 'X-Frame-Options' is {'missing' if not xfo else f'set to weak/unsupported value ({xfo})'} "
                "and no CSP 'frame-ancestors' directive was found."
            ),
            'remediation': (
                "Set 'X-Frame-Options: DENY' (or 'SAMEORIGIN') and add CSP \"frame-ancestors 'self'\" "
                "to prevent clickjacking attacks."
            )
        })

    # 5. Referrer-Policy
    rp = h.get('referrer-policy')
    safe_rp_values = {
        'no-referrer',
        'same-origin',
        'strict-origin',
        'strict-origin-when-cross-origin',
        'origin-when-cross-origin',
        'no-referrer-when-downgrade'
    }
    if not rp:
        findings.append({
            'check_key': 'header_referrer_policy',
            'title': 'Referrer-Policy',
            'category': 'HTTP Security Headers',
            'severity': 'LOW',
            'status': 'FAIL',
            'evidence': "Header 'Referrer-Policy' is missing from HTTP response.",
            'remediation': "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer' to limit URL leakage."
        })
    elif rp.strip().lower() in ('unsafe-url',):
        findings.append({
            'check_key': 'header_referrer_policy',
            'title': 'Referrer-Policy',
            'category': 'HTTP Security Headers',
            'severity': 'MEDIUM',
            'status': 'FAIL',
            'evidence': f"Referrer-Policy is set to insecure value '{rp}', which leaks full URLs across origins and protocols.",
            'remediation': "Change Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'."
        })
    else:
        is_recognized = any(tok.strip().lower() in safe_rp_values for tok in rp.split(','))
        findings.append({
            'check_key': 'header_referrer_policy',
            'title': 'Referrer-Policy',
            'category': 'HTTP Security Headers',
            'severity': 'INFO' if is_recognized else 'LOW',
            'status': 'PASS' if is_recognized else 'WARNING',
            'evidence': f"Referrer-Policy detected: '{rp}'.",
            'remediation': "Referrer-Policy is configured." if is_recognized else "Use a standard policy such as 'strict-origin-when-cross-origin'."
        })

    return findings


def analyze_cookies(set_cookie_headers):
    """Inspects real Set-Cookie headers for Secure, HttpOnly, and SameSite security flags."""
    if not set_cookie_headers:
        return {
            'check_key': 'cookie_security_flags',
            'title': 'Cookie Security Flags (Secure, HttpOnly, SameSite)',
            'category': 'Session & Cookie Security',
            'severity': 'INFO',
            'status': 'PASS',
            'evidence': "No Set-Cookie headers were issued on the assessed endpoint.",
            'remediation': "When setting session cookies, always include 'Secure; HttpOnly; SameSite=Lax' (or Strict)."
        }

    issues = []
    inspected_names = []
    for raw_cookie in set_cookie_headers:
        parts = [p.strip() for p in raw_cookie.split(';') if p.strip()]
        if not parts:
            continue
        cookie_name = parts[0].split('=', 1)[0].strip()
        inspected_names.append(cookie_name)
        attrs_lower = [p.lower() for p in parts[1:]]

        missing = []
        if 'secure' not in attrs_lower:
            missing.append('Secure')
        if 'httponly' not in attrs_lower:
            missing.append('HttpOnly')
        if not any(a.startswith('samesite=') for a in attrs_lower):
            missing.append('SameSite')

        if missing:
            issues.append(f"Cookie '{cookie_name}' missing {', '.join(missing)}")

    if issues:
        has_missing_secure_or_httponly = any(('Secure' in i or 'HttpOnly' in i) for i in issues)
        return {
            'check_key': 'cookie_security_flags',
            'title': 'Cookie Security Flags (Secure, HttpOnly, SameSite)',
            'category': 'Session & Cookie Security',
            'severity': 'HIGH' if has_missing_secure_or_httponly else 'MEDIUM',
            'status': 'FAIL',
            'evidence': f"Inspected {len(inspected_names)} cookie(s). Issues found: {'; '.join(issues)}.",
            'remediation': (
                "Set the 'Secure', 'HttpOnly', and 'SameSite=Lax' (or 'Strict') attributes on all session and sensitive cookies."
            )
        }

    return {
        'check_key': 'cookie_security_flags',
        'title': 'Cookie Security Flags (Secure, HttpOnly, SameSite)',
        'category': 'Session & Cookie Security',
        'severity': 'INFO',
        'status': 'PASS',
        'evidence': (
            f"All {len(inspected_names)} issued cookie(s) ({', '.join(inspected_names)}) "
            "include Secure, HttpOnly, and SameSite flags."
        ),
        'remediation': "Cookie security flags are properly configured."
    }


def analyze_server_exposure(headers):
    """Detects server version and technology stack disclosure in response headers."""
    h = {k.lower(): v for k, v in (headers or {}).items()}
    exposed = []
    version_disclosed = False

    for hdr in ('server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator'):
        val = h.get(hdr)
        if val:
            exposed.append(f"{hdr}: {val}")
            # Check if explicit version numbers (e.g. nginx/1.24.0, PHP/8.2, Apache/2.4.57) are exposed
            if re.search(r'\d+\.\d+', val) or hdr in ('x-powered-by', 'x-aspnet-version'):
                version_disclosed = True

    if version_disclosed:
        return {
            'check_key': 'server_info_exposure',
            'title': 'Server & Technology Information Exposure',
            'category': 'Information Disclosure',
            'severity': 'LOW',
            'status': 'FAIL',
            'evidence': f"Detailed server/framework headers exposed: {'; '.join(exposed)}.",
            'remediation': (
                "Suppress or sanitize 'Server', 'X-Powered-By', and framework version headers "
                "(e.g., 'server_tokens off;' in Nginx or 'ServerTokens Prod' in Apache)."
            )
        }
    if exposed:
        return {
            'check_key': 'server_info_exposure',
            'title': 'Server & Technology Information Exposure',
            'category': 'Information Disclosure',
            'severity': 'INFO',
            'status': 'PASS',
            'evidence': f"Minimal server banner observed without version leakage: {'; '.join(exposed)}.",
            'remediation': "Keep version numbers suppressed in HTTP response headers."
        }

    return {
        'check_key': 'server_info_exposure',
        'title': 'Server & Technology Information Exposure',
        'category': 'Information Disclosure',
        'severity': 'INFO',
        'status': 'PASS',
        'evidence': "No server or framework version headers ('Server', 'X-Powered-By') exposed.",
        'remediation': "Server banner minimization is properly configured."
    }


def analyze_basic_configuration(headers):
    """
    Performs safe, passive basic configuration checks:
    - Permissions-Policy header presence
    - CORS wildcard misconfiguration (Access-Control-Allow-Origin: *)
    """
    h = {k.lower(): v for k, v in (headers or {}).items()}
    findings = []

    # Permissions-Policy
    pp = h.get('permissions-policy') or h.get('feature-policy')
    if pp:
        findings.append({
            'check_key': 'config_permissions_policy',
            'title': 'Permissions-Policy Configuration',
            'category': 'Basic Configuration',
            'severity': 'INFO',
            'status': 'PASS',
            'evidence': f"Permissions-Policy header present: {pp[:200]}",
            'remediation': "Permissions-Policy restricts unnecessary browser APIs."
        })
    else:
        findings.append({
            'check_key': 'config_permissions_policy',
            'title': 'Permissions-Policy Configuration',
            'category': 'Basic Configuration',
            'severity': 'LOW',
            'status': 'WARNING',
            'evidence': "Header 'Permissions-Policy' is not set.",
            'remediation': (
                "Add a 'Permissions-Policy' header (e.g., \"geolocation=(), microphone=(), camera=()\") "
                "to restrict browser feature access."
            )
        })

    # Overly permissive CORS check
    acao = h.get('access-control-allow-origin')
    acac = (h.get('access-control-allow-credentials') or '').lower()
    if acao and acao.strip() == '*':
        sev = 'HIGH' if acac == 'true' else 'LOW'
        findings.append({
            'check_key': 'config_cors_policy',
            'title': 'CORS Policy Configuration',
            'category': 'Basic Configuration',
            'severity': sev,
            'status': 'FAIL' if acac == 'true' else 'WARNING',
            'evidence': (
                f"Access-Control-Allow-Origin is set to wildcard '*' "
                f"(Access-Control-Allow-Credentials: {acac or 'not set'})."
            ),
            'remediation': (
                "Avoid wildcard CORS ('*') on authenticated or sensitive endpoints; "
                "explicitly allowlist trusted origins."
            )
        })
    else:
        findings.append({
            'check_key': 'config_cors_policy',
            'title': 'CORS Policy Configuration',
            'category': 'Basic Configuration',
            'severity': 'INFO',
            'status': 'PASS',
            'evidence': (
                f"No wildcard CORS misconfiguration detected (Access-Control-Allow-Origin: {acao or 'not set'})."
            ),
            'remediation': "CORS origin policy does not expose wildcard cross-origin access."
        })

    return findings


def verify_target_ownership(target, provided_token=None, attestation_note=None, actor='owner'):
    """
    Executes the website-owner authorization verification workflow.
    Supports:
      - 'signed_attestation': confirms cryptographic verification_token supplied by owner + consent.
      - 'http_file': safely fetches https://<domain>/.well-known/cyberfortify-verify.txt and matches token.
      - 'meta_tag': safely fetches target URL and checks <meta name="cyberfortify-verification" content="<token>">.
      - 'dns_txt': validates matching token proof (or supplied token attestation if offline).
    """
    expected_token = target['verification_token']
    method = target['verification_method']
    domain = target['domain']

    if not target['owner_consent']:
        return None, "Explicit website-owner authorization consent is required."

    # Direct cryptographic token proof verification (for signed_attestation or admin/owner proof submission)
    if method == 'signed_attestation' or (provided_token and provided_token.strip() == expected_token):
        if not provided_token or provided_token.strip() != expected_token:
            log_live_audit(
                action='VERIFICATION_FAILED',
                outcome='FAILED',
                target_uuid=target['target_uuid'],
                domain=domain,
                reason="Provided verification token did not match expected target verification token.",
                actor=actor
            )
            return None, "Verification failed: provided token does not match the target's verification token."

        if method == 'signed_attestation':
            default_note = (
                "Signed authorization self-attestation recorded with matching token "
                "(does not claim independent DNS/HTTP domain ownership verification; requires administrator approval)."
            )
        else:
            default_note = f"Authorization token confirmed via {method}."
        note = attestation_note or default_note
        return mark_target_verified(target['target_uuid'], verification_notes=note, actor=actor)

    # Live HTTP verification file check (.well-known/cyberfortify-verify.txt)
    if method == 'http_file':
        verify_url = f"https://{domain}/.well-known/cyberfortify-verify.txt"
        try:
            resp = safe_http_request(
                url=verify_url,
                target=target,
                method='GET',
                follow_redirects=False,
                skip_path_check=True
            )
            body_text = resp['body'].decode('utf-8', errors='ignore')
            if resp['status_code'] == 200 and expected_token in body_text:
                return mark_target_verified(
                    target['target_uuid'],
                    verification_notes=f"Verified token at {verify_url} (HTTP 200, IP {resp['resolved_ip']}).",
                    actor=actor
                )
            return None, (
                f"Verification token not found at {verify_url} (HTTP {resp['status_code']}). "
                f"Ensure the file contains '{expected_token}'."
            )
        except LiveSecurityError as e:
            return None, f"Verification blocked by target security policy: {e.message}"
        except Exception as e:
            return None, f"Could not reach {verify_url} for ownership verification: {str(e)}"

    # Live HTML meta tag check
    if method == 'meta_tag':
        verify_url = f"https://{domain}/"
        try:
            resp = safe_http_request(
                url=verify_url,
                target=target,
                method='GET',
                follow_redirects=True,
                skip_path_check=True
            )
            body_text = resp['body'].decode('utf-8', errors='ignore')
            if resp['status_code'] == 200 and expected_token in body_text:
                return mark_target_verified(
                    target['target_uuid'],
                    verification_notes=f"Verified meta tag token at {verify_url} (IP {resp['resolved_ip']}).",
                    actor=actor
                )
            return None, (
                f"Verification meta tag not found at {verify_url}. "
                f"Add <meta name=\"cyberfortify-verification\" content=\"{expected_token}\"> to the page head."
            )
        except LiveSecurityError as e:
            return None, f"Verification blocked by target security policy: {e.message}"
        except Exception as e:
            return None, f"Could not reach {verify_url} for meta tag verification: {str(e)}"

    return None, (
        f"Verification requires either hosting token '{expected_token}' via {method} "
        "or submitting the matching verification token for attestation."
    )


def run_live_assessment(target_uuid, path=None):
    """
    Executes a safe, non-invasive live website security assessment on an APPROVED target.
    Strictly enforces authorization, expiry, SSRF/DNS-rebinding protection, approved paths/methods,
    rate limiting, and audit logging. Uses real HTTP/TLS responses only.
    """
    # 1. Strict Authorization & Expiry Enforcement
    is_auth, err_code, err_msg, target = check_target_authorization(target_uuid)
    if not is_auth:
        log_live_audit(
            action='LIVE_SCAN_REJECTED',
            outcome='BLOCKED',
            target_uuid=target_uuid,
            domain=target['domain'] if target else None,
            url=target['target_url'] if target else None,
            reason=f"[{err_code}] {err_msg}"
        )
        raise LiveSecurityError(err_msg, error_code=err_code, status_code=403)

    domain = target['domain']
    parsed_target = urllib.parse.urlsplit(target['target_url'])
    scan_path = path or parsed_target.path or (target['approved_paths'][0] if target['approved_paths'] else '/')
    if not scan_path.startswith('/'):
        scan_path = '/' + scan_path

    # Pre-validate path against approved_paths before creating assessment record
    from app.live_testing.security import is_path_approved
    if not is_path_approved(scan_path, target['approved_paths']):
        msg = f"Requested scan path '{scan_path}' is not in approved paths {target['approved_paths']}."
        log_live_audit(
            action='UNAPPROVED_PATH_BLOCKED',
            outcome='BLOCKED',
            target_uuid=target_uuid,
            domain=domain,
            url=f"https://{domain}{scan_path}",
            reason=msg
        )
        raise ScopeViolationError(msg, error_code='UNAPPROVED_PATH')

    assessment_uuid = create_live_assessment_record(
        target_uuid=target_uuid,
        target_url=f"https://{domain}{scan_path}",
        domain=domain
    )

    findings = []
    metadata = {
        'domain': domain,
        'scan_path': scan_path,
        'resolved_ip': None,
        'tls_version': None,
        'https_status_code': None,
        'http_status_code': None,
        'redirect_chain': [],
        'observed_headers': {}
    }

    try:
        # Step 1: TLS Certificate & HTTPS Availability Inspection
        update_live_assessment_progress(assessment_uuid, 20, 'Inspecting HTTPS availability and TLS certificate')
        tls_res = inspect_tls_certificate(
            domain=domain,
            target_uuid=target_uuid,
            max_request_rate=target['max_request_rate']
        )
        metadata['resolved_ip'] = tls_res.get('resolved_ip')
        metadata['tls_version'] = tls_res.get('tls_version')
        findings.extend(analyze_tls_certificate(tls_res, domain))

        # Step 2: HTTP to HTTPS Redirection Check (non-following single probe)
        update_live_assessment_progress(assessment_uuid, 45, 'Checking HTTP to HTTPS redirection')
        http_url = f"http://{domain}{scan_path}"
        http_resp = None
        try:
            http_resp = safe_http_request(
                url=http_url,
                target=target,
                method='GET' if 'GET' in target['allowed_methods'] else target['allowed_methods'][0],
                follow_redirects=False
            )
            metadata['http_status_code'] = http_resp.get('status_code')
        except (LiveSecurityError,):
            raise
        except Exception:
            http_resp = None

        findings.append(analyze_https_redirect(http_resp, domain))

        # Step 3: Live HTTPS Response Inspection (Headers, Cookies, Server Exposure, Config)
        update_live_assessment_progress(assessment_uuid, 70, 'Analyzing HTTP security headers, cookies, and configuration')
        primary_resp = None
        used_https = False
        preferred_method = 'GET' if 'GET' in target['allowed_methods'] else target['allowed_methods'][0]

        if tls_res.get('reachable') and tls_res.get('verified'):
            https_url = f"https://{domain}{scan_path}"
            try:
                primary_resp = safe_http_request(
                    url=https_url,
                    target=target,
                    method=preferred_method,
                    follow_redirects=True
                )
                used_https = True
                metadata['https_status_code'] = primary_resp.get('status_code')
                metadata['redirect_chain'] = primary_resp.get('redirect_chain', [])
                metadata['resolved_ip'] = primary_resp.get('resolved_ip')
            except (LiveSecurityError,):
                raise
            except Exception as e:
                metadata['https_fetch_error'] = str(e)

        # Fallback to HTTP response headers ONLY if HTTPS was unavailable and HTTP responded
        if primary_resp is None and http_resp is not None:
            primary_resp = http_resp
            used_https = False

        if primary_resp is not None:
            resp_headers = primary_resp.get('headers') or {}
            metadata['observed_headers'] = resp_headers
            findings.extend(analyze_security_headers(resp_headers, is_https=used_https))
            findings.append(analyze_cookies(primary_resp.get('set_cookies') or []))
            findings.append(analyze_server_exposure(resp_headers))
            findings.extend(analyze_basic_configuration(resp_headers))
        else:
            findings.append({
                'check_key': 'http_response_unavailable',
                'title': 'HTTP/HTTPS Response Inspection',
                'category': 'HTTP Security Headers',
                'severity': 'HIGH',
                'status': 'FAIL',
                'evidence': f"Could not retrieve a verified HTTP/HTTPS response from {domain}{scan_path}.",
                'remediation': "Verify that the authorized target is online and serving valid HTTPS responses."
            })

        update_live_assessment_progress(assessment_uuid, 95, 'Computing security score and saving report')
        record = finalize_live_assessment(
            assessment_uuid=assessment_uuid,
            findings=findings,
            metadata=metadata,
            status='COMPLETED'
        )
        from app.live_testing.remediation import sync_remediations_from_assessment
        sync_remediations_from_assessment(record)
        return record

    except LiveSecurityError as e:
        finalize_live_assessment(
            assessment_uuid=assessment_uuid,
            findings=findings,
            metadata=metadata,
            status='BLOCKED',
            error_message=e.message
        )
        raise
    except Exception as e:
        finalize_live_assessment(
            assessment_uuid=assessment_uuid,
            findings=findings,
            metadata=metadata,
            status='FAILED',
            error_message=str(e)
        )
        raise
