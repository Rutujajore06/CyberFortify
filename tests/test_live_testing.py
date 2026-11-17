import unittest
import json
import datetime
import socket
import sqlite3
from unittest.mock import patch, MagicMock

from app import create_app
from app.database import get_db_connection
from app.models.live_target_model import (
    get_live_target_by_uuid,
    get_live_audit_logs,
    utc_now
)
from app.live_testing.security import (
    is_ip_blocked,
    validate_registration_url,
    resolve_and_validate_host,
    safe_http_request,
    rate_limiter,
    SSRFBlockedError,
    ScopeViolationError,
    RateLimitExceededError
)
from app.live_testing.scanner import (
    analyze_tls_certificate,
    analyze_security_headers,
    analyze_cookies,
    analyze_server_exposure,
    analyze_https_redirect,
    analyze_basic_configuration
)


class _FakeHTTPResponse:
    def __init__(self, status=200, headers=None, body=b''):
        self.status = status
        self._headers = headers or []
        self._body = body

    def getheaders(self):
        return list(self._headers)

    def read(self, n=-1):
        return self._body if n < 0 else self._body[:n]


class TestLiveAuthorizedWebsiteTesting(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        rate_limiter.reset()

    def _register_payload(self, **overrides):
        now = utc_now()
        payload = {
            'target_url': 'https://authorized-example.org/',
            'owner_name': 'Alice Security',
            'owner_email': 'alice@authorized-example.org',
            'owner_consent': True,
            'verification_method': 'signed_attestation',
            'approved_paths': ['/', '/docs/*'],
            'allowed_methods': ['GET', 'HEAD'],
            'start_date': (now - datetime.timedelta(minutes=5)).isoformat(),
            'expiry_date': (now + datetime.timedelta(days=3)).isoformat(),
            'max_request_rate': 10
        }
        payload.update(overrides)
        return payload

    def _register_verify_approve(self, **overrides):
        res = self.client.post('/api/live/targets', json=self._register_payload(**overrides))
        self.assertEqual(res.status_code, 201, res.data)
        target = res.json['target']

        vres = self.client.post(
            f"/api/live/targets/{target['target_uuid']}/verify",
            json={'verification_token': target['verification_token']}
        )
        self.assertEqual(vres.status_code, 200, vres.data)

        ares = self.client.post(
            f"/api/live/targets/{target['target_uuid']}/approve",
            json={'approved_by': 'security-admin'}
        )
        self.assertEqual(ares.status_code, 200, ares.data)
        return ares.json['target']

    # ------------------------------------------------------------------
    # 1. Authorization Verification & Approval Workflow Tests
    # ------------------------------------------------------------------
    def test_01_authorization_verification_workflow_and_pre_approval_blocking(self):
        """Tests explicit owner consent, token verification, admin approval, and blocking before approval."""
        # Reject registration without explicit owner consent
        no_consent = self.client.post('/api/live/targets', json=self._register_payload(owner_consent=False))
        self.assertEqual(no_consent.status_code, 400)
        self.assertEqual(no_consent.json['error_type'], 'AUTHORIZATION_REQUIRED')

        # Register valid target -> PENDING_VERIFICATION
        reg = self.client.post('/api/live/targets', json=self._register_payload())
        self.assertEqual(reg.status_code, 201)
        target = reg.json['target']
        uuid = target['target_uuid']
        self.assertEqual(target['auth_status'], 'PENDING_VERIFICATION')
        self.assertFalse(target['is_verified'])
        self.assertFalse(target['is_scannable'])
        self.assertTrue(target['verification_token'].startswith('cyberfortify-verify='))

        # Cannot approve before ownership verification
        early_approve = self.client.post(f'/api/live/targets/{uuid}/approve', json={'approved_by': 'admin'})
        self.assertEqual(early_approve.status_code, 400)

        # Cannot scan before verification/approval
        early_scan = self.client.post('/api/live/assessments/run', json={'target_uuid': uuid})
        self.assertEqual(early_scan.status_code, 403)
        self.assertEqual(early_scan.json['error_type'], 'NOT_VERIFIED')

        # Wrong verification token fails
        bad_verify = self.client.post(f'/api/live/targets/{uuid}/verify', json={'verification_token': 'wrong-token'})
        self.assertEqual(bad_verify.status_code, 400)

        # Correct verification token succeeds -> PENDING_APPROVAL
        good_verify = self.client.post(
            f'/api/live/targets/{uuid}/verify',
            json={'verification_token': target['verification_token']}
        )
        self.assertEqual(good_verify.status_code, 200)
        self.assertEqual(good_verify.json['target']['auth_status'], 'PENDING_APPROVAL')
        self.assertTrue(good_verify.json['target']['is_verified'])

        # Still cannot scan before admin approval
        unapproved_scan = self.client.post('/api/live/assessments/run', json={'target_uuid': uuid})
        self.assertEqual(unapproved_scan.status_code, 403)
        self.assertEqual(unapproved_scan.json['error_type'], 'NOT_APPROVED')

        # Admin approves -> APPROVED and scannable
        approve = self.client.post(f'/api/live/targets/{uuid}/approve', json={'approved_by': 'lead-admin'})
        self.assertEqual(approve.status_code, 200)
        approved_target = approve.json['target']
        self.assertEqual(approved_target['auth_status'], 'APPROVED')
        self.assertTrue(approved_target['is_scannable'])

        # Admin rejection blocks scanning
        reject = self.client.post(f'/api/live/targets/{uuid}/reject', json={'reason': 'Scope revoked'})
        self.assertEqual(reject.status_code, 200)
        self.assertEqual(reject.json['target']['auth_status'], 'REJECTED')
        rejected_scan = self.client.post('/api/live/assessments/run', json={'target_uuid': uuid})
        self.assertEqual(rejected_scan.status_code, 403)

    def test_02_expired_authorization_auto_expires_and_blocks_scanning(self):
        """Tests automatic expiration when validity window ends and not-yet-active window enforcement."""
        target = self._register_verify_approve(target_url='https://expiring-example.org/')
        uuid = target['target_uuid']

        # Force expiry_date into the past in SQLite to simulate validity end
        past_iso = (utc_now() - datetime.timedelta(minutes=2)).isoformat()
        conn = get_db_connection()
        conn.execute('UPDATE live_targets SET expiry_date = ? WHERE target_uuid = ?', (past_iso, uuid))
        conn.commit()
        conn.close()

        # Fetching target automatically transitions it to EXPIRED
        refreshed = get_live_target_by_uuid(uuid)
        self.assertEqual(refreshed['auth_status'], 'EXPIRED')
        self.assertTrue(refreshed['is_expired'])
        self.assertFalse(refreshed['is_scannable'])

        # Scanning expired target is strictly rejected
        scan_res = self.client.post('/api/live/assessments/run', json={'target_uuid': uuid})
        self.assertEqual(scan_res.status_code, 403)
        self.assertEqual(scan_res.json['error_type'], 'AUTHORIZATION_EXPIRED')

        # Not-yet-active target (start_date in the future) is blocked
        future_start = (utc_now() + datetime.timedelta(hours=2)).isoformat()
        future_expiry = (utc_now() + datetime.timedelta(days=2)).isoformat()
        future_target = self._register_verify_approve(
            target_url='https://future-window.org/',
            start_date=future_start,
            expiry_date=future_expiry
        )
        future_scan = self.client.post('/api/live/assessments/run', json={'target_uuid': future_target['target_uuid']})
        self.assertEqual(future_scan.status_code, 403)
        self.assertEqual(future_scan.json['error_type'], 'NOT_YET_ACTIVE')

    # ------------------------------------------------------------------
    # 2. Private IP Blocking, SSRF Prevention & DNS Rebinding Tests
    # ------------------------------------------------------------------
    def test_03_private_ip_and_localhost_blocking(self):
        """Tests strict blocking of localhost, private, link-local, metadata, IPv6, and obfuscated IPs."""
        blocked_ips = [
            '127.0.0.1',
            '127.0.1.1',
            '10.0.0.1',
            '10.255.255.254',
            '172.16.0.1',
            '172.31.255.254',
            '192.168.0.1',
            '192.168.1.100',
            '169.254.169.254',       # AWS/GCP/Azure Cloud Metadata
            '100.64.0.1',            # CGNAT
            '0.0.0.0',
            '224.0.0.1',             # Multicast
            '::1',                   # IPv6 loopback
            'fc00::1',               # IPv6 unique local
            'fd12:3456:789a::1',     # IPv6 unique local
            'fe80::1',               # IPv6 link-local
            '::ffff:127.0.0.1',      # IPv4-mapped IPv6 loopback
            '::ffff:169.254.169.254',# IPv4-mapped IPv6 metadata
            '64:ff9b::7f00:1',       # NAT64-wrapped 127.0.0.1
            '64:ff9b::a9fe:a9fe',    # NAT64-wrapped 169.254.169.254
            '64:ff9b::a00:1'         # NAT64-wrapped 10.0.0.1
        ]
        for ip in blocked_ips:
            with self.subTest(ip=ip):
                blocked, reason = is_ip_blocked(ip)
                self.assertTrue(blocked, f"Expected {ip} to be blocked")
                self.assertIsNotNone(reason)

        # Public IPs (including NAT64-wrapped public IPv4) should be allowed
        for pub_ip in ['93.184.216.34', '1.1.1.1', '8.8.8.8', '2606:2800:220:1:248:1893:25c8:1946', '64:ff9b::d8c6:4f03']:
            with self.subTest(public_ip=pub_ip):
                blocked, _ = is_ip_blocked(pub_ip)
                self.assertFalse(blocked, f"Expected public IP {pub_ip} to be allowed")

        # URLs targeting localhost, private IPs, obfuscated IPs, internal domains must be rejected
        bad_urls = [
            'http://localhost/',
            'https://sub.localhost/',
            'http://127.0.0.1/',
            'http://192.168.1.1/',
            'http://10.0.0.5/',
            'http://169.254.169.254/latest/meta-data/',
            'http://[::1]/',
            'http://2130706433/',          # decimal 127.0.0.1
            'http://0x7f000001/',          # hex 127.0.0.1
            'http://0177.0.0.1/',          # octal 127.0.0.1
            'https://service.internal/',
            'https://printer.local/',
            'file:///etc/passwd',
            'ftp://example.com/',
            'gopher://example.com/',
            'javascript:alert(1)',
            'https://user:pass@example.com/',
            'https://example.com:8443/',
            'http://example.com:8080/',
            'https://example.com:22/',
            'https://example.com/../../etc/passwd',
        ]
        for u in bad_urls:
            with self.subTest(url=u):
                ok, err, _ = validate_registration_url(u)
                self.assertFalse(ok, f"Expected URL '{u}' to be rejected")
                self.assertIsNotNone(err)

    def test_04_ssrf_dns_resolution_and_dns_rebinding_prevention(self):
        """Tests DNS resolution validation blocking private IPs and IP-pinned connections preventing DNS rebinding."""
        # DNS returning loopback IP must raise SSRFBlockedError
        with patch('socket.getaddrinfo', return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))]):
            with self.assertRaises(SSRFBlockedError) as ctx:
                resolve_and_validate_host('rebind-attacker.example.com', 443)
            self.assertEqual(ctx.exception.error_code, 'PRIVATE_IP_BLOCKED')

        # DNS returning a mix of public + private IP must STILL be blocked
        mixed_dns = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('169.254.169.254', 443)),
        ]
        with patch('socket.getaddrinfo', return_value=mixed_dns):
            with self.assertRaises(SSRFBlockedError):
                resolve_and_validate_host('dual-record.example.com', 443)

        # Verify DNS rebinding protection: PinnedHTTPSConnection receives exact validated IP
        target = self._register_verify_approve(target_url='https://pinned-example.org/')
        captured_ips = []
        captured_headers = []

        class MockPinnedHTTPS:
            def __init__(self, host, port, pinned_ip, timeout=5.0, context=None):
                captured_ips.append(pinned_ip)
                self.host = host
                self.tls_version = 'TLSv1.3'
                self.tls_cipher = ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
                self.peer_cert = {}

            def request(self, method, path, headers=None):
                captured_headers.append(headers or {})

            def getresponse(self):
                return _FakeHTTPResponse(200, [('X-Content-Type-Options', 'nosniff')], b'ok')

            def close(self):
                pass

        with patch('socket.getaddrinfo', return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443))]) as mock_dns, \
             patch('app.live_testing.security.PinnedHTTPSConnection', MockPinnedHTTPS):
            resp = safe_http_request(
                'https://pinned-example.org/',
                target=target,
                method='GET',
                headers={'Cookie': 'session=secret', 'Authorization': 'Bearer topsecret', 'X-Safe': '1'}
            )
            self.assertEqual(resp['resolved_ip'], '93.184.216.34')
            self.assertEqual(captured_ips, ['93.184.216.34'])
            # DNS resolved only once for this request (pinned directly into connection)
            self.assertEqual(mock_dns.call_count, 1)
            # Sensitive headers stripped
            sent_keys = {k.lower() for k in captured_headers[0].keys()}
            self.assertNotIn('cookie', sent_keys)
            self.assertNotIn('authorization', sent_keys)

    # ------------------------------------------------------------------
    # 3. Unauthorized Domain, Path, Method & Redirect Validation Tests
    # ------------------------------------------------------------------
    def test_05_unauthorized_domain_path_and_method_rejection(self):
        """Tests strict enforcement of approved domain, approved paths, and safe allowed methods."""
        target = self._register_verify_approve(
            target_url='https://scoped-example.org/',
            approved_paths=['/', '/docs/*'],
            allowed_methods=['GET']
        )

        # Unauthorized domain rejected
        with self.assertRaises(ScopeViolationError) as ctx1:
            safe_http_request('https://other-domain.org/', target=target, method='GET')
        self.assertEqual(ctx1.exception.error_code, 'UNAUTHORIZED_DOMAIN')

        # Unapproved path rejected
        with self.assertRaises(ScopeViolationError) as ctx2:
            safe_http_request('https://scoped-example.org/admin/panel', target=target, method='GET')
        self.assertEqual(ctx2.exception.error_code, 'UNAPPROVED_PATH')

        # Disallowed HTTP method (POST / HEAD not in target allowed_methods) rejected
        with self.assertRaises(ScopeViolationError) as ctx3:
            safe_http_request('https://scoped-example.org/', target=target, method='POST')
        self.assertEqual(ctx3.exception.error_code, 'METHOD_NOT_ALLOWED')

        with self.assertRaises(ScopeViolationError) as ctx4:
            safe_http_request('https://scoped-example.org/', target=target, method='HEAD')
        self.assertEqual(ctx4.exception.error_code, 'METHOD_NOT_ALLOWED')

        # Registration with destructive methods (POST/DELETE) rejected
        bad_method_reg = self.client.post(
            '/api/live/targets',
            json=self._register_payload(allowed_methods=['GET', 'POST', 'DELETE'])
        )
        self.assertEqual(bad_method_reg.status_code, 400)

    def test_06_redirect_validation_blocks_ssrf_and_unapproved_domains(self):
        """Tests every redirect hop is strictly revalidated against SSRF, private IP, scheme, port, and approved domain."""
        target = self._register_verify_approve(
            target_url='https://redirect-test.org/',
            approved_paths=['/', '/docs/*'],
            allowed_methods=['GET']
        )

        def make_redirect_conn(location_value):
            class RedirectConn:
                def __init__(self, host, port, pinned_ip, timeout=5.0, context=None):
                    self.tls_version = 'TLSv1.3'
                    self.tls_cipher = None
                    self.peer_cert = {}
                def request(self, method, path, headers=None):
                    pass
                def getresponse(self):
                    return _FakeHTTPResponse(302, [('Location', location_value)], b'')
                def close(self):
                    pass
            return RedirectConn

        pub_dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443))]

        # 1. Redirect to AWS metadata private IP -> blocked
        with patch('socket.getaddrinfo', return_value=pub_dns), \
             patch('app.live_testing.security.PinnedHTTPSConnection', make_redirect_conn('http://169.254.169.254/latest/meta-data/')):
            with self.assertRaises(SSRFBlockedError):
                safe_http_request('https://redirect-test.org/', target=target, method='GET', follow_redirects=True)

        # 2. Redirect to unapproved external domain -> blocked
        with patch('socket.getaddrinfo', return_value=pub_dns), \
             patch('app.live_testing.security.PinnedHTTPSConnection', make_redirect_conn('https://unapproved-other.com/')):
            with self.assertRaises(ScopeViolationError) as ctx:
                safe_http_request('https://redirect-test.org/', target=target, method='GET', follow_redirects=True)
            self.assertEqual(ctx.exception.error_code, 'UNAUTHORIZED_DOMAIN')

        # 3. Redirect to file:// scheme -> blocked
        with patch('socket.getaddrinfo', return_value=pub_dns), \
             patch('app.live_testing.security.PinnedHTTPSConnection', make_redirect_conn('file:///etc/passwd')):
            with self.assertRaises(SSRFBlockedError):
                safe_http_request('https://redirect-test.org/', target=target, method='GET', follow_redirects=True)

        # 4. Valid same-domain redirect from HTTP -> HTTPS -> succeeds and records redirect_chain
        class Hop1HTTP:
            def __init__(self, host, port, pinned_ip, timeout=5.0):
                pass
            def request(self, method, path, headers=None):
                pass
            def getresponse(self):
                return _FakeHTTPResponse(301, [('Location', 'https://redirect-test.org/docs/guide')], b'')
            def close(self):
                pass

        class Hop2HTTPS:
            def __init__(self, host, port, pinned_ip, timeout=5.0, context=None):
                self.tls_version = 'TLSv1.3'
                self.tls_cipher = None
                self.peer_cert = {}
            def request(self, method, path, headers=None):
                pass
            def getresponse(self):
                return _FakeHTTPResponse(200, [('X-Content-Type-Options', 'nosniff')], b'welcome')
            def close(self):
                pass

        with patch('socket.getaddrinfo', return_value=pub_dns), \
             patch('app.live_testing.security.PinnedHTTPConnection', Hop1HTTP), \
             patch('app.live_testing.security.PinnedHTTPSConnection', Hop2HTTPS):
            resp = safe_http_request('http://redirect-test.org/', target=target, method='GET', follow_redirects=True)
            self.assertEqual(resp['status_code'], 200)
            self.assertEqual(resp['final_url'], 'https://redirect-test.org/docs/guide')
            self.assertEqual(len(resp['redirect_chain']), 1)

    # ------------------------------------------------------------------
    # 4. Rate Limiting Tests
    # ------------------------------------------------------------------
    def test_07_rate_limiting_enforcement(self):
        """Tests per-target sliding-window rate limiter blocks excess requests and logs audit event."""
        target_uuid = 'target-ratelimit-test'
        rate_limiter.reset(target_uuid)

        # Allow exactly 3 requests
        for _ in range(3):
            rate_limiter.acquire(target_uuid, max_per_minute=3, domain='ratelimit.example.org')

        # 4th request must raise RateLimitExceededError (429)
        with self.assertRaises(RateLimitExceededError) as ctx:
            rate_limiter.acquire(target_uuid, max_per_minute=3, domain='ratelimit.example.org')
        self.assertEqual(ctx.exception.status_code, 429)
        self.assertEqual(ctx.exception.error_code, 'RATE_LIMIT_EXCEEDED')

        # Audit log recorded the rate limit block
        logs = get_live_audit_logs(limit=10, target_uuid=target_uuid, outcome='BLOCKED')
        self.assertTrue(any(l['action'] == 'RATE_LIMIT_BLOCKED' for l in logs))

    # ------------------------------------------------------------------
    # 5. Security Header, Cookie, Redirect & Server Exposure Detection
    # ------------------------------------------------------------------
    def test_08_security_header_cookie_and_config_detection(self):
        """Tests accurate detection of missing vs hardened security headers, cookies, server info, and redirects."""
        # Case A: Missing / weak headers
        weak_headers = {
            'server': 'nginx/1.18.0',
            'x-powered-by': 'PHP/8.1.2',
            'referrer-policy': 'unsafe-url',
            'access-control-allow-origin': '*',
            'access-control-allow-credentials': 'true'
        }
        header_findings = {f['check_key']: f for f in analyze_security_headers(weak_headers, is_https=True)}
        self.assertEqual(header_findings['header_csp']['status'], 'FAIL')
        self.assertEqual(header_findings['header_hsts']['status'], 'FAIL')
        self.assertEqual(header_findings['header_x_content_type_options']['status'], 'FAIL')
        self.assertEqual(header_findings['header_x_frame_options']['status'], 'FAIL')
        self.assertEqual(header_findings['header_referrer_policy']['status'], 'FAIL')

        server_finding = analyze_server_exposure(weak_headers)
        self.assertEqual(server_finding['status'], 'FAIL')
        self.assertIn('nginx/1.18.0', server_finding['evidence'])

        cookie_finding = analyze_cookies(['sessionid=abc123; Path=/'])
        self.assertEqual(cookie_finding['status'], 'FAIL')
        self.assertEqual(cookie_finding['severity'], 'HIGH')
        self.assertIn('Secure', cookie_finding['evidence'])
        self.assertIn('HttpOnly', cookie_finding['evidence'])
        self.assertIn('SameSite', cookie_finding['evidence'])

        config_findings = {f['check_key']: f for f in analyze_basic_configuration(weak_headers)}
        self.assertEqual(config_findings['config_cors_policy']['status'], 'FAIL')
        self.assertEqual(config_findings['config_cors_policy']['severity'], 'HIGH')

        # Case B: Hardened headers & secure cookies
        strong_headers = {
            'content-security-policy': "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
            'strict-transport-security': 'max-age=31536000; includeSubDomains',
            'x-content-type-options': 'nosniff',
            'x-frame-options': 'DENY',
            'referrer-policy': 'strict-origin-when-cross-origin',
            'permissions-policy': 'geolocation=(), microphone=()'
        }
        strong_findings = {f['check_key']: f for f in analyze_security_headers(strong_headers, is_https=True)}
        for key in ('header_csp', 'header_hsts', 'header_x_content_type_options', 'header_x_frame_options', 'header_referrer_policy'):
            self.assertEqual(strong_findings[key]['status'], 'PASS', f"Expected {key} to PASS")

        self.assertEqual(analyze_server_exposure(strong_headers)['status'], 'PASS')
        self.assertEqual(
            analyze_cookies(['sessionid=abc123; Secure; HttpOnly; SameSite=Strict'])['status'],
            'PASS'
        )

        # HTTP -> HTTPS redirection check
        self.assertEqual(
            analyze_https_redirect({'status_code': 301, 'headers': {'location': 'https://example.org/'}}, 'example.org')['status'],
            'PASS'
        )
        self.assertEqual(
            analyze_https_redirect({'status_code': 200, 'headers': {}}, 'example.org')['status'],
            'FAIL'
        )

    # ------------------------------------------------------------------
    # 6. TLS Validation Tests
    # ------------------------------------------------------------------
    def test_09_tls_certificate_validation(self):
        """Tests TLS validation for valid, expiring-soon, expired, weak-protocol, and invalid certificates."""
        now = datetime.datetime(2026, 11, 17, 12, 0, 0, tzinfo=datetime.timezone.utc)

        # 1. Valid cert expiring in 90 days on TLSv1.3
        valid_res = {
            'reachable': True,
            'verified': True,
            'resolved_ip': '93.184.216.34',
            'tls_version': 'TLSv1.3',
            'cipher': 'TLS_AES_256_GCM_SHA384',
            'cert': {
                'notAfter': 'Feb 15 12:00:00 2027 GMT',
                'issuer': ((('organizationName', 'Trusted CA'),),)
            }
        }
        f_valid = {f['check_key']: f for f in analyze_tls_certificate(valid_res, 'example.org', now=now)}
        self.assertEqual(f_valid['https_availability']['status'], 'PASS')
        self.assertEqual(f_valid['tls_certificate']['status'], 'PASS')

        # 2. Expiring soon (10 days)
        soon_res = dict(valid_res, cert={'notAfter': 'Nov 27 12:00:00 2026 GMT', 'issuer': ()})
        f_soon = {f['check_key']: f for f in analyze_tls_certificate(soon_res, 'example.org', now=now)}
        self.assertEqual(f_soon['tls_certificate']['status'], 'WARNING')

        # 3. Expired certificate
        expired_res = dict(valid_res, cert={'notAfter': 'Nov 01 12:00:00 2026 GMT', 'issuer': ()})
        f_exp = {f['check_key']: f for f in analyze_tls_certificate(expired_res, 'example.org', now=now)}
        self.assertEqual(f_exp['tls_certificate']['status'], 'FAIL')
        self.assertEqual(f_exp['tls_certificate']['severity'], 'CRITICAL')

        # 4. Weak TLS protocol (TLSv1.0)
        weak_proto = dict(valid_res, tls_version='TLSv1.0')
        f_weak = {f['check_key']: f for f in analyze_tls_certificate(weak_proto, 'example.org', now=now)}
        self.assertEqual(f_weak['tls_certificate']['status'], 'FAIL')
        self.assertEqual(f_weak['tls_certificate']['severity'], 'HIGH')

        # 5. Certificate verification error (self-signed / mismatch)
        unverified = {'reachable': True, 'verified': False, 'resolved_ip': '93.184.216.34', 'error': 'CERTIFICATE_VERIFY_FAILED'}
        f_unver = {f['check_key']: f for f in analyze_tls_certificate(unverified, 'example.org', now=now)}
        self.assertEqual(f_unver['tls_certificate']['status'], 'FAIL')
        self.assertEqual(f_unver['tls_certificate']['severity'], 'CRITICAL')

    # ------------------------------------------------------------------
    # 7. End-to-End Approved Live Assessment & UI Rendering Tests
    # ------------------------------------------------------------------
    def test_10_end_to_end_live_assessment_and_ui_routes(self):
        """Tests full live assessment API flow with mocked HTTP/TLS responses and verifies new UI views."""
        target = self._register_verify_approve(target_url='https://e2e-approved.org/')

        mock_tls = {
            'reachable': True,
            'verified': True,
            'resolved_ip': '93.184.216.34',
            'tls_version': 'TLSv1.3',
            'cipher': 'TLS_AES_256_GCM_SHA384',
            'cert': {
                'notAfter': 'Nov 17 23:59:59 2027 GMT',
                'issuer': ((('commonName', 'Let\'s Encrypt'),),)
            },
            'error': None
        }

        def mock_safe_request(url, target, method='GET', follow_redirects=False, **kwargs):
            if url.startswith('http://'):
                return {
                    'url': url,
                    'final_url': url,
                    'status_code': 301,
                    'headers': {'location': 'https://e2e-approved.org/'},
                    'raw_headers': [('Location', 'https://e2e-approved.org/')],
                    'set_cookies': [],
                    'body': b'',
                    'resolved_ip': '93.184.216.34',
                    'redirect_chain': [],
                    'tls_info': None
                }
            return {
                'url': url,
                'final_url': url,
                'status_code': 200,
                'headers': {
                    'strict-transport-security': 'max-age=31536000; includeSubDomains',
                    'x-content-type-options': 'nosniff',
                    'x-frame-options': 'SAMEORIGIN',
                    'referrer-policy': 'strict-origin-when-cross-origin',
                    'server': 'cloudflare'
                },
                'raw_headers': [],
                'set_cookies': ['sid=xyz; Secure; HttpOnly; SameSite=Lax'],
                'body': b'<html><body>Authorized Target</body></html>',
                'resolved_ip': '93.184.216.34',
                'redirect_chain': [],
                'tls_info': {'version': 'TLSv1.3'}
            }

        with patch('app.live_testing.scanner.inspect_tls_certificate', return_value=mock_tls), \
             patch('app.live_testing.scanner.safe_http_request', side_effect=mock_safe_request):
            res = self.client.post('/api/live/assessments/run', json={'target_uuid': target['target_uuid']})
            self.assertEqual(res.status_code, 200, res.data)
            assess = res.json['assessment']
            self.assertEqual(assess['status'], 'COMPLETED')
            self.assertEqual(assess['domain'], 'e2e-approved.org')
            self.assertGreater(assess['total_checks'], 8)
            self.assertGreater(assess['security_score'], 0)
            # CSP was intentionally omitted in mock response -> must fail
            keys = {f['check_key']: f for f in assess['findings']}
            self.assertEqual(keys['header_csp']['status'], 'FAIL')
            self.assertEqual(keys['header_hsts']['status'], 'PASS')
            self.assertEqual(keys['https_availability']['status'], 'PASS')
            self.assertEqual(keys['http_to_https_redirect']['status'], 'PASS')

            # Retrieve assessment by UUID and list history
            detail_res = self.client.get(f"/api/live/assessments/{assess['assessment_uuid']}")
            self.assertEqual(detail_res.status_code, 200)
            self.assertEqual(detail_res.json['assessment']['assessment_uuid'], assess['assessment_uuid'])

            hist_res = self.client.get('/api/live/assessments')
            self.assertEqual(hist_res.status_code, 200)
            self.assertGreaterEqual(hist_res.json['count'], 1)

        # Verify UI pages & static JS render cleanly
        for route in ('/live-targets', '/live-assessment', '/static/js/live_targets.js', '/static/js/live_assessment.js'):
            r = self.client.get(route)
            self.assertEqual(r.status_code, 200, f"Route {route} failed")
            r.close()

    # ------------------------------------------------------------------
    # 8. DNS Resolution & Connection/Read Timeout Protection Tests
    # ------------------------------------------------------------------
    def test_11_dns_and_socket_timeout_protection(self):
        """Tests that hanging DNS lookups and socket timeouts fail cleanly within bounded time."""
        import time
        from app.live_testing.scanner import inspect_tls_certificate

        # 1. Hanging DNS resolver must abort cleanly within dns_timeout (never hang indefinitely)
        def hanging_getaddrinfo(*args, **kwargs):
            time.sleep(5.0)
            return []

        start = time.monotonic()
        with patch('socket.getaddrinfo', side_effect=hanging_getaddrinfo):
            with self.assertRaises(SSRFBlockedError) as ctx:
                resolve_and_validate_host('slow-dns.example.org', 443, target_uuid='target-timeout-test', dns_timeout=0.15)
        elapsed = time.monotonic() - start
        self.assertEqual(ctx.exception.error_code, 'DNS_RESOLUTION_TIMEOUT')
        self.assertLess(elapsed, 1.5, f"DNS timeout guard took too long: {elapsed:.2f}s")

        # Audit log should record DNS_RESOLUTION_TIMEOUT
        logs = get_live_audit_logs(limit=10, target_uuid='target-timeout-test')
        self.assertTrue(any(l['action'] == 'DNS_RESOLUTION_TIMEOUT' for l in logs))

        # 2. TLS socket connect timeout produces controlled unreachable result (no crash/hang)
        pub_dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443))]
        with patch('socket.getaddrinfo', return_value=pub_dns), \
             patch('socket.create_connection', side_effect=socket.timeout('connect timed out')):
            tls_res = inspect_tls_certificate('timeout.example.org', 'target-timeout-test', max_request_rate=10, timeout=0.5)
            self.assertFalse(tls_res['reachable'])
            self.assertFalse(tls_res['verified'])
            self.assertIn('timed out', tls_res['error'].lower())


if __name__ == '__main__':
    unittest.main()
