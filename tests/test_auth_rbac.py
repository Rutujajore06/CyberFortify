import unittest
import uuid
import json
import datetime
from unittest.mock import patch

from app import create_app
from app.database import get_db_connection
from app.models.user_model import create_user, ROLE_ADMIN, ROLE_OWNER, ROLE_VIEWER
from app.models.live_target_model import utc_now
from app.live_testing.security import rate_limiter
from app.auth.security import auth_rate_limiter


def _mock_tls():
    return {
        'reachable': True,
        'verified': True,
        'resolved_ip': '93.184.216.34',
        'tls_version': 'TLSv1.3',
        'cipher': 'TLS_AES_128_GCM_SHA256',
        'cert': {
            'notAfter': 'Nov 17 23:59:59 2027 GMT',
            'issuer': ((('commonName', 'Trusted CA'),),)
        },
        'error': None
    }


def _mock_http(url, target, method='GET', follow_redirects=False, **kwargs):
    domain = target['domain']
    if url.startswith('http://'):
        return {
            'url': url,
            'final_url': url,
            'status_code': 308,
            'headers': {'location': f'https://{domain}/'},
            'raw_headers': [('Location', f'https://{domain}/')],
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
            'strict-transport-security': 'max-age=63072000; includeSubDomains',
            'x-content-type-options': 'nosniff',
            'x-frame-options': 'DENY',
            'server': 'Vercel'
        },
        'raw_headers': [],
        'set_cookies': [],
        'body': b'<html><body>OK</body></html>',
        'resolved_ip': '93.184.216.34',
        'redirect_chain': [],
        'tls_info': {'version': 'TLSv1.3'}
    }


class TestAdminAuthAndRBAC(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.app.config['REQUIRE_AUTH'] = True
        self.app.config['CSRF_ENABLED'] = True
        rate_limiter.reset()
        auth_rate_limiter.reset()
        self.tag = uuid.uuid4().hex[:8]

    def _login_client(self, username, password):
        client = self.app.test_client()
        res = client.post('/api/auth/login', json={'identifier': username, 'password': password})
        self.assertEqual(res.status_code, 200, res.data)
        csrf_token = res.json['csrf_token']
        return client, csrf_token, res

    def _target_payload(self, domain, owner_email):
        now = utc_now()
        return {
            'target_url': f'https://{domain}/',
            'owner_name': 'Authorized Owner',
            'owner_email': owner_email,
            'owner_consent': True,
            'verification_method': 'signed_attestation',
            'approved_paths': ['/'],
            'allowed_methods': ['GET'],
            'start_date': (now - datetime.timedelta(minutes=5)).isoformat(),
            'expiry_date': (now + datetime.timedelta(days=5)).isoformat(),
            'max_request_rate': 60
        }

    def test_01_password_hashing_cookie_security_and_no_self_admin(self):
        """Verifies scrypt hashing, zero password leakage, HttpOnly cookies, and no Admin self-registration."""
        # Self-registering as ADMIN must be strictly forbidden (403)
        anon = self.app.test_client()
        bad_reg = anon.post('/api/auth/register', json={
            'username': f'rogue_{self.tag}',
            'email': f'rogue_{self.tag}@example.org',
            'password': 'StrongPassword123!',
            'role': 'ADMIN'
        })
        self.assertEqual(bad_reg.status_code, 403)
        self.assertEqual(bad_reg.json['error_type'], 'FORBIDDEN')

        # Create Admin via model (simulating env bootstrap / setup) and verify scrypt hash in SQLite
        admin_uname = f'adm_{self.tag}'
        admin_email = f'adm_{self.tag}@example.org'
        admin_pwd = 'AdminStrongPass!2026'
        admin_user, err = create_user(admin_uname, admin_email, admin_pwd, role=ROLE_ADMIN)
        self.assertIsNone(err)
        self.assertNotIn('password_hash', admin_user)

        conn = get_db_connection()
        row = conn.execute('SELECT password_hash FROM platform_users WHERE user_uuid = ?', (admin_user['user_uuid'],)).fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertTrue(row['password_hash'].startswith('scrypt:'))
        self.assertNotIn(admin_pwd, row['password_hash'])

        # Once an Admin exists, /api/auth/setup-admin is permanently locked (403)
        locked = anon.post('/api/auth/setup-admin', json={
            'username': f'second_adm_{self.tag}',
            'email': f'second_{self.tag}@example.org',
            'password': 'AnotherPassword123!'
        })
        self.assertEqual(locked.status_code, 403)
        self.assertEqual(locked.json['error_type'], 'ADMIN_ALREADY_EXISTS')

        # Verify HttpOnly & SameSite session cookie flags on login
        admin_client, csrf_tok, login_res = self._login_client(admin_uname, admin_pwd)
        set_cookie = login_res.headers.get('Set-Cookie', '')
        self.assertIn('HttpOnly', set_cookie)
        self.assertIn('SameSite=Lax', set_cookie)
        self.assertNotIn('password_hash', json.dumps(login_res.json))

        # Wrong password rejected
        bad_login = anon.post('/api/auth/login', json={'identifier': admin_uname, 'password': 'WrongPassword!'})
        self.assertEqual(bad_login.status_code, 401)

        # Admin user list never leaks password_hash
        users_res = admin_client.get('/api/auth/users')
        self.assertEqual(users_res.status_code, 200)
        self.assertNotIn('password_hash', users_res.data.decode('utf-8'))

    def test_02_public_deployment_blocks_unauthenticated_access(self):
        """Verifies public/production deployments strictly block unauthenticated access to protected endpoints."""
        pub_app = create_app()
        pub_app.config['TESTING'] = True
        pub_app.config['REQUIRE_AUTH'] = False  # Even if REQUIRE_AUTH not explicitly set
        pub_app.config['IS_RENDER'] = True      # Public deployment flag forces auth!
        client = pub_app.test_client()

        protected = [
            ('GET', '/api/live/targets'),
            ('POST', '/api/live/targets'),
            ('POST', '/api/live/targets/target-fake/approve'),
            ('POST', '/api/live/targets/target-fake/reject'),
            ('POST', '/api/live/assessments/run'),
            ('POST', '/api/live/retest/run'),
            ('GET', '/api/live/remediations?target_uuid=target-fake'),
            ('PATCH', '/api/live/remediations/rem-fake'),
            ('GET', '/api/live/audit-logs'),
        ]
        for method, path in protected:
            with self.subTest(method=method, path=path):
                res = client.open(path, method=method, json={})
                self.assertEqual(res.status_code, 401, f"{method} {path} should require auth on public deployment")
                self.assertEqual(res.json['error_type'], 'AUTHENTICATION_REQUIRED')

    def test_03_csrf_protection_enforced_on_mutations(self):
        """Verifies state-changing API calls from authenticated sessions require valid X-CSRF-Token."""
        adm_u = f'csrf_adm_{self.tag}'
        create_user(adm_u, f'{adm_u}@example.org', 'CsrfPass1234!', role=ROLE_ADMIN)
        client, csrf_tok, _ = self._login_client(adm_u, 'CsrfPass1234!')

        # Missing CSRF token -> 403 CSRF_FAILED
        no_csrf = client.post('/api/live/targets', json=self._target_payload(f'csrf-{self.tag}.example.org', f'{adm_u}@example.org'))
        self.assertEqual(no_csrf.status_code, 403)
        self.assertEqual(no_csrf.json['error_type'], 'CSRF_FAILED')

        # Wrong CSRF token -> 403 CSRF_FAILED
        bad_csrf = client.post(
            '/api/live/targets',
            json=self._target_payload(f'csrf-{self.tag}.example.org', f'{adm_u}@example.org'),
            headers={'X-CSRF-Token': 'forged-token'}
        )
        self.assertEqual(bad_csrf.status_code, 403)
        self.assertEqual(bad_csrf.json['error_type'], 'CSRF_FAILED')

        # Valid CSRF token -> 201 Created
        good_csrf = client.post(
            '/api/live/targets',
            json=self._target_payload(f'csrf-{self.tag}.example.org', f'{adm_u}@example.org'),
            headers={'X-CSRF-Token': csrf_tok}
        )
        self.assertEqual(good_csrf.status_code, 201)

    def test_04_full_rbac_matrix_and_idor_prevention(self):
        """Tests Admin, Website Owner (A & B IDOR isolation), and Viewer (read-only + token redaction) end-to-end."""
        # Provision 4 accounts: Admin, Owner A, Owner B, Viewer
        create_user(f'admin_{self.tag}', f'admin_{self.tag}@example.org', 'PassAdmin123!', role=ROLE_ADMIN)
        create_user(f'ownerA_{self.tag}', f'ownerA_{self.tag}@example.org', 'PassOwnerA12!', role=ROLE_OWNER)
        create_user(f'ownerB_{self.tag}', f'ownerB_{self.tag}@example.org', 'PassOwnerB12!', role=ROLE_OWNER)
        create_user(f'viewer_{self.tag}', f'viewer_{self.tag}@example.org', 'PassViewer12!', role=ROLE_VIEWER)

        adm_c, adm_csrf, _ = self._login_client(f'admin_{self.tag}', 'PassAdmin123!')
        ownA_c, ownA_csrf, _ = self._login_client(f'ownerA_{self.tag}', 'PassOwnerA12!')
        ownB_c, ownB_csrf, _ = self._login_client(f'ownerB_{self.tag}', 'PassOwnerB12!')
        view_c, view_csrf, _ = self._login_client(f'viewer_{self.tag}', 'PassViewer12!')

        # 1. Viewer CANNOT register a target (403)
        v_reg = view_c.post(
            '/api/live/targets',
            json=self._target_payload(f'viewer-{self.tag}.example.org', f'viewer_{self.tag}@example.org'),
            headers={'X-CSRF-Token': view_csrf}
        )
        self.assertEqual(v_reg.status_code, 403)

        # 2. Owner A registers their own target -> 201
        regA = ownA_c.post(
            '/api/live/targets',
            json=self._target_payload(f'ownerA-{self.tag}.example.org', f'ownerA_{self.tag}@example.org'),
            headers={'X-CSRF-Token': ownA_csrf}
        )
        self.assertEqual(regA.status_code, 201, regA.data)
        targetA = regA.json['target']
        tuuidA = targetA['target_uuid']
        tokA = targetA['verification_token']

        # 3. IDOR Check: Owner B CANNOT view or verify Owner A's target (403 IDOR_BLOCKED)
        idor_get = ownB_c.get(f'/api/live/targets/{tuuidA}')
        self.assertEqual(idor_get.status_code, 403)
        self.assertEqual(idor_get.json['error_type'], 'IDOR_BLOCKED')

        idor_ver = ownB_c.post(
            f'/api/live/targets/{tuuidA}/verify',
            json={'verification_token': tokA},
            headers={'X-CSRF-Token': ownB_csrf}
        )
        self.assertEqual(idor_ver.status_code, 403)
        self.assertEqual(idor_ver.json['error_type'], 'IDOR_BLOCKED')

        # Owner B's target list MUST NOT include Owner A's target
        ownB_list = ownB_c.get('/api/live/targets')
        self.assertEqual(ownB_list.status_code, 200)
        self.assertFalse(any(t['target_uuid'] == tuuidA for t in ownB_list.json['targets']))

        # 4. Owner A verifies their own target -> 200 PENDING_APPROVAL
        verA = ownA_c.post(
            f'/api/live/targets/{tuuidA}/verify',
            json={'verification_token': tokA},
            headers={'X-CSRF-Token': ownA_csrf}
        )
        self.assertEqual(verA.status_code, 200)

        # 5. Owner A & Viewer CANNOT approve or reject targets (403 FORBIDDEN)
        for bad_c, bad_csrf in ((ownA_c, ownA_csrf), (view_c, view_csrf)):
            self.assertEqual(
                bad_c.post(f'/api/live/targets/{tuuidA}/approve', json={}, headers={'X-CSRF-Token': bad_csrf}).status_code,
                403
            )
            self.assertEqual(
                bad_c.post(f'/api/live/targets/{tuuidA}/reject', json={}, headers={'X-CSRF-Token': bad_csrf}).status_code,
                403
            )

        # 6. Admin approves Owner A's target -> 200 APPROVED
        app_res = adm_c.post(
            f'/api/live/targets/{tuuidA}/approve',
            json={},
            headers={'X-CSRF-Token': adm_csrf}
        )
        self.assertEqual(app_res.status_code, 200)
        self.assertEqual(app_res.json['target']['auth_status'], 'APPROVED')

        # 7. Owner A & Viewer CANNOT start live assessments or retests (403 FORBIDDEN)
        for bad_c, bad_csrf in ((ownA_c, ownA_csrf), (view_c, view_csrf)):
            self.assertEqual(
                bad_c.post('/api/live/assessments/run', json={'target_uuid': tuuidA}, headers={'X-CSRF-Token': bad_csrf}).status_code,
                403
            )
            self.assertEqual(
                bad_c.post('/api/live/retest/run', json={'target_uuid': tuuidA}, headers={'X-CSRF-Token': bad_csrf}).status_code,
                403
            )

        # 8. Admin runs live assessment & retest -> 200
        with patch('app.live_testing.scanner.inspect_tls_certificate', return_value=_mock_tls()), \
             patch('app.live_testing.scanner.safe_http_request', side_effect=_mock_http):
            run_res = adm_c.post(
                '/api/live/assessments/run',
                json={'target_uuid': tuuidA},
                headers={'X-CSRF-Token': adm_csrf}
            )
            self.assertEqual(run_res.status_code, 200, run_res.data)
            assess_uuid = run_res.json['assessment']['assessment_uuid']

            retest_res = adm_c.post(
                '/api/live/retest/run',
                json={'target_uuid': tuuidA},
                headers={'X-CSRF-Token': adm_csrf}
            )
            self.assertEqual(retest_res.status_code, 200, retest_res.data)

        # 9. Owner A CAN view own assessment, report, and edit own remediation notes
        self.assertEqual(ownA_c.get(f'/api/live/assessments/{assess_uuid}').status_code, 200)
        self.assertEqual(ownA_c.get(f'/api/live/assessments/{assess_uuid}/report?format=html').status_code, 200)
        remsA = ownA_c.get(f'/api/live/remediations?target_uuid={tuuidA}')
        self.assertEqual(remsA.status_code, 200)
        rem_uuid = remsA.json['remediations'][0]['remediation_uuid']

        updA = ownA_c.patch(
            f'/api/live/remediations/{rem_uuid}',
            json={'remediation_status': 'In Progress', 'remediation_notes': 'Owner A adding CSP header'},
            headers={'X-CSRF-Token': ownA_csrf}
        )
        self.assertEqual(updA.status_code, 200)

        # 10. IDOR Check: Owner B CANNOT view Owner A's assessment, compare, report, remediations, or edit notes
        self.assertEqual(ownB_c.get(f'/api/live/assessments/{assess_uuid}').status_code, 403)
        self.assertEqual(ownB_c.get(f'/api/live/assessments/compare?target_uuid={tuuidA}').status_code, 403)
        self.assertEqual(ownB_c.get(f'/api/live/assessments/{assess_uuid}/report?format=json').status_code, 403)
        self.assertEqual(ownB_c.get(f'/api/live/remediations?target_uuid={tuuidA}').status_code, 403)
        self.assertEqual(
            ownB_c.patch(
                f'/api/live/remediations/{rem_uuid}',
                json={'remediation_notes': 'Cross-owner tamper'},
                headers={'X-CSRF-Token': ownB_csrf}
            ).status_code,
            403
        )
        self.assertEqual(ownB_c.get(f'/api/live/audit-logs?target_uuid={tuuidA}').status_code, 403)

        # 11. Viewer has Read-Only access, NEVER sees verification_token, and CANNOT edit remediations or view audit logs
        v_targets = view_c.get('/api/live/targets')
        self.assertEqual(v_targets.status_code, 200)
        self.assertNotIn(tokA, v_targets.data.decode('utf-8'))

        v_detail = view_c.get(f'/api/live/targets/{tuuidA}')
        self.assertEqual(v_detail.status_code, 200)
        self.assertNotIn('verification_token', v_detail.json['target'])

        self.assertEqual(view_c.get(f'/api/live/assessments/{assess_uuid}').status_code, 200)
        self.assertEqual(view_c.get(f'/api/live/assessments/{assess_uuid}/report?format=json').status_code, 200)
        self.assertEqual(view_c.get(f'/api/live/remediations?target_uuid={tuuidA}').status_code, 200)
        self.assertEqual(
            view_c.patch(
                f'/api/live/remediations/{rem_uuid}',
                json={'remediation_notes': 'Viewer tamper'},
                headers={'X-CSRF-Token': view_csrf}
            ).status_code,
            403
        )
        self.assertEqual(view_c.get('/api/live/audit-logs').status_code, 403)
        self.assertEqual(view_c.get('/api/auth/users').status_code, 403)

        # 12. Login UI & static JS serve cleanly with CSRF meta tag
        login_page = self.app.test_client().get('/login')
        self.assertEqual(login_page.status_code, 200)
        self.assertIn(b'name="csrf-token"', login_page.data)
        js_res = self.app.test_client().get('/static/js/login.js')
        self.assertEqual(js_res.status_code, 200)
        js_res.close()


if __name__ == '__main__':
    unittest.main()
