import os
import uuid
import sqlite3
import tempfile
import threading
import datetime
import unittest
from unittest.mock import patch
from werkzeug.middleware.proxy_fix import ProxyFix

from app import create_app
from app.config import Config
from app.database import init_db
from app.models.user_model import create_user, create_initial_admin_atomic, ROLE_ADMIN, ROLE_OWNER
from app.models.live_target_model import create_live_target, utc_now
from app.auth.security import auth_rate_limiter


class TestProductionSecurityHardening(unittest.TestCase):
    def setUp(self):
        auth_rate_limiter.reset()
        self.tag = uuid.uuid4().hex[:8]

    def test_01_login_and_registration_rate_limiting(self):
        """Verifies brute-force login and registration abuse are blocked with HTTP 429."""
        app = create_app()
        app.config['TESTING'] = True
        app.config['AUTH_LOGIN_MAX_ATTEMPTS'] = 3
        app.config['AUTH_LOGIN_WINDOW_SECONDS'] = 300
        app.config['AUTH_REGISTER_MAX_ATTEMPTS'] = 2
        app.config['AUTH_REGISTER_WINDOW_SECONDS'] = 600
        client = app.test_client()

        # 3 failed login attempts -> 401; 4th -> 429 RATE_LIMIT_EXCEEDED
        ident = f'brute_{self.tag}'
        for i in range(3):
            res = client.post('/api/auth/login', json={'identifier': ident, 'password': 'WrongPassword1!'})
            self.assertEqual(res.status_code, 401)
        blocked_login = client.post('/api/auth/login', json={'identifier': ident, 'password': 'WrongPassword1!'})
        self.assertEqual(blocked_login.status_code, 429)
        self.assertEqual(blocked_login.json['error_type'], 'RATE_LIMIT_EXCEEDED')

        # 2 registration attempts -> allowed; 3rd -> 429 RATE_LIMIT_EXCEEDED
        for i in range(2):
            r = client.post('/api/auth/register', json={
                'username': f'reglim_{self.tag}_{i}',
                'email': f'reglim_{self.tag}_{i}@example.org',
                'password': 'ValidPassword123!',
                'role': 'VIEWER'
            })
            self.assertEqual(r.status_code, 201)
        blocked_reg = client.post('/api/auth/register', json={
            'username': f'reglim_{self.tag}_2',
            'email': f'reglim_{self.tag}_2@example.org',
            'password': 'ValidPassword123!',
            'role': 'VIEWER'
        })
        self.assertEqual(blocked_reg.status_code, 429)
        self.assertEqual(blocked_reg.json['error_type'], 'RATE_LIMIT_EXCEEDED')

    def test_02_atomic_concurrent_admin_bootstrap_and_public_protection(self):
        """Verifies atomic one-time Admin bootstrap under concurrency and public deployment lock."""
        # A. Public deployment without CYBERFORTIFY_BOOTSTRAP_TOKEN blocks /api/auth/setup-admin
        class PublicNoBootConfig(Config):
            IS_RENDER = True
            SECRET_KEY = 'a' * 40
            CYBERFORTIFY_BOOTSTRAP_TOKEN = None

        pub_app = create_app(config_class=PublicNoBootConfig)
        pub_client = pub_app.test_client()
        res = pub_client.post('/api/auth/setup-admin', json={
            'username': f'pubadm_{self.tag}',
            'email': f'pubadm_{self.tag}@example.org',
            'password': 'StrongPassword123!'
        })
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json['error_type'], 'BOOTSTRAP_DISABLED_IN_PRODUCTION')

        # B. Concurrent race on an isolated fresh SQLite DB: strictly 1 Admin created
        tmp_fd, tmp_db_path = tempfile.mkstemp(suffix='.db')
        os.close(tmp_fd)
        orig_db_path = Config.DATABASE_PATH
        try:
            Config.DATABASE_PATH = tmp_db_path
            init_db()

            results = []
            barrier = threading.Barrier(5)

            def _attempt(idx):
                barrier.wait()
                user, err_code, _ = create_initial_admin_atomic(
                    f'race_admin_{idx}',
                    f'race_admin_{idx}@example.org',
                    'StrongRacePass123!'
                )
                results.append((user is not None, err_code))

            threads = [threading.Thread(target=_attempt, args=(i,)) for i in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            successes = [r for r in results if r[0]]
            self.assertEqual(len(successes), 1, f"Expected strictly 1 admin created, got: {results}")
        finally:
            Config.DATABASE_PATH = orig_db_path
            try:
                os.remove(tmp_db_path)
            except OSError:
                pass

    def test_03_legacy_targets_without_owner_user_id_are_admin_only(self):
        """Verifies self-registered Website Owners cannot hijack legacy targets (owner_user_id=NULL) via email match."""
        app = create_app()
        app.config['TESTING'] = True
        app.config['REQUIRE_AUTH'] = True

        legacy_email = f'legacy_{self.tag}@example.org'
        now = utc_now()
        legacy_target = create_live_target(
            target_url=f'https://legacy-{self.tag}.example.org/',
            domain=f'legacy-{self.tag}.example.org',
            owner_name='Legacy Owner',
            owner_email=legacy_email,
            owner_consent=True,
            verification_method='signed_attestation',
            approved_paths=['/'],
            allowed_methods=['GET'],
            start_date=(now - datetime.timedelta(minutes=5)).isoformat(),
            expiry_date=(now + datetime.timedelta(days=3)).isoformat(),
            max_request_rate=10,
            owner_user_id=None  # Unassigned legacy target
        )
        luuid = legacy_target['target_uuid']

        # Attacker self-registers a WEBSITE_OWNER account with the EXACT same email
        attacker_client = app.test_client()
        reg = attacker_client.post('/api/auth/register', json={
            'username': f'claim_{self.tag}',
            'email': legacy_email,
            'password': 'ClaimPassword123!',
            'role': 'WEBSITE_OWNER'
        })
        self.assertEqual(reg.status_code, 201)

        # Website Owner MUST be blocked from viewing the legacy target (403 IDOR_BLOCKED)
        get_res = attacker_client.get(f'/api/live/targets/{luuid}')
        self.assertEqual(get_res.status_code, 403)
        self.assertEqual(get_res.json['error_type'], 'IDOR_BLOCKED')

        # And it must NOT appear in their target list
        list_res = attacker_client.get('/api/live/targets')
        self.assertEqual(list_res.status_code, 200)
        self.assertFalse(any(t['target_uuid'] == luuid for t in list_res.json['targets']))

        # Admin still has full access to manage legacy targets
        adm_u = f'legadm_{self.tag}'
        create_user(adm_u, f'{adm_u}@example.org', 'AdminLegacy123!', role=ROLE_ADMIN)
        adm_client = app.test_client()
        adm_client.post('/api/auth/login', json={'identifier': adm_u, 'password': 'AdminLegacy123!'})
        adm_get = adm_client.get(f'/api/live/targets/{luuid}')
        self.assertEqual(adm_get.status_code, 200)

    def test_04_production_config_secret_key_proxyfix_and_secure_cookies(self):
        """Verifies SECRET_KEY enforcement, REQUIRE_AUTH lock, ProxyFix, and Secure cookies behind HTTPS proxy."""
        # 1. STRICT_PRODUCTION_CONFIG=True rejects hardcoded default SECRET_KEY
        class StrictBadSecretConfig(Config):
            FLASK_ENV = 'production'
            STRICT_PRODUCTION_CONFIG = True
            SECRET_KEY = Config.DEFAULT_DEV_SECRET_KEY

        with self.assertRaises(RuntimeError):
            create_app(config_class=StrictBadSecretConfig)

        # 2. Non-strict public deployment rotates weak key, locks REQUIRE_AUTH=True, DEBUG=False, Secure cookies & ProxyFix
        class RenderConfig(Config):
            IS_RENDER = True
            REQUIRE_AUTH = False   # Attempt to disable auth in production must be overridden!
            DEBUG = True           # Attempt to enable debug in production must be overridden!
            SECRET_KEY = Config.DEFAULT_DEV_SECRET_KEY

        prod_app = create_app(config_class=RenderConfig)
        self.assertNotEqual(prod_app.config['SECRET_KEY'], Config.DEFAULT_DEV_SECRET_KEY)
        self.assertGreaterEqual(len(prod_app.config['SECRET_KEY']), 64)
        self.assertTrue(prod_app.config['LIVE_AUTH_ENFORCED'])
        with prod_app.app_context():
            from app.auth.security import is_auth_enforced
            self.assertTrue(is_auth_enforced())
        self.assertFalse(prod_app.config['DEBUG'])
        self.assertTrue(prod_app.config['SESSION_COOKIE_SECURE'])
        self.assertIsInstance(prod_app.wsgi_app, ProxyFix)

        # Login over HTTPS reverse proxy headers produces Secure; HttpOnly; SameSite=Lax cookie
        adm_u = f'prxadm_{self.tag}'
        create_user(adm_u, f'{adm_u}@example.org', 'ProxyPass1234!', role=ROLE_ADMIN)
        client = prod_app.test_client()
        login_res = client.post(
            '/api/auth/login',
            json={'identifier': adm_u, 'password': 'ProxyPass1234!'},
            headers={'X-Forwarded-Proto': 'https', 'X-Forwarded-For': '203.0.113.10'}
        )
        self.assertEqual(login_res.status_code, 200)
        cookie_hdr = login_res.headers.get('Set-Cookie', '')
        self.assertIn('Secure', cookie_hdr)
        self.assertIn('HttpOnly', cookie_hdr)
        self.assertIn('SameSite=Lax', cookie_hdr)

    def test_05_sanitized_error_responses_no_secret_or_traceback_leakage(self):
        """Verifies 500/404 API errors never leak internal exception text, secrets, or stack traces."""
        app = create_app()
        app.config['TESTING'] = True
        app.config['REQUIRE_AUTH'] = True

        adm_u = f'erradm_{self.tag}'
        create_user(adm_u, f'{adm_u}@example.org', 'ErrAdmin1234!', role=ROLE_ADMIN)
        client = app.test_client()
        login_res = client.post('/api/auth/login', json={'identifier': adm_u, 'password': 'ErrAdmin1234!'})
        csrf_tok = login_res.json['csrf_token']

        # Simulated unexpected crash with sensitive internal string must NOT appear in API 500 JSON
        with patch('app.api.live_testing_routes.run_live_assessment', side_effect=RuntimeError('LEAKED_INTERNAL_SECRET_999')):
            res = client.post(
                '/api/live/assessments/run',
                json={'target_uuid': 'target-does-not-matter'},
                headers={'X-CSRF-Token': csrf_tok}
            )
            self.assertEqual(res.status_code, 500)
            body = res.data.decode('utf-8')
            self.assertNotIn('LEAKED_INTERNAL_SECRET_999', body)
            self.assertNotIn('Traceback', body)
            self.assertEqual(res.json['error_type'], 'ASSESSMENT_ERROR')

        # Clean JSON 404 for unknown API route
        not_found = client.get('/api/nonexistent-endpoint-xyz')
        self.assertEqual(not_found.status_code, 404)
        self.assertEqual(not_found.json['error_type'], 'NOT_FOUND')


if __name__ == '__main__':
    unittest.main()
