import unittest
import json
import os
import tempfile
from app import create_app
from app.config import Config
from app.models.defense_model import set_defense_state, is_defense_enabled, get_all_defenses
from app.models.event_model import get_events

class TestPhase1(unittest.TestCase):
    def setUp(self):
        # Create test client
        self.app = create_app()
        self.client = self.app.test_client()

    def test_01_target_status(self):
        """Test health status and defense snapshot"""
        response = self.client.get('/api/target/status')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'online')
        self.assertIn('active_defenses', data)

    def test_02_login_and_rate_limiting(self):
        """Test login endpoint and toggleable rate limiting"""
        # Ensure rate limiting is disabled
        set_defense_state('rate_limiting', False)
        self.assertFalse(is_defense_enabled('rate_limiting'))

        # 1. Invalid login returns 401
        res = self.client.post('/api/target/login', json={'username': 'alice', 'password': 'wrongpassword'})
        self.assertEqual(res.status_code, 401)

        # 2. Valid login returns 200
        res = self.client.post('/api/target/login', json={'username': 'alice', 'password': 'AliceSecure123#'})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')

        # 3. Enable rate limiting and test lockout after 3 consecutive failures
        set_defense_state('rate_limiting', True)
        for _ in range(3):
            self.client.post('/api/target/login', json={'username': 'locked_user', 'password': 'bad'})
        
        # 4th attempt should be blocked with 429
        res_blocked = self.client.post('/api/target/login', json={'username': 'locked_user', 'password': 'bad'})
        self.assertEqual(res_blocked.status_code, 429)

        # Reset rate limiting
        set_defense_state('rate_limiting', False)

    def test_03_admin_secrets_rbac(self):
        """Test RBAC enforcement toggle on admin endpoint"""
        # Vulnerable mode: RBAC disabled
        set_defense_state('rbac_enforcement', False)
        res = self.client.get('/api/target/admin/secrets')
        self.assertEqual(res.status_code, 200)
        self.assertIn('vault_master_key', json.loads(res.data)['secrets'])

        # Fortified mode: RBAC enabled
        set_defense_state('rbac_enforcement', True)
        res_denied = self.client.get('/api/target/admin/secrets')
        self.assertEqual(res_denied.status_code, 403)

        # Authorized token passes
        from app.target_app.defenses import DEMO_VALID_ADMIN_TOKEN
        res_auth = self.client.get('/api/target/admin/secrets', headers={'Authorization': DEMO_VALID_ADMIN_TOKEN})
        self.assertEqual(res_auth.status_code, 200)

        # Reset
        set_defense_state('rbac_enforcement', False)

    def test_04_sql_injection_defense(self):
        """Test SQL injection parameterization toggle"""
        # Vulnerable mode: SQL injection returns accounts
        set_defense_state('parameterized_queries', False)
        res = self.client.get("/api/target/search?q=' OR 1=1 --")
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        # In vulnerable mode, all users returned
        self.assertGreater(data['results_count'], 1)

        # Fortified mode: Parameterized queries / SQLi guard treats payload literally or blocks it
        set_defense_state('parameterized_queries', True)
        res_fortified = self.client.get("/api/target/search?q=' OR 1=1 --")
        self.assertIn(res_fortified.status_code, (200, 400))
        data_fortified = json.loads(res_fortified.data)
        self.assertEqual(data_fortified.get('results_count', 0), 0)

        # Reset
        set_defense_state('parameterized_queries', False)

    def test_05_input_validation_defense(self):
        """Test input sanitization toggle on feedback endpoint"""
        # Vulnerable mode: stores raw script tags
        set_defense_state('input_sanitization', False)
        payload = "<script>alert('XSS')</script>"
        res = self.client.post('/api/target/feedback', json={'author': 'hacker', 'content': payload})
        self.assertEqual(res.status_code, 201)
        self.assertEqual(json.loads(res.data)['stored_content'], payload)

        # Fortified mode: rejects or encodes malicious script
        set_defense_state('input_sanitization', True)
        res_blocked = self.client.post('/api/target/feedback', json={'author': 'hacker', 'content': payload})
        self.assertEqual(res_blocked.status_code, 400)

        # Reset
        set_defense_state('input_sanitization', False)

    def test_06_event_telemetry(self):
        """Test that events are recorded in SQLite events table"""
        events, total = get_events(limit=10)
        self.assertGreater(total, 0)
        first = events[0]
        self.assertIn('endpoint', first)
        self.assertIn('status_code', first)

if __name__ == '__main__':
    unittest.main()
