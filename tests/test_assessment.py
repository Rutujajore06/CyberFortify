import unittest
import json
from unittest.mock import patch
from app import create_app
from app.config import Config
from app.models.defense_model import set_defense_state
from app.models.assessment_model import get_assessment_by_uuid, get_recent_assessments
from app.target_app.defenses import DEMO_VALID_ADMIN_TOKEN

class TestWebsiteSecurityAssessment(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()

    def test_01_scope_config_endpoint(self):
        """Test scope config endpoint returns configured local demo parameters."""
        res = self.client.get('/api/assessment/config')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')
        self.assertIn('demo_origin', data)
        self.assertIn('127.0.0.1', data['allowed_hosts'])
        self.assertIn('localhost', data['allowed_hosts'])
        self.assertEqual(data['demo_port'], Config.PORT)

    def test_02_url_scope_validation_rejections(self):
        """Test server-side scope enforcement rejects out-of-scope or invalid targets."""
        invalid_cases = [
            # 1. Empty / Missing URL
            ('', 'Target URL is required'),
            ('   ', 'Target URL cannot be empty'),
            
            # 2. External domain targets (Strictly Forbidden)
            ('http://google.com', 'Out-of-scope host'),
            ('http://example.com:5000', 'Out-of-scope host'),
            ('http://attacker.local:5000', 'Out-of-scope host'),
            ('http://192.168.1.100:5000', 'Out-of-scope host'),

            # 3. Unsupported schemes
            ('https://127.0.0.1:5000', 'Unsupported URL scheme'),
            ('ftp://127.0.0.1:5000', 'Unsupported URL scheme'),
            ('file:///etc/passwd', 'Unsupported URL scheme'),
            ('javascript:alert(1)', 'Unsupported URL scheme'),

            # 4. URL credentials (userinfo)
            ('http://admin:secret@127.0.0.1:5000', 'URL credentials'),
            ('http://user@127.0.0.1:5000', 'URL credentials'),

            # 5. Unexpected ports
            ('http://127.0.0.1:8080', 'Unexpected port'),
            ('http://127.0.0.1:22', 'Unexpected port'),
            ('http://127.0.0.1:9999', 'Unexpected port'),

            # 6. Path traversal sequences
            ('http://127.0.0.1:5000/../../etc/passwd', 'traversal'),
            ('http://127.0.0.1:5000/api/target/%2e%2e/admin', 'traversal'),

            # 7. Disallowed non-demo paths
            ('http://127.0.0.1:5000/phpmyadmin', 'Unexpected path')
        ]

        for test_url, expected_err in invalid_cases:
            with self.subTest(url=test_url):
                res = self.client.post('/api/assessment/run', json={'url': test_url})
                self.assertEqual(res.status_code, 400)
                data = json.loads(res.data)
                self.assertEqual(data['status'], 'error')
                self.assertEqual(data.get('error_type'), 'SCOPE_VIOLATION')
                self.assertIn(expected_err.lower(), data['message'].lower())

    def test_03_url_scope_validation_valid_targets(self):
        """Test that valid Fortress Bank demo URLs are accepted and assessed."""
        valid_urls = [
            f"http://127.0.0.1:{Config.PORT}",
            f"http://localhost:{Config.PORT}",
            f"http://127.0.0.1:{Config.PORT}/",
            f"http://127.0.0.1:{Config.PORT}/api/target/status"
        ]

        for test_url in valid_urls:
            with self.subTest(url=test_url):
                res = self.client.post('/api/assessment/run', json={'url': test_url})
                self.assertEqual(res.status_code, 200)
                data = json.loads(res.data)
                self.assertEqual(data['status'], 'success')
                self.assertIn('assessment', data)
                self.assertEqual(data['assessment']['scope_target'], 'Fortress Bank Demo')

    def test_04_assessment_vulnerable_baseline_state(self):
        """Test assessment accurately reports vulnerabilities when defensive controls are disabled."""
        # Disable all 4 defenses
        set_defense_state('rate_limiting', False)
        set_defense_state('rbac_enforcement', False)
        set_defense_state('parameterized_queries', False)
        set_defense_state('input_sanitization', False)

        res = self.client.post('/api/assessment/run', json={'url': f"http://127.0.0.1:{Config.PORT}"})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        assessment = data['assessment']

        self.assertEqual(assessment['overall_status'], 'VULNERABLE')
        self.assertGreater(assessment['failed_checks'], 0)

        # Verify specific findings
        findings_by_key = {f['check_key']: f for f in assessment['findings']}
        
        # Rate limiting check
        self.assertEqual(findings_by_key['rate_limiting']['status'], 'VULNERABLE')
        self.assertEqual(findings_by_key['rate_limiting']['severity'], 'HIGH')
        self.assertIn('is_enabled=0', findings_by_key['rate_limiting']['evidence'])
        self.assertTrue(bool(findings_by_key['rate_limiting']['remediation']))

        # RBAC check
        self.assertEqual(findings_by_key['rbac_enforcement']['status'], 'VULNERABLE')
        self.assertEqual(findings_by_key['rbac_enforcement']['severity'], 'CRITICAL')
        self.assertIn('is_enabled=0', findings_by_key['rbac_enforcement']['evidence'])

        # SQL Injection parameterization check
        self.assertEqual(findings_by_key['parameterized_queries']['status'], 'VULNERABLE')
        self.assertEqual(findings_by_key['parameterized_queries']['severity'], 'CRITICAL')

        # Input sanitization check
        self.assertEqual(findings_by_key['input_sanitization']['status'], 'VULNERABLE')
        self.assertEqual(findings_by_key['input_sanitization']['severity'], 'HIGH')

        # Verify SQLite persistence
        db_record = get_assessment_by_uuid(assessment['assessment_uuid'])
        self.assertIsNotNone(db_record)
        self.assertEqual(db_record['overall_status'], 'VULNERABLE')
        self.assertGreater(len(db_record['granular_findings']), 0)

    def test_05_assessment_fortified_state_reflection(self):
        """Test assessment accurately reflects defended status when controls are enabled."""
        # Enable all defenses in database
        set_defense_state('rate_limiting', True)
        set_defense_state('rbac_enforcement', True)
        set_defense_state('parameterized_queries', True)
        set_defense_state('input_sanitization', True)

        res = self.client.post('/api/assessment/run', json={'url': f"http://127.0.0.1:{Config.PORT}"})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        assessment = data['assessment']

        findings_by_key = {f['check_key']: f for f in assessment['findings']}
        self.assertEqual(findings_by_key['rate_limiting']['status'], 'DEFENDED')
        self.assertEqual(findings_by_key['rbac_enforcement']['status'], 'DEFENDED')
        self.assertEqual(findings_by_key['parameterized_queries']['status'], 'DEFENDED')
        self.assertEqual(findings_by_key['input_sanitization']['status'], 'DEFENDED')

        # Reset defenses back to disabled
        set_defense_state('rate_limiting', False)
        set_defense_state('rbac_enforcement', False)
        set_defense_state('parameterized_queries', False)
        set_defense_state('input_sanitization', False)

    def test_06_assessment_history_and_details_endpoints(self):
        """Test history listing and detailed UUID retrieval endpoints."""
        res_run = self.client.post('/api/assessment/run', json={'url': f"http://127.0.0.1:{Config.PORT}"})
        uuid = json.loads(res_run.data)['assessment']['assessment_uuid']

        # 1. Fetch history
        res_history = self.client.get('/api/assessment/history?limit=10')
        self.assertEqual(res_history.status_code, 200)
        history_data = json.loads(res_history.data)
        self.assertGreater(history_data['count'], 0)
        self.assertTrue(any(a['assessment_uuid'] == uuid for a in history_data['assessments']))

        # 2. Fetch specific assessment by UUID
        res_detail = self.client.get(f'/api/assessment/{uuid}')
        self.assertEqual(res_detail.status_code, 200)
        detail_data = json.loads(res_detail.data)
        self.assertEqual(detail_data['assessment']['assessment_uuid'], uuid)
        self.assertIn('granular_findings', detail_data['assessment'])

        # 3. 404 for invalid UUID
        res_404 = self.client.get('/api/assessment/assess-nonexistent-1234')
        self.assertEqual(res_404.status_code, 404)

    def test_07_backend_authentication_handling(self):
        """Test backend authentication handling consistency."""
        # 1. Valid Authorization token accepted
        res_auth = self.client.post(
            '/api/assessment/run',
            headers={'Authorization': DEMO_VALID_ADMIN_TOKEN},
            json={'url': f"http://127.0.0.1:{Config.PORT}"}
        )
        self.assertEqual(res_auth.status_code, 200)

        # 2. Invalid Authorization credentials rejected with 401
        res_invalid_auth = self.client.post(
            '/api/assessment/run',
            headers={'Authorization': 'Bearer forged-invalid-token-xyz'},
            json={'url': f"http://127.0.0.1:{Config.PORT}"}
        )
        self.assertEqual(res_invalid_auth.status_code, 401)
        data = json.loads(res_invalid_auth.data)
        self.assertEqual(data.get('error_type'), 'UNAUTHORIZED')

    def test_08_no_external_network_requests_executed(self):
        """Verify that assessment does not make any external network requests."""
        with patch('urllib.request.urlopen') as mock_urlopen, \
             patch('requests.get') as mock_requests_get, \
             patch('requests.post') as mock_requests_post:

            res = self.client.post('/api/assessment/run', json={'url': f"http://127.0.0.1:{Config.PORT}"})
            self.assertEqual(res.status_code, 200)

            # Ensure neither urllib nor requests made any external socket/HTTP connections
            mock_urlopen.assert_not_called()
            mock_requests_get.assert_not_called()
            mock_requests_post.assert_not_called()

    def test_09_ui_route_rendering(self):
        """Verify that the /assessment web page renders HTML properly."""
        res = self.client.get('/assessment')
        self.assertEqual(res.status_code, 200)
        html = res.data.decode('utf-8')
        self.assertIn('Website Security Assessment', html)
        self.assertIn('Fortress Bank Demo Application', html)
        self.assertIn('target-url-input', html)
        self.assertIn('btn-run-assessment', html)

if __name__ == '__main__':
    unittest.main()
