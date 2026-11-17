import unittest
import json
import datetime
from unittest.mock import patch

from app import create_app
from app.database import get_db_connection
from app.models.live_target_model import (
    get_live_assessment_by_uuid,
    get_live_audit_logs,
    utc_now
)
from app.live_testing.security import rate_limiter


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


def _make_mock_http(https_headers, set_cookies=None):
    def _mock_request(url, target, method='GET', follow_redirects=False, **kwargs):
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
            'headers': dict(https_headers),
            'raw_headers': list(https_headers.items()),
            'set_cookies': list(set_cookies or []),
            'body': b'<html><body>OK</body></html>',
            'resolved_ip': '93.184.216.34',
            'redirect_chain': [],
            'tls_info': {'version': 'TLSv1.3'}
        }
    return _mock_request


class TestLiveRemediationAndRetesting(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        rate_limiter.reset()

    def _create_approved_target(self, domain='remediate-test.example.org'):
        now = utc_now()
        reg = self.client.post('/api/live/targets', json={
            'target_url': f'https://{domain}/',
            'owner_name': 'Site Owner',
            'owner_email': f'owner@{domain}',
            'owner_consent': True,
            'verification_method': 'signed_attestation',
            'approved_paths': ['/'],
            'allowed_methods': ['GET'],
            'start_date': (now - datetime.timedelta(minutes=5)).isoformat(),
            'expiry_date': (now + datetime.timedelta(days=5)).isoformat(),
            'max_request_rate': 60
        })
        self.assertEqual(reg.status_code, 201, reg.data)
        target = reg.json['target']

        ver = self.client.post(
            f"/api/live/targets/{target['target_uuid']}/verify",
            json={'verification_token': target['verification_token']}
        )
        self.assertEqual(ver.status_code, 200, ver.data)

        app_res = self.client.post(
            f"/api/live/targets/{target['target_uuid']}/approve",
            json={'approved_by': 'admin'}
        )
        self.assertEqual(app_res.status_code, 200, app_res.data)
        return app_res.json['target']

    def test_01_remediation_tracking_notes_and_strict_retest_gate(self):
        """Tests remediation sync, affected headers, notes, and blocking manual Fixed/Verified without retest."""
        target = self._create_approved_target('rem-gate.example.org')
        tuuid = target['target_uuid']

        # Baseline scan: missing CSP, Referrer-Policy, Permissions-Policy; wildcard CORS
        baseline_headers = {
            'strict-transport-security': 'max-age=63072000; includeSubDomains',
            'x-content-type-options': 'nosniff',
            'x-frame-options': 'DENY',
            'server': 'Vercel',
            'access-control-allow-origin': '*'
        }
        with patch('app.live_testing.scanner.inspect_tls_certificate', return_value=_mock_tls()), \
             patch('app.live_testing.scanner.safe_http_request', side_effect=_make_mock_http(baseline_headers)):
            scan_res = self.client.post('/api/live/assessments/run', json={'target_uuid': tuuid})
            self.assertEqual(scan_res.status_code, 200)
            baseline_assess = scan_res.json['assessment']
            self.assertEqual(baseline_assess['security_score'], 80)

        # Fetch remediations -> 4 Open items with affected headers & instructions
        rem_res = self.client.get(f'/api/live/remediations?target_uuid={tuuid}')
        self.assertEqual(rem_res.status_code, 200)
        summary = rem_res.json['summary']
        self.assertEqual(summary['open'], 4)
        self.assertEqual(summary['fixed'], 0)
        self.assertEqual(summary['verified'], 0)

        by_key = {r['check_key']: r for r in rem_res.json['remediations']}
        self.assertEqual(by_key['header_csp']['affected_header'], 'Content-Security-Policy')
        self.assertEqual(by_key['header_referrer_policy']['affected_header'], 'Referrer-Policy')
        self.assertTrue(len(by_key['header_csp']['remediation_instructions']) > 20)

        csp_uuid = by_key['header_csp']['remediation_uuid']

        # Owner can update status to 'In Progress' and record notes
        upd_ok = self.client.patch(f'/api/live/remediations/{csp_uuid}', json={
            'remediation_status': 'In Progress',
            'remediation_notes': 'Adding Content-Security-Policy header in vercel.json'
        })
        self.assertEqual(upd_ok.status_code, 200)
        self.assertEqual(upd_ok.json['remediation']['remediation_status'], 'In Progress')
        self.assertIn('vercel.json', upd_ok.json['remediation']['remediation_notes'])

        # Owner CANNOT manually mark Fixed or Verified without a passing retest
        for forbidden_status in ('Fixed', 'Verified'):
            bad = self.client.patch(f'/api/live/remediations/{csp_uuid}', json={
                'remediation_status': forbidden_status
            })
            self.assertEqual(bad.status_code, 400)
            self.assertEqual(bad.json['error_type'], 'RETEST_REQUIRED')

        # Audit log recorded manual fix block
        logs = get_live_audit_logs(limit=20, target_uuid=tuuid)
        self.assertTrue(any(l['action'] == 'REMEDIATION_MANUAL_FIX_BLOCKED' for l in logs))

    def test_02_live_retest_comparison_fixed_verified_and_regression(self):
        """Tests full retest lifecycle: Before/After scores, Fixed -> Verified, history preservation, and regression."""
        target = self._create_approved_target('rem-retest.example.org')
        tuuid = target['target_uuid']

        # 1. Baseline assessment (Score 80: missing CSP, Referrer-Policy, Permissions-Policy, wildcard CORS)
        baseline_headers = {
            'strict-transport-security': 'max-age=63072000; includeSubDomains',
            'x-content-type-options': 'nosniff',
            'x-frame-options': 'DENY',
            'server': 'Vercel',
            'access-control-allow-origin': '*'
        }
        with patch('app.live_testing.scanner.inspect_tls_certificate', return_value=_mock_tls()), \
             patch('app.live_testing.scanner.safe_http_request', side_effect=_make_mock_http(baseline_headers)):
            base_res = self.client.post('/api/live/assessments/run', json={'target_uuid': tuuid})
            self.assertEqual(base_res.status_code, 200)
            baseline_uuid = base_res.json['assessment']['assessment_uuid']
            baseline_score = base_res.json['assessment']['security_score']

        # 2. Owner adds CSP and Referrer-Policy on their website, leaves Permissions-Policy & CORS open -> Retest #1
        improved_headers = {
            'strict-transport-security': 'max-age=63072000; includeSubDomains',
            'x-content-type-options': 'nosniff',
            'x-frame-options': 'DENY',
            'content-security-policy': "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
            'referrer-policy': 'strict-origin-when-cross-origin',
            'server': 'Vercel',
            'access-control-allow-origin': '*'
        }
        with patch('app.live_testing.scanner.inspect_tls_certificate', return_value=_mock_tls()), \
             patch('app.live_testing.scanner.safe_http_request', side_effect=_make_mock_http(improved_headers)):
            retest1 = self.client.post('/api/live/retest/run', json={'target_uuid': tuuid})
            self.assertEqual(retest1.status_code, 200, retest1.data)
            data1 = retest1.json['data']
            cmp1 = data1['comparison']

            # Verify before-and-after score improvement (80 -> 98, delta +18)
            self.assertTrue(cmp1['has_previous'])
            self.assertEqual(cmp1['before']['assessment_uuid'], baseline_uuid)
            self.assertEqual(cmp1['before']['security_score'], baseline_score)
            self.assertGreater(cmp1['after']['security_score'], baseline_score)
            self.assertEqual(cmp1['score_delta'], cmp1['after']['security_score'] - baseline_score)
            self.assertEqual(cmp1['verdict'], 'SECURITY_POSTURE_IMPROVED')

            fixed_keys = {f['check_key'] for f in cmp1['fixed_vulnerabilities']}
            rem_keys = {f['check_key'] for f in cmp1['remaining_vulnerabilities']}
            self.assertEqual(fixed_keys, {'header_csp', 'header_referrer_policy'})
            self.assertEqual(rem_keys, {'config_permissions_policy', 'config_cors_policy'})

            # Fixed items automatically promoted to 'Fixed' with retest_confirmed=True
            rems1 = {r['check_key']: r for r in data1['remediations']}
            self.assertEqual(rems1['header_csp']['remediation_status'], 'Fixed')
            self.assertTrue(rems1['header_csp']['retest_confirmed'])
            self.assertEqual(rems1['config_permissions_policy']['remediation_status'], 'Open')

        # 3. After passing retest, owner can confirm 'Verified' on a retest-confirmed item
        csp_rem_uuid = rems1['header_csp']['remediation_uuid']
        ver_upd = self.client.patch(f'/api/live/remediations/{csp_rem_uuid}', json={
            'remediation_status': 'Verified',
            'remediation_notes': 'Confirmed via retest.'
        })
        self.assertEqual(ver_upd.status_code, 200)
        self.assertEqual(ver_upd.json['remediation']['remediation_status'], 'Verified')

        # 4. Second confirmation retest automatically promotes remaining 'Fixed' item (header_referrer_policy) -> 'Verified'
        with patch('app.live_testing.scanner.inspect_tls_certificate', return_value=_mock_tls()), \
             patch('app.live_testing.scanner.safe_http_request', side_effect=_make_mock_http(improved_headers)):
            retest2 = self.client.post('/api/live/retest/run', json={'target_uuid': tuuid})
            self.assertEqual(retest2.status_code, 200)
            rems2 = {r['check_key']: r for r in retest2.json['data']['remediations']}
            self.assertEqual(rems2['header_referrer_policy']['remediation_status'], 'Verified')

        # 5. Regression test: CSP removed again -> automatically reopens to 'Open'
        regressed_headers = dict(improved_headers)
        del regressed_headers['content-security-policy']
        with patch('app.live_testing.scanner.inspect_tls_certificate', return_value=_mock_tls()), \
             patch('app.live_testing.scanner.safe_http_request', side_effect=_make_mock_http(regressed_headers)):
            retest3 = self.client.post('/api/live/retest/run', json={'target_uuid': tuuid})
            self.assertEqual(retest3.status_code, 200)
            cmp3 = retest3.json['data']['comparison']
            self.assertEqual(cmp3['verdict'], 'SECURITY_POSTURE_REGRESSED')
            self.assertLess(cmp3['score_delta'], 0)
            new_keys = {f['check_key'] for f in cmp3['new_vulnerabilities']}
            self.assertIn('header_csp', new_keys)
            rems3 = {r['check_key']: r for r in retest3.json['data']['remediations']}
            self.assertEqual(rems3['header_csp']['remediation_status'], 'Open')
            self.assertFalse(rems3['header_csp']['retest_confirmed'])

        # 6. Original baseline assessment record & audit logs remain completely preserved
        orig = get_live_assessment_by_uuid(baseline_uuid)
        self.assertIsNotNone(orig)
        self.assertEqual(orig['security_score'], baseline_score)
        hist = self.client.get(f'/api/live/assessments?target_uuid={tuuid}')
        self.assertEqual(hist.json['count'], 4)

    def test_03_compare_endpoint_and_downloadable_reports(self):
        """Tests comparison API and downloadable HTML, Markdown, and JSON reports + UI routes."""
        target = self._create_approved_target('rem-report.example.org')
        tuuid = target['target_uuid']

        h1 = {
            'strict-transport-security': 'max-age=63072000',
            'x-content-type-options': 'nosniff',
            'x-frame-options': 'DENY'
        }
        h2 = dict(h1, **{
            'content-security-policy': "default-src 'self'",
            'referrer-policy': 'no-referrer',
            'permissions-policy': 'geolocation=()'
        })

        with patch('app.live_testing.scanner.inspect_tls_certificate', return_value=_mock_tls()), \
             patch('app.live_testing.scanner.safe_http_request', side_effect=_make_mock_http(h1)):
            r1 = self.client.post('/api/live/assessments/run', json={'target_uuid': tuuid})
            self.assertEqual(r1.status_code, 200)

        with patch('app.live_testing.scanner.inspect_tls_certificate', return_value=_mock_tls()), \
             patch('app.live_testing.scanner.safe_http_request', side_effect=_make_mock_http(h2)):
            r2 = self.client.post('/api/live/retest/run', json={'target_uuid': tuuid})
            self.assertEqual(r2.status_code, 200)
            latest_uuid = r2.json['data']['latest_assessment']['assessment_uuid']

        # Compare endpoint
        cmp_res = self.client.get(f'/api/live/assessments/compare?target_uuid={tuuid}')
        self.assertEqual(cmp_res.status_code, 200)
        self.assertTrue(cmp_res.json['has_assessments'])
        self.assertEqual(cmp_res.json['comparison']['verdict'], 'ALL_VULNERABILITIES_REMEDIATED')

        # Downloadable HTML report (must NOT expose sensitive verification_token)
        token_bytes = target['verification_token'].encode('utf-8')
        html_res = self.client.get(f'/api/live/assessments/{latest_uuid}/report?format=html')
        self.assertEqual(html_res.status_code, 200)
        self.assertIn('attachment;', html_res.headers.get('Content-Disposition', ''))
        self.assertIn(b'Before-and-After Retest Comparison', html_res.data)
        self.assertIn(b'Content-Security-Policy', html_res.data)
        self.assertNotIn(token_bytes, html_res.data)

        # Downloadable Markdown report (must NOT expose sensitive verification_token)
        md_res = self.client.get(f'/api/live/assessments/{latest_uuid}/report?format=md')
        self.assertEqual(md_res.status_code, 200)
        self.assertIn('attachment;', md_res.headers.get('Content-Disposition', ''))
        self.assertIn(b'# CyberFortify Live Security Assessment Report', md_res.data)
        self.assertNotIn(token_bytes, md_res.data)

        # Downloadable JSON report (must NOT expose sensitive verification_token)
        json_res = self.client.get(f'/api/live/assessments/{latest_uuid}/report?format=json')
        self.assertEqual(json_res.status_code, 200)
        self.assertIn('attachment;', json_res.headers.get('Content-Disposition', ''))
        self.assertNotIn(token_bytes, json_res.data)
        parsed = json.loads(json_res.data)
        self.assertEqual(parsed['assessment']['assessment_uuid'], latest_uuid)
        self.assertNotIn('verification_token', parsed.get('target') or {})
        self.assertIn('comparison', parsed)
        self.assertIn('remediations', parsed)

        # Expired target cannot be retested
        conn = get_db_connection()
        conn.execute(
            'UPDATE live_targets SET expiry_date = ? WHERE target_uuid = ?',
            ((utc_now() - datetime.timedelta(minutes=5)).isoformat(), tuuid)
        )
        conn.commit()
        conn.close()
        exp_retest = self.client.post('/api/live/retest/run', json={'target_uuid': tuuid})
        self.assertEqual(exp_retest.status_code, 403)
        self.assertEqual(exp_retest.json['error_type'], 'AUTHORIZATION_EXPIRED')

        # UI route & static JS serve cleanly
        for route in ('/live-remediation', '/static/js/live_remediation.js'):
            r = self.client.get(route)
            self.assertEqual(r.status_code, 200, f"Route {route} failed")
            r.close()


if __name__ == '__main__':
    unittest.main()
