import unittest
import json
from app import create_app
from app.remediation.retester import run_retest_experiment

class TestPhase4(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()

    def test_01_retest_experiment_mitigation(self):
        """Test Before-and-After Retest Experiment produces verified remediation"""
        report = run_retest_experiment(scenario_name='all', client=self.client)
        self.assertIn('comparison', report)
        comp = report['comparison']
        
        # Verify baseline had 0 or low block rate
        self.assertLessEqual(comp['baseline']['block_rate_percent'], 20.0)
        
        # Verify fortified had high block rate (active defense mitigation)
        self.assertGreaterEqual(comp['fortified']['block_rate_percent'], 80.0)
        
        # Verify positive improvement
        self.assertGreater(comp['improvement_percent'], 50.0)
        self.assertEqual(len(report['remediations']), 4)

    def test_02_defense_api_endpoints(self):
        """Test defense management endpoints"""
        # 1. List
        res = self.client.get('/api/defenses')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['count'], 4)

        # 2. Toggle single
        res = self.client.post('/api/defenses/toggle', json={'defense_key': 'rate_limiting', 'is_enabled': True})
        self.assertEqual(res.status_code, 200)

        # 3. Bulk toggle
        res = self.client.post('/api/defenses/bulk-toggle', json={'enable_all': True})
        self.assertEqual(res.status_code, 200)

    def test_03_simulation_and_alert_apis(self):
        """Test simulation trigger and alert triage APIs"""
        # Trigger simulation via API
        res = self.client.post('/api/simulations/run', json={'scenario': 'sql_injection', 'notes': 'API test'})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        run_uuid = data['data']['run_info']['run_uuid']

        # Get simulation details
        res_det = self.client.get(f'/api/simulations/{run_uuid}')
        self.assertEqual(res_det.status_code, 200)

        # List alerts and update status
        res_alerts = self.client.get(f'/api/alerts?simulation_run_id={run_uuid}')
        self.assertEqual(res_alerts.status_code, 200)
        alerts_data = json.loads(res_alerts.data)
        if alerts_data['alerts']:
            aid = alerts_data['alerts'][0]['id']
            res_up = self.client.post(f'/api/alerts/{aid}/status', json={'status': 'ACKNOWLEDGED'})
            self.assertEqual(res_up.status_code, 200)

    def test_04_csv_export_endpoint(self):
        """Test CSV export returns valid CSV content"""
        res = self.client.get('/api/events/export/csv')
        self.assertEqual(res.status_code, 200)
        self.assertIn('text/csv', res.headers.get('Content-Type'))
        content = res.data.decode('utf-8')
        self.assertIn('Event UUID', content)
        self.assertIn('Timestamp', content)

    def test_05_retest_api_endpoint(self):
        """Test POST /api/retest/run endpoint"""
        res = self.client.post('/api/retest/run', json={'scenario': 'all'})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data['status'], 'success')
        self.assertIn('comparison', data['data'])

    def test_06_single_event_endpoint(self):
        """Test GET /api/events/<int:event_id> endpoint for audit event inspection"""
        # Fetch list of events first
        res_list = self.client.get('/api/events?limit=1')
        self.assertEqual(res_list.status_code, 200)
        data_list = json.loads(res_list.data)
        self.assertGreater(data_list['total'], 0)
        eid = data_list['events'][0]['id']

        # Query single event by ID
        res_single = self.client.get(f'/api/events/{eid}')
        self.assertEqual(res_single.status_code, 200)
        data_single = json.loads(res_single.data)
        self.assertEqual(data_single['status'], 'success')
        self.assertEqual(data_single['event']['id'], eid)

        # Non-existent event returns 404
        res_missing = self.client.get('/api/events/99999999')
        self.assertEqual(res_missing.status_code, 404)

if __name__ == '__main__':
    unittest.main()
