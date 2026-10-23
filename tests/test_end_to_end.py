import unittest
from app import create_app

class TestEndToEnd(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()

    def test_01_ui_pages_render(self):
        """Verify that all CyberFortify web dashboard views render with HTTP 200"""
        pages = ['/', '/simulations', '/alerts', '/logs', '/defenses', '/report']
        for p in pages:
            res = self.client.get(p)
            self.assertEqual(res.status_code, 200, f"Page {p} failed to render")
            self.assertIn(b'CyberFortify', res.data)

    def test_02_static_assets_serve(self):
        """Verify that CSS and JS frontend controllers are served properly"""
        assets = [
            '/static/css/style.css',
            '/static/js/dashboard.js',
            '/static/js/simulations.js',
            '/static/js/alerts.js',
            '/static/js/logs.js',
            '/static/js/defenses.js'
        ]
        for a in assets:
            res = self.client.get(a)
            self.assertEqual(res.status_code, 200, f"Static asset {a} failed to serve")
            res.close()

    def test_03_full_operational_lifecycle(self):
        """Verify complete lifecycle: Red Team attack -> Blue Team detect -> Evaluate -> Retest"""
        # 1. Trigger simulation
        sim_res = self.client.post('/api/simulations/run', json={'scenario': 'all', 'notes': 'E2E Lifecycle Test'})
        self.assertEqual(sim_res.status_code, 200)

        # 2. Query KPIs
        eval_res = self.client.get('/api/evaluations/overall')
        self.assertEqual(eval_res.status_code, 200)
        metrics = eval_res.json['metrics']
        self.assertGreater(metrics['total_runs'], 0)
        self.assertGreater(metrics['total_attacks'], 0)
        self.assertGreater(metrics['total_alerts'], 0)

        # 3. Query alerts
        alert_res = self.client.get('/api/alerts')
        self.assertEqual(alert_res.status_code, 200)
        self.assertGreater(alert_res.json['total'], 0)

        # 4. Trigger Retest Experiment
        retest_res = self.client.post('/api/retest/run', json={'scenario': 'all'})
        self.assertEqual(retest_res.status_code, 200)
        self.assertIn('comparison', retest_res.json['data'])

        # 5. Export CSV
        csv_res = self.client.get('/api/events/export/csv')
        self.assertEqual(csv_res.status_code, 200)
        self.assertIn('text/csv', csv_res.headers.get('Content-Type'))

if __name__ == '__main__':
    unittest.main()
