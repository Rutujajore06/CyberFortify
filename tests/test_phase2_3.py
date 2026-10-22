import unittest
from app import create_app
from app.models.defense_model import set_defense_state
from app.red_team.runner import execute_simulation
from app.models.alert_model import get_alerts_by_simulation
from app.models.simulation_model import get_simulation_run, get_latest_evaluation

class TestPhase2And3(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()

    def test_01_sql_injection_simulation_and_detection(self):
        """Test SQL injection simulation execution and Blue team alert generation"""
        # Ensure defenses are in vulnerable baseline for baseline detection testing
        set_defense_state('parameterized_queries', False)

        result = execute_simulation('sql_injection', client=self.client, notes='Unit test SQL injection')
        self.assertIsNotNone(result['run_info'])
        run_uuid = result['run_info']['run_uuid']

        # Verify alerts were generated for SQL injection
        alerts = get_alerts_by_simulation(run_uuid)
        self.assertGreater(len(alerts), 0)
        self.assertTrue(any(a['rule_id'] == 'RULE_SQLI_DETECTED_01' for a in alerts))

        # Verify evaluation metrics
        evaluation = result['evaluation']
        self.assertGreater(evaluation['true_positives'], 0)
        self.assertGreater(evaluation['detection_rate'], 50.0)
        self.assertGreaterEqual(evaluation['avg_latency_ms'], 0.0)

    def test_02_brute_force_simulation_and_detection(self):
        """Test Brute Force credential simulation and threshold alert generation"""
        result = execute_simulation('brute_force', client=self.client, notes='Unit test Brute Force')
        run_uuid = result['run_info']['run_uuid']
        alerts = get_alerts_by_simulation(run_uuid)
        self.assertTrue(any(a['rule_id'] == 'RULE_BRUTE_FORCE_01' for a in alerts))

    def test_03_unauthorized_access_simulation(self):
        """Test Broken Access Control simulation and alert generation"""
        result = execute_simulation('unauthorized_access', client=self.client, notes='Unit test Unauthorized Access')
        run_uuid = result['run_info']['run_uuid']
        alerts = get_alerts_by_simulation(run_uuid)
        self.assertTrue(any(a['rule_id'] == 'RULE_UNAUTHORIZED_ACCESS_01' for a in alerts))

    def test_04_input_validation_simulation(self):
        """Test XSS / Input validation simulation and alert generation"""
        result = execute_simulation('input_validation', client=self.client, notes='Unit test Input Validation')
        run_uuid = result['run_info']['run_uuid']
        alerts = get_alerts_by_simulation(run_uuid)
        self.assertTrue(any(a['rule_id'] == 'RULE_XSS_INPUT_01' for a in alerts))

    def test_05_benign_traffic_no_false_positives(self):
        """Test Benign traffic produces zero false positives"""
        result = execute_simulation('benign', client=self.client, notes='Unit test Benign')
        evaluation = result['evaluation']
        self.assertEqual(evaluation['false_positives'], 0)
        self.assertGreater(evaluation['true_negatives'], 0)

    def test_06_comprehensive_battery(self):
        """Test full battery execution with all 4 attacks + benign baseline"""
        result = execute_simulation('all', client=self.client, notes='Full battery test')
        run_uuid = result['run_info']['run_uuid']
        evaluation = result['evaluation']

        self.assertGreater(result['attack_count'], 10)
        self.assertGreater(result['benign_count'], 0)
        self.assertGreater(evaluation['detection_rate'], 80.0)
        self.assertGreater(evaluation['f1_score'], 0.8)

if __name__ == '__main__':
    unittest.main()
