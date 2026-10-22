import time
import requests
from app.config import Config
from app.red_team.payloads import (
    BRUTE_FORCE_CREDENTIALS,
    UNAUTHORIZED_ACCESS_PROBES,
    SQL_INJECTION_PROBES,
    INPUT_VALIDATION_PROBES,
    BENIGN_ACTIVITY
)

def send_test_request(method, path, run_uuid, scenario_name, is_attack, expected_rule,
                      json_data=None, params=None, headers=None, base_url=None, client=None):
    """
    Sends a test request using either Flask test_client or requests.Session.
    Captures status code, response time, and payload tracking.
    """
    if headers is None:
        headers = {}

    headers['X-Simulation-Run-ID'] = run_uuid
    headers['X-Simulation-Scenario'] = scenario_name
    headers['X-Simulation-Is-Attack'] = '1' if is_attack else '0'
    if expected_rule:
        headers['X-Simulation-Expected-Rule'] = expected_rule

    start_time = time.time()

    if client:
        # Internal execution via Flask test_client
        if method.upper() == 'GET':
            res = client.get(path, query_string=params, headers=headers)
        elif method.upper() == 'POST':
            res = client.post(path, json=json_data, headers=headers)
        status_code = res.status_code
        try:
            body = res.get_json()
        except Exception:
            body = res.data.decode('utf-8', errors='ignore')
    else:
        # Network execution via requests against local server
        if not base_url:
            base_url = f"http://{Config.HOST}:{Config.PORT}"
        full_url = f"{base_url}{path}"
        if method.upper() == 'GET':
            res = requests.get(full_url, params=params, headers=headers, timeout=5)
        elif method.upper() == 'POST':
            res = requests.post(full_url, json=json_data, headers=headers, timeout=5)
        status_code = res.status_code
        try:
            body = res.json()
        except Exception:
            body = res.text

    latency_ms = round((time.time() - start_time) * 1000, 2)
    return {
        'status_code': status_code,
        'latency_ms': latency_ms,
        'body': body,
        'is_attack': is_attack,
        'expected_rule': expected_rule
    }

def run_brute_force_scenario(run_uuid, base_url=None, client=None):
    """Scenario 1: Repeated failed login attempts against demo target app."""
    scenario_name = 'brute_force'
    results = []

    for item in BRUTE_FORCE_CREDENTIALS:
        res = send_test_request(
            method='POST',
            path='/api/target/login',
            run_uuid=run_uuid,
            scenario_name=scenario_name,
            is_attack=item['is_attack'],
            expected_rule=item['expected_rule'],
            json_data={'username': item['username'], 'password': item['password']},
            base_url=base_url,
            client=client
        )
        res['username'] = item['username']
        results.append(res)
        time.sleep(0.05)  # brief burst pause

    return results

def run_unauthorized_access_scenario(run_uuid, base_url=None, client=None):
    """Scenario 2: Unauthorized access / forced browsing to protected demo resource."""
    scenario_name = 'unauthorized_access'
    results = []

    for item in UNAUTHORIZED_ACCESS_PROBES:
        res = send_test_request(
            method='GET',
            path=item['endpoint'],
            run_uuid=run_uuid,
            scenario_name=scenario_name,
            is_attack=item['is_attack'],
            expected_rule=item['expected_rule'],
            headers=dict(item['headers']),
            base_url=base_url,
            client=client
        )
        res['description'] = item['description']
        results.append(res)
        time.sleep(0.05)

    return results

def run_sql_injection_scenario(run_uuid, base_url=None, client=None):
    """Scenario 3: Harmless SQL injection test inputs."""
    scenario_name = 'sql_injection'
    results = []

    for item in SQL_INJECTION_PROBES:
        res = send_test_request(
            method='GET',
            path='/api/target/search',
            run_uuid=run_uuid,
            scenario_name=scenario_name,
            is_attack=item['is_attack'],
            expected_rule=item['expected_rule'],
            params={'q': item['query']},
            base_url=base_url,
            client=client
        )
        res['query'] = item['query']
        res['description'] = item['description']
        results.append(res)
        time.sleep(0.05)

    return results

def run_input_validation_scenario(run_uuid, base_url=None, client=None):
    """Scenario 4: Input validation / safe script tag probe tests."""
    scenario_name = 'input_validation'
    results = []

    for item in INPUT_VALIDATION_PROBES:
        res = send_test_request(
            method='POST',
            path='/api/target/feedback',
            run_uuid=run_uuid,
            scenario_name=scenario_name,
            is_attack=item['is_attack'],
            expected_rule=item['expected_rule'],
            json_data={'author': item['author'], 'content': item['content']},
            base_url=base_url,
            client=client
        )
        res['payload'] = item['content']
        res['description'] = item['description']
        results.append(res)
        time.sleep(0.05)

    return results

def run_benign_traffic_scenario(run_uuid, base_url=None, client=None):
    """Benign Traffic: Normal browsing, clean searches, and authorized actions."""
    scenario_name = 'benign'
    results = []

    for item in BENIGN_ACTIVITY:
        if item['type'] == 'search':
            res = send_test_request(
                method='GET',
                path='/api/target/search',
                run_uuid=run_uuid,
                scenario_name=scenario_name,
                is_attack=False,
                expected_rule=None,
                params={'q': item['query']},
                base_url=base_url,
                client=client
            )
        elif item['type'] == 'feedback':
            res = send_test_request(
                method='POST',
                path='/api/target/feedback',
                run_uuid=run_uuid,
                scenario_name=scenario_name,
                is_attack=False,
                expected_rule=None,
                json_data={'author': item['author'], 'content': item['content']},
                base_url=base_url,
                client=client
            )
        elif item['type'] == 'login':
            res = send_test_request(
                method='POST',
                path='/api/target/login',
                run_uuid=run_uuid,
                scenario_name=scenario_name,
                is_attack=False,
                expected_rule=None,
                json_data={'username': item['username'], 'password': item['password']},
                base_url=base_url,
                client=client
            )
        res['description'] = item['description']
        results.append(res)
        time.sleep(0.05)

    return results
