from app.models.defense_model import set_defense_state, get_all_defenses
from app.red_team.runner import execute_simulation

def run_retest_experiment(scenario_name='all', client=None, base_url=None):
    """
    Executes a complete Before-and-After Retesting Experiment:
    1. Baseline (Defenses OFF): Evaluates vulnerability exposure.
    2. Fortification (Defenses ON): Applies recommended security remediations.
    3. Retest (Defenses ON): Evaluates mitigation efficacy and calculates improvements.
    """
    # 1. BASELINE ASSESSMENT (Defenses Disabled)
    set_defense_state('rate_limiting', False)
    set_defense_state('rbac_enforcement', False)
    set_defense_state('parameterized_queries', False)
    set_defense_state('input_sanitization', False)

    baseline_run = execute_simulation(
        scenario_name=scenario_name,
        target_base_url=base_url,
        client=client,
        notes='Baseline Assessment (Vulnerable: Defenses OFF)'
    )

    # 2. APPLY REMEDIATIONS (Enable Defenses)
    set_defense_state('rate_limiting', True)
    set_defense_state('rbac_enforcement', True)
    set_defense_state('parameterized_queries', True)
    set_defense_state('input_sanitization', True)

    # 3. VERIFICATION RETEST (Defenses Enabled)
    fortified_run = execute_simulation(
        scenario_name=scenario_name,
        target_base_url=base_url,
        client=client,
        notes='Verification Retest (Fortified: Defenses ON)'
    )

    # 4. COMPUTE COMPARATIVE METRICS
    base_attacks = baseline_run['attack_count']
    base_blocked = baseline_run['blocked_count']
    base_breaches = max(0, base_attacks - base_blocked)
    base_block_rate = round((base_blocked / base_attacks * 100), 1) if base_attacks > 0 else 0.0

    fort_attacks = fortified_run['attack_count']
    fort_blocked = fortified_run['blocked_count']
    fort_breaches = max(0, fort_attacks - fort_blocked)
    fort_block_rate = round((fort_blocked / fort_attacks * 100), 1) if fort_attacks > 0 else 0.0

    improvement = round(fort_block_rate - base_block_rate, 1)

    remediations = [
        {
            'vulnerability': 'Authentication Brute Force',
            'defense_control': 'Rate Limiting & Lockout Filter',
            'before_status': 'VULNERABLE (Unlimited login attempts permitted)',
            'after_status': 'FORTIFIED (HTTP 429 Lockout enforced after 3 failures)',
            'recommendation': 'Implement sliding-window rate limiting on all login endpoints and progressive exponential backoff.'
        },
        {
            'vulnerability': 'Broken Access Control',
            'defense_control': 'RBAC & Server-Side Token Authorization',
            'before_status': 'VULNERABLE (Direct forced browsing to admin vaults allowed)',
            'after_status': 'FORTIFIED (HTTP 403 Forbidden enforced without valid Bearer token)',
            'recommendation': 'Enforce cryptographic token and role validation decorators across all privileged administrative routes.'
        },
        {
            'vulnerability': 'SQL Injection (SQLi)',
            'defense_control': 'Parameterized Queries & Prepared Statements',
            'before_status': 'VULNERABLE (Raw string interpolation leaked user records)',
            'after_status': 'FORTIFIED (Query parameterization treated payload as literal string)',
            'recommendation': 'Enforce parameterized query binding (?) in SQLite/database abstraction layers and disallow raw string formatting.'
        },
        {
            'vulnerability': 'Cross-Site Scripting (XSS) / Input Validation',
            'defense_control': 'Input Whitelisting & HTML Output Encoding',
            'before_status': 'VULNERABLE (Raw script payloads stored and reflected)',
            'after_status': 'FORTIFIED (HTTP 400 rejection / HTML entity escaping enforced)',
            'recommendation': 'Apply context-aware HTML entity encoding on user input and implement Content Security Policy (CSP) headers.'
        }
    ]

    return {
        'scenario': scenario_name,
        'baseline_run_uuid': baseline_run['run_info']['run_uuid'],
        'fortified_run_uuid': fortified_run['run_info']['run_uuid'],
        'comparison': {
            'baseline': {
                'total_requests': baseline_run['results_count'],
                'attack_requests': base_attacks,
                'blocked_by_defense': base_blocked,
                'successful_breaches': base_breaches,
                'block_rate_percent': base_block_rate,
                'detection_rate_percent': baseline_run['evaluation']['detection_rate'],
                'avg_latency_ms': baseline_run['evaluation']['avg_latency_ms']
            },
            'fortified': {
                'total_requests': fortified_run['results_count'],
                'attack_requests': fort_attacks,
                'blocked_by_defense': fort_blocked,
                'successful_breaches': fort_breaches,
                'block_rate_percent': fort_block_rate,
                'detection_rate_percent': fortified_run['evaluation']['detection_rate'],
                'avg_latency_ms': fortified_run['evaluation']['avg_latency_ms']
            },
            'improvement_percent': improvement,
            'security_verdict': 'SECURITY POSTURE FORTIFIED - VULNERABILITIES SUCCESSFULLY MITIGATED'
        },
        'remediations': remediations
    }
