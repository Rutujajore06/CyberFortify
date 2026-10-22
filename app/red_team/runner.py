from app.models.defense_model import get_defense_snapshot
from app.models.simulation_model import (
    create_simulation_run,
    update_simulation_run,
    get_simulation_run
)
from app.red_team.scenarios import (
    run_brute_force_scenario,
    run_unauthorized_access_scenario,
    run_sql_injection_scenario,
    run_input_validation_scenario,
    run_benign_traffic_scenario
)

def execute_simulation(scenario_name, target_base_url=None, client=None, notes=None):
    """
    Executes a security simulation run, collects telemetry,
    triggers Blue Team detection rules, and computes evaluation metrics.
    """
    defense_snapshot = get_defense_snapshot()
    run_uuid = create_simulation_run(
        scenario_name=scenario_name,
        defense_config_snapshot=defense_snapshot,
        notes=notes
    )

    all_results = []

    if scenario_name == 'brute_force':
        all_results = run_brute_force_scenario(run_uuid, base_url=target_base_url, client=client)
    elif scenario_name == 'unauthorized_access':
        all_results = run_unauthorized_access_scenario(run_uuid, base_url=target_base_url, client=client)
    elif scenario_name == 'sql_injection':
        all_results = run_sql_injection_scenario(run_uuid, base_url=target_base_url, client=client)
    elif scenario_name == 'input_validation':
        all_results = run_input_validation_scenario(run_uuid, base_url=target_base_url, client=client)
    elif scenario_name == 'benign':
        all_results = run_benign_traffic_scenario(run_uuid, base_url=target_base_url, client=client)
    elif scenario_name in ('all', 'battery', 'full'):
        # Comprehensive test battery: all attacks + benign baseline
        all_results.extend(run_brute_force_scenario(run_uuid, base_url=target_base_url, client=client))
        all_results.extend(run_unauthorized_access_scenario(run_uuid, base_url=target_base_url, client=client))
        all_results.extend(run_sql_injection_scenario(run_uuid, base_url=target_base_url, client=client))
        all_results.extend(run_input_validation_scenario(run_uuid, base_url=target_base_url, client=client))
        all_results.extend(run_benign_traffic_scenario(run_uuid, base_url=target_base_url, client=client))
    else:
        raise ValueError(f"Unknown scenario name: {scenario_name}")

    total_requests = len(all_results)
    attack_requests = sum(1 for r in all_results if r.get('is_attack'))
    benign_requests = total_requests - attack_requests

    # Count requests actively blocked by defense (429 Too Many Requests, 403 Forbidden, 400 Bad Request)
    blocked_by_defense = sum(
        1 for r in all_results 
        if r.get('is_attack') and r.get('status_code') in (429, 403, 400)
    )

    update_simulation_run(
        run_uuid=run_uuid,
        total_requests=total_requests,
        attack_requests=attack_requests,
        benign_requests=benign_requests,
        blocked_by_defense=blocked_by_defense,
        notes=notes
    )

    # Trigger Blue Team detection & evaluation
    from app.blue_team.detector import run_detection_pipeline
    from app.blue_team.evaluator import evaluate_simulation_run

    alerts = run_detection_pipeline(simulation_run_id=run_uuid)
    evaluation = evaluate_simulation_run(simulation_run_id=run_uuid)

    run_info = get_simulation_run(run_uuid)

    return {
        'run_info': run_info,
        'results_count': total_requests,
        'attack_count': attack_requests,
        'benign_count': benign_requests,
        'blocked_count': blocked_by_defense,
        'alerts_generated': alerts,
        'evaluation': evaluation
    }
