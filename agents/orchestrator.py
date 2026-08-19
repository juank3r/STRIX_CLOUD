"""Orchestrator prototype: reads agents.yaml and dispatches connector checks.

This prototype is intentionally simple: it shows how to load connector
instances via the plugin loader, validate permissions, list resources and
run safe checks. Use with care and always verify authorization.
"""
import yaml
import argparse
from agents.plugins import loader
from agents.common import audit


def run_plan(plan_path: str, dry_run: bool = True):
    with open(plan_path, 'r', encoding='utf-8') as f:
        plan = yaml.safe_load(f)

    for repo in plan.get('repositories', []):
        name = repo.get('name')
        provider = repo.get('provider')
        connector_name = repo.get('connector', 'azure_connector')
        config = repo.get('connector_config', {})
        audit.audit('orchestrator.start_repo', {'repo': name, 'provider': provider})

        try:
            conn = loader.load_connector(connector_name, config)
            audit.audit('connector.loaded', {'repo': name, 'connector': connector_name})
            if conn.validate_permissions():
                resources = conn.list_resources()
                audit.audit('resources.listed', {'repo': name, 'count': len(resources)})
                if not dry_run:
                    for r in resources:
                        res = conn.run_safe_check(str(r))
                        audit.audit('resource.checked', {'repo': name, 'resource': r, 'result': res})
                else:
                    print(f"[dry-run] {name}: {len(resources)} resources")
        except Exception as e:
            audit.audit('orchestrator.error', {'repo': name, 'error': str(e)})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('plan', help='Path to agents.yaml')
    parser.add_argument('--run', action='store_true', help='Execute checks (not dry-run)')
    args = parser.parse_args()
    run_plan(args.plan, dry_run=not args.run)


if __name__ == '__main__':
    main()
