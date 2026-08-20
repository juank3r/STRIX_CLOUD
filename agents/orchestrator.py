"""Orchestrator: reads agents.yaml and dispatches connector checks.

It loads connector instances via the plugin loader, validates permissions,
lists resources, and (optionally) runs read-only CSPM-style security checks,
aggregating results into a :class:`~agents.common.findings.Report`.

Everything here is non-destructive. Always verify written authorization
before pointing the orchestrator at real cloud accounts.
"""
import argparse
import sys

import yaml

from agents.common import audit
from agents.common.findings import Report, Severity
from agents.plugins import loader


def _resolve_secrets(config: dict) -> dict:
    """Resolve ``secret:`` references in a connector config in place."""
    for k, v in list(config.items()):
        if isinstance(v, str) and v.startswith("secret:"):
            secret_name = v.split("secret:", 1)[1]
            from agents.common import secrets as _secrets

            cfg_val = _secrets.get_secret(secret_name, env_fallback=secret_name)
            if cfg_val:
                config[k] = cfg_val
    return config


def run_plan(plan_path: str, dry_run: bool = True, security: bool = False) -> Report:
    with open(plan_path, "r", encoding="utf-8") as f:
        plan = yaml.safe_load(f)

    report = Report()

    for repo in plan.get("repositories", []):
        name = repo.get("name")
        provider = repo.get("provider")
        connector_name = repo.get("connector", "azure_connector")
        config = repo.get("connector_config", {})
        audit.audit("orchestrator.start_repo", {"repo": name, "provider": provider})

        try:
            _resolve_secrets(config)

            conn = loader.load_connector(connector_name, config)
            audit.audit("connector.loaded", {"repo": name, "connector": connector_name})
            if not conn.validate_permissions():
                continue

            resources = conn.list_resources()
            audit.audit("resources.listed", {"repo": name, "count": len(resources)})

            if dry_run:
                print(f"[dry-run] {name}: {len(resources)} resources")
                continue

            for r in resources:
                res = conn.run_safe_check(str(r))
                audit.audit("resource.checked", {"repo": name, "resource": r, "result": res})

            if security:
                findings = conn.run_security_checks()
                report.extend(findings)
                audit.audit(
                    "security.checked",
                    {"repo": name, "findings": len(findings), "failures": sum(f.is_failure for f in findings)},
                )
        except Exception as e:
            audit.audit("orchestrator.error", {"repo": name, "error": str(e)})

    return report


def _write_reports(report: Report, report_path: str = None, sarif_path: str = None) -> None:
    if report_path:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report.to_json())
        print(f"Wrote findings report to {report_path}")
    if sarif_path:
        with open(sarif_path, "w", encoding="utf-8") as f:
            f.write(report.to_sarif_json())
        print(f"Wrote SARIF report to {sarif_path}")


def _print_summary(report: Report) -> None:
    summary = report.summary()
    print("Security summary:")
    print(f"  findings: {summary['total']}  failures: {summary['failures']}")
    if summary["by_severity"]:
        parts = ", ".join(f"{k}={v}" for k, v in sorted(summary["by_severity"].items()))
        print(f"  by severity: {parts}")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("plan", help="Path to agents.yaml")
    parser.add_argument("--run", action="store_true", help="Execute checks (not dry-run)")
    parser.add_argument("--security", action="store_true", help="Run read-only security (CSPM) checks")
    parser.add_argument("--report", metavar="PATH", help="Write findings JSON to PATH")
    parser.add_argument("--sarif", metavar="PATH", help="Write SARIF 2.1.0 to PATH")
    parser.add_argument(
        "--fail-on",
        metavar="SEVERITY",
        help="Exit non-zero if any failure at or above this severity (e.g. HIGH)",
    )
    args = parser.parse_args(argv)

    report = run_plan(args.plan, dry_run=not args.run, security=args.security)

    if args.security:
        _print_summary(report)
        _write_reports(report, report_path=args.report, sarif_path=args.sarif)

        if args.fail_on:
            threshold = Severity.from_name(args.fail_on)
            highest = report.highest_severity()
            if highest is not None and highest >= threshold:
                print(f"Failing: highest severity {highest.name} >= {threshold.name}")
                return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
