# Orchestrator

This document describes the Orchestrator prototype included in `agents/orchestrator.py`.

Overview
--------

The Orchestrator reads a plan file (`agents.yaml`) with repository/target definitions,
loads the appropriate connector via the plugin loader and performs safe, read-only
checks against discovered resources.

Quickstart
----------

0. Install the package: `pip install -e .[azure]` (exposes the `strix-cloud` command).
1. Ensure you have authenticated to Azure with `az login` (if using Azure connectors).
2. Adjust `examples/agents.yaml` to list your repositories/targets.
3. Dry-run the plan (no authorization needed — lists resources only):

```bash
strix-cloud examples/agents.yaml
```

4. Execute checks (non-dry-run). `--run` requires a `--scope` authorization file
   (see `examples/scope.yaml`) listing the authorized target accounts:

```bash
strix-cloud examples/agents.yaml --run --scope examples/scope.yaml
```

Security notes
--------------

- The orchestrator will call connector methods that may perform network operations.
- Always run first in `--run` disabled (dry-run) mode to ensure expected behavior.
- Use dedicated Service Principals with least privilege and store secrets in Key Vault.
 
Secrets and Key Vault
----------------------

- The orchestrator can resolve secrets from Azure Key Vault or environment variables. Set the environment variable `AZURE_KEYVAULT_NAME` to enable Key Vault lookups.
- In `agents.yaml` you may reference connector config values using the `secret:` prefix. Example: `subscription_id: "secret:subscription_id"`.
- See the dedicated secrets guide: [docs/SECRETS.md](docs/SECRETS.md)

Security checks (CSPM)
----------------------

The orchestrator can run read-only, provider-neutral security checks and
aggregate them into a findings report.

```bash
# Run checks and emit reports; gate CI on HIGH-or-above failures.
strix-cloud examples/agents.yaml --run --scope examples/scope.yaml --security \
  --report findings.json --sarif findings.sarif --fail-on HIGH
```

Flags:
- `--scope PATH` — authorization file (required with `--run`); see `examples/scope.yaml`.

- `--security` — run `run_security_checks()` on each connector and print a summary.
- `--report PATH` — write findings as JSON.
- `--sarif PATH` — write SARIF 2.1.0 (e.g. for GitHub code scanning).
- `--fail-on SEVERITY` — exit code 2 if any failure is at/above SEVERITY.

See `docs/FINDINGS.md` for the control catalog and the per-provider mapping.
