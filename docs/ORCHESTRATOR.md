# Orchestrator

This document describes the Orchestrator prototype included in `agents/orchestrator.py`.

Overview
--------

The Orchestrator reads a plan file (`agents.yaml`) with repository/target definitions,
loads the appropriate connector via the plugin loader and performs safe, read-only
checks against discovered resources.

Quickstart
----------

1. Ensure you have authenticated to Azure with `az login` (if using Azure connectors).
2. Adjust `examples/agents.yaml` to list your repositories/targets.
3. Dry-run the plan:

```bash
python agents/orchestrator.py examples/agents.yaml
```

4. Execute checks (non-dry-run):

```bash
python agents/orchestrator.py examples/agents.yaml --run
```

Security notes
--------------

- The orchestrator will call connector methods that may perform network operations.
- Always run first in `--run` disabled (dry-run) mode to ensure expected behavior.
- Use dedicated Service Principals with least privilege and store secrets in Key Vault.
