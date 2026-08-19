# Connectors (Cloud Gateways)

This document describes the connector pattern and how to implement new connectors
for cloud providers.

Principles
----------

- Connectors implement `agents.cloud_gateway.CloudGateway`.
- Prefer read-only, non-destructive operations by default.
- Validate permissions and limit scopes before any operation.
- Log all actions via `agents.common.audit.audit()`.

Structure
---------

- `agents/plugins/<provider>_connector.py` — module exposing `Connector` class.
- `agents/plugins/loader.py` — discovery and loader helper.
- Tests should live under `tests/` and validate discovery and basic behavior.

Example
-------

See `agents/plugins/aws_connector.py`, `azure_connector.py`, and `gcp_connector.py`
for minimal implementations.
