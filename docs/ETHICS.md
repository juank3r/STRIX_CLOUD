# Ethics and Usage Limits

Agents in this repository must follow strict ethical guidelines:

- Obtain explicit permission before testing.
- Avoid destructive or privacy-invasive techniques.
- Log all actions and provide remediation guidance.

## Enforced in code (not just policy)

- **Authorization gate:** running real checks (`--run`) requires a `--scope`
  file (`examples/scope.yaml`) that names the authorized target accounts and who
  authorized the run. Any target not on the allowlist aborts the run before a
  single API call — see `agents/common/authorization.py`.
- **Read-only by design:** connectors only call describe/get/list APIs; there is
  no destructive action path.
- **Evidence trail:** set `STRIX_AUDIT_LOG` to persist a JSON-lines audit log of
  every action (including `authorization.granted` / `authorization.denied`).
