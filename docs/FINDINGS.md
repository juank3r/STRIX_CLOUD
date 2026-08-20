# Findings & Security Checks (CSPM)

STRIX_CLOUD connectors can run **read-only, non-destructive** security checks
against cloud storage and report the results as provider-neutral *findings*.

## Concepts

- **Control** (`agents/checks/catalog.py`) — a provider-neutral security
  expectation (e.g. "storage must not be public"). Controls carry an id,
  default severity, description, remediation and references.
- **Finding** (`agents/common/findings.py`) — one observation about one
  resource: `check_id`, `provider`, `resource_id`, `resource_type`,
  `severity`, `status` (`pass` / `fail` / `error`), `evidence`.
- **Report** — a collection of findings with aggregation (`summary()`,
  `highest_severity()`) and exporters (`to_json()`, `to_sarif()`).

Everything is an *observation*. No check performs any mutating action; each
connector uses only describe/get/list APIs.

## Core controls

Every provider connector implements these equivalently (`CORE_CONTROLS`):

| Control id                    | Severity   | Meaning                                        |
|-------------------------------|------------|------------------------------------------------|
| `STORAGE_PUBLIC_ACCESS`       | HIGH       | Bucket/container reachable by anonymous        |
| `STORAGE_SECURE_TRANSPORT`    | MEDIUM     | TLS/HTTPS not enforced                          |
| `STORAGE_ENCRYPTION`          | MEDIUM     | Encryption at rest / CMK not configured         |
| `STORAGE_VERSIONING`          | LOW        | Object versioning disabled                      |
| `NETWORK_UNRESTRICTED_INGRESS`| HIGH/CRIT  | Firewall allows inbound from 0.0.0.0/0 (::/0)   |

`STORAGE_LOGGING` (LOW) is an optional extension implemented by the AWS and
GCP connectors. `NETWORK_UNRESTRICTED_INGRESS` is reported at **CRITICAL** when
the open rule exposes admin ports (SSH 22 / RDP 3389) or all ports, otherwise
**HIGH**.

### Provider mapping — storage

| Control                 | AWS (S3)                              | Azure (Storage Account)         | GCP (GCS)                          |
|-------------------------|---------------------------------------|---------------------------------|------------------------------------|
| Public access           | Public Access Block + policy status   | `allow_blob_public_access`      | IAM `allUsers`/`allAuthenticated`  |
| Secure transport        | Bucket policy denies non-TLS          | `enable_https_traffic_only`     | Always HTTPS (pass)                |
| Encryption              | `GetBucketEncryption`                  | `encryption.key_source` == CMK  | `default_kms_key_name`             |
| Versioning              | `GetBucketVersioning`                  | blob service versioning         | `versioning_enabled`               |
| Logging (ext.)          | `GetBucketLogging`                     | —                               | `bucket.logging`                   |

### Provider mapping — network

| Control                        | AWS                          | Azure                          | GCP                          |
|--------------------------------|------------------------------|--------------------------------|------------------------------|
| Unrestricted ingress           | EC2 `describe_security_groups` | `network_security_groups.list_all` | `FirewallsClient.list` |
| Resource type                  | `security_group`             | `network_security_group`       | `firewall_rule`              |
| "Open" source                  | `0.0.0.0/0`, `::/0`          | `*`, `Internet`, `0.0.0.0/0`   | `0.0.0.0/0`, `::/0`          |

> Note: Azure and GCP encrypt at rest by default with platform keys, so a
> missing customer-managed key is reported at **LOW** severity there, while an
> S3 bucket with no encryption configured is **MEDIUM**.

## Running checks

Via the orchestrator (see `docs/ORCHESTRATOR.md`):

```bash
python agents/orchestrator.py examples/agents.yaml --run --security \
  --report findings.json --sarif findings.sarif --fail-on HIGH
```

- `--security` runs the CSPM checks and prints a summary.
- `--report PATH` writes findings as JSON.
- `--sarif PATH` writes SARIF 2.1.0 (consumable by GitHub code scanning, etc.).
- `--fail-on SEVERITY` exits non-zero when any failure is at/above the
  threshold — useful as a CI gate.

Programmatically:

```python
from agents.plugins import loader
from agents.common.findings import Report

conn = loader.load_connector("aws_connector", {"region": "us-east-1"})
conn.validate_permissions()
report = Report()
report.extend(conn.run_security_checks())
print(report.summary())
```

## Adding a control

1. Define a `Control` in `agents/checks/catalog.py` and register it in
   `CONTROLS` (add to `CORE_CONTROLS` only if all providers can implement it).
2. Implement the read-only check in each connector's `run_security_checks`
   path and add the id to that connector's `implemented_controls`.
3. Add tests (see `tests/test_security_checks.py`) with mocked clients.

## Ethics

These checks are for **authorized** auditing only. See `docs/ETHICS.md` and
`docs/LEGAL.md`.
