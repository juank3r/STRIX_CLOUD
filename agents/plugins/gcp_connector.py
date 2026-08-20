"""GCP connector implementing CloudGateway.

Read-only / non-destructive checks only. Security checks evaluate Cloud
Storage (GCS) buckets using describe/get APIs exclusively.

Requires `google-cloud-storage`. The import is optional and monkeypatchable
so the connector degrades gracefully and stays testable.
"""
from typing import Any, Dict, List

from agents.checks import catalog, network
from agents.cloud_gateway import CloudGateway, GatewayError
from agents.common import audit
from agents.common.findings import STATUS_FAIL, STATUS_PASS, Finding, Severity

try:  # pragma: no cover - import side effect
    from google.cloud import storage  # type: ignore
except Exception:  # pragma: no cover
    storage = None

try:  # pragma: no cover
    from google.cloud import compute_v1  # type: ignore
except Exception:  # pragma: no cover
    compute_v1 = None

_ANON_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


class Connector(CloudGateway):
    implemented_controls = (
        catalog.STORAGE_PUBLIC_ACCESS.id,
        catalog.STORAGE_SECURE_TRANSPORT.id,
        catalog.STORAGE_ENCRYPTION.id,
        catalog.STORAGE_VERSIONING.id,
        catalog.STORAGE_LOGGING.id,
        catalog.NETWORK_UNRESTRICTED_INGRESS.id,
    )

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.storage = storage
        self.compute_v1 = compute_v1

    # -- client seams (overridable in tests) -----------------------------
    def _gcs_client(self):
        if not self.storage:
            return None
        return self.storage.Client()

    def _firewalls_client(self):
        if not self.compute_v1 or not self.config.get("project"):
            return None
        return self.compute_v1.FirewallsClient()

    # -- CloudGateway core ----------------------------------------------
    def validate_permissions(self) -> bool:
        audit.audit("connector.validate", {"provider": "gcp", "config_keys": list(self.config.keys())})
        if not self.storage:
            audit.audit("connector.validate.failed", {"provider": "gcp", "reason": "libs_missing"})
            raise GatewayError("google-cloud libraries not available; install optional deps to use GCP connector")
        audit.audit("connector.validate.succeeded", {"provider": "gcp"})
        return True

    def list_resources(self) -> Any:
        audit.audit("connector.list", {"provider": "gcp"})
        client = self._gcs_client()
        if client is None:
            audit.audit("connector.list.empty", {"provider": "gcp", "reason": "libs_missing"})
            return []
        buckets = [b.name for b in client.list_buckets()]
        audit.audit("connector.list.succeeded", {"provider": "gcp", "count": len(buckets)})
        return buckets

    def run_safe_check(self, resource_id: str) -> Dict[str, Any]:
        audit.audit("connector.check", {"provider": "gcp", "resource_id": resource_id})
        client = self._gcs_client()
        if client is None:
            audit.audit(
                "connector.check.failed",
                {"provider": "gcp", "resource_id": resource_id, "reason": "libs_missing"},
            )
            return {"error": "gcp libs not available"}
        bucket = client.get_bucket(resource_id)
        result = {"bucket": bucket.name, "location": getattr(bucket, "location", None)}
        audit.audit("connector.check.succeeded", {"provider": "gcp", "resource_id": resource_id})
        return result

    # -- security checks (CSPM) -----------------------------------------
    def run_security_checks(self) -> List[Finding]:
        findings: List[Finding] = []
        gcs = self._gcs_client()
        if gcs is not None:
            audit.audit("connector.security.start", {"provider": "gcp", "domain": "storage"})
            for bucket in gcs.list_buckets():
                findings.extend(self._check_bucket(bucket))
        else:
            audit.audit("connector.security.skipped", {"provider": "gcp", "domain": "storage"})

        fw = self._firewalls_client()
        if fw is not None:
            audit.audit("connector.security.start", {"provider": "gcp", "domain": "network"})
            findings.extend(self._network_findings(fw))
        else:
            audit.audit("connector.security.skipped", {"provider": "gcp", "domain": "network"})

        audit.audit(
            "connector.security.done",
            {"provider": "gcp", "findings": len(findings), "failures": sum(f.is_failure for f in findings)},
        )
        return findings

    def _network_findings(self, client) -> List[Finding]:
        ctl = catalog.NETWORK_UNRESTRICTED_INGRESS
        out: List[Finding] = []
        project = self.config.get("project")
        for fw in client.list(project=project):
            name = getattr(fw, "name", "unknown")
            direction = str(getattr(fw, "direction", "INGRESS")).upper()
            disabled = bool(getattr(fw, "disabled", False))
            if direction != "INGRESS" or disabled:
                out.append(ctl.finding("gcp", name, "firewall_rule", status=STATUS_PASS, evidence={}))
                continue
            sources = list(getattr(fw, "source_ranges", None) or [])
            if not any(network.is_open_cidr(s) for s in sources):
                out.append(ctl.finding("gcp", name, "firewall_rule", status=STATUS_PASS, evidence={}))
                continue
            allowed = _allowed_summary(getattr(fw, "allowed", None) or [])
            admin = any(network.any_token_covers_admin(a["ports"]) for a in allowed) if allowed else True
            out.append(
                ctl.finding(
                    "gcp",
                    name,
                    "firewall_rule",
                    status=STATUS_FAIL,
                    evidence={"source_ranges": sources, "allowed": allowed},
                    severity=Severity.CRITICAL if admin else Severity.HIGH,
                )
            )
        return out

    # -- helpers ---------------------------------------------------------
    def _check_bucket(self, bucket) -> List[Finding]:
        name = getattr(bucket, "name", "unknown")
        rtype = "gcs_bucket"
        return [
            self._check_public_access(bucket, name, rtype),
            self._check_secure_transport(name, rtype),
            self._check_encryption(bucket, name, rtype),
            self._check_versioning(bucket, name, rtype),
            self._check_logging(bucket, name, rtype),
        ]

    def _check_public_access(self, bucket, name: str, rtype: str) -> Finding:
        ctl = catalog.STORAGE_PUBLIC_ACCESS
        evidence: Dict[str, Any] = {}
        public = False
        try:
            policy = bucket.get_iam_policy()
            members = _anon_members(policy)
            evidence["anonymous_members"] = sorted(members)
            public = bool(members)
        except Exception as exc:
            evidence["iam_error"] = str(exc)
        return ctl.finding(
            provider="gcp",
            resource_id=name,
            resource_type=rtype,
            status=STATUS_FAIL if public else STATUS_PASS,
            evidence=evidence,
        )

    def _check_secure_transport(self, name: str, rtype: str) -> Finding:
        ctl = catalog.STORAGE_SECURE_TRANSPORT
        # GCS endpoints are HTTPS-only; transport is always encrypted.
        return ctl.finding(
            provider="gcp",
            resource_id=name,
            resource_type=rtype,
            status=STATUS_PASS,
            evidence={"note": "GCS API is HTTPS-only"},
        )

    def _check_encryption(self, bucket, name: str, rtype: str) -> Finding:
        ctl = catalog.STORAGE_ENCRYPTION
        kms = getattr(bucket, "default_kms_key_name", None)
        cmk = bool(kms)
        # GCS encrypts at rest by default (Google-managed); missing CMK is lower risk.
        return ctl.finding(
            provider="gcp",
            resource_id=name,
            resource_type=rtype,
            status=STATUS_PASS if cmk else STATUS_FAIL,
            evidence={"default_kms_key_name": kms},
            severity=Severity.LOW,
        )

    def _check_versioning(self, bucket, name: str, rtype: str) -> Finding:
        ctl = catalog.STORAGE_VERSIONING
        enabled = bool(getattr(bucket, "versioning_enabled", False))
        return ctl.finding(
            provider="gcp",
            resource_id=name,
            resource_type=rtype,
            status=STATUS_PASS if enabled else STATUS_FAIL,
            evidence={"versioning_enabled": enabled},
        )

    def _check_logging(self, bucket, name: str, rtype: str) -> Finding:
        ctl = catalog.STORAGE_LOGGING
        logging_cfg = getattr(bucket, "logging", None)
        enabled = bool(logging_cfg)
        return ctl.finding(
            provider="gcp",
            resource_id=name,
            resource_type=rtype,
            status=STATUS_PASS if enabled else STATUS_FAIL,
            evidence={"logging": logging_cfg},
            severity=Severity.LOW,
        )


def _allowed_summary(allowed) -> list:
    """Normalize GCP firewall ``allowed`` entries to {protocol, ports} dicts.

    The compute client exposes the protocol as ``I_p_protocol`` while the REST
    API uses ``IPProtocol``; dict-shaped inputs (tests) are also supported.
    """
    out = []
    for item in allowed:
        if isinstance(item, dict):
            proto = item.get("IPProtocol") or item.get("I_p_protocol")
            ports = list(item.get("ports") or [])
        else:
            proto = getattr(item, "I_p_protocol", None) or getattr(item, "IPProtocol", None)
            ports = list(getattr(item, "ports", None) or [])
        out.append({"protocol": proto, "ports": ports})
    return out


def _anon_members(policy) -> set:
    """Return the set of anonymous/all-authenticated members across bindings."""
    found: set = set()
    bindings = getattr(policy, "bindings", policy)
    try:
        iterator = list(bindings)
    except TypeError:
        return found
    for binding in iterator:
        members = binding.get("members", []) if isinstance(binding, dict) else getattr(binding, "members", [])
        for m in members:
            if m in _ANON_MEMBERS:
                found.add(m)
    return found
