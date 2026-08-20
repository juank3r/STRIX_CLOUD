"""Azure connector implementing CloudGateway.

Read-only / non-destructive checks only. Resource listing uses resource
groups; security checks evaluate Storage Accounts via management (describe)
APIs exclusively.

Requires `azure-identity` and `azure-mgmt-resource` for listing, and
`azure-mgmt-storage` for storage security checks. All SDK imports are optional
and monkeypatchable so the connector degrades gracefully and stays testable.
"""
from typing import Any, Dict, List, Optional

from agents.checks import catalog, network
from agents.cloud_gateway import CloudGateway, GatewayError
from agents.common import audit, secrets
from agents.common.findings import STATUS_FAIL, STATUS_PASS, Finding, Severity

try:  # pragma: no cover - import side effect
    from azure.identity import DefaultAzureCredential  # type: ignore
except Exception:  # pragma: no cover
    DefaultAzureCredential = None

try:  # pragma: no cover
    from azure.mgmt.resource import ResourceManagementClient  # type: ignore
except Exception:  # pragma: no cover
    ResourceManagementClient = None

try:  # pragma: no cover
    from azure.mgmt.storage import StorageManagementClient  # type: ignore
except Exception:  # pragma: no cover
    StorageManagementClient = None

try:  # pragma: no cover
    from azure.mgmt.network import NetworkManagementClient  # type: ignore
except Exception:  # pragma: no cover
    NetworkManagementClient = None


class Connector(CloudGateway):
    implemented_controls = (
        catalog.STORAGE_PUBLIC_ACCESS.id,
        catalog.STORAGE_SECURE_TRANSPORT.id,
        catalog.STORAGE_ENCRYPTION.id,
        catalog.STORAGE_VERSIONING.id,
        catalog.NETWORK_UNRESTRICTED_INGRESS.id,
    )

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        # Bind (possibly monkeypatched) module-level SDK references.
        self.DefaultAzureCredential = DefaultAzureCredential
        self.ResourceManagementClient = ResourceManagementClient
        self.StorageManagementClient = StorageManagementClient
        self.NetworkManagementClient = NetworkManagementClient

    # -- client seams (overridable in tests) -----------------------------
    def _resource_client(self):
        cred = self.DefaultAzureCredential()
        return self.ResourceManagementClient(cred, self.config.get("subscription_id"))

    def _storage_mgmt_client(self):
        if not self.StorageManagementClient or not self.DefaultAzureCredential:
            return None
        cred = self.DefaultAzureCredential()
        return self.StorageManagementClient(cred, self.config.get("subscription_id"))

    def _network_mgmt_client(self):
        if not self.NetworkManagementClient or not self.DefaultAzureCredential:
            return None
        cred = self.DefaultAzureCredential()
        return self.NetworkManagementClient(cred, self.config.get("subscription_id"))

    # -- CloudGateway core ----------------------------------------------
    def validate_permissions(self) -> bool:
        audit.audit("connector.validate", {"provider": "azure", "config_keys": list(self.config.keys())})
        if not self.ResourceManagementClient:
            audit.audit("connector.validate.failed", {"provider": "azure", "reason": "sdk_missing"})
            raise GatewayError("Azure SDK not available; install optional deps to use Azure connector")
        if "subscription_id" not in self.config:
            sub = secrets.get_secret("subscription_id", env_fallback="AZURE_SUBSCRIPTION_ID")
            if not sub:
                audit.audit("connector.validate.failed", {"provider": "azure", "reason": "missing_subscription_id"})
                raise GatewayError("Missing 'subscription_id' in connector config")
            self.config["subscription_id"] = sub
        audit.audit("connector.validate.succeeded", {"provider": "azure"})
        return True

    def list_resources(self) -> Any:
        audit.audit("connector.list", {"provider": "azure"})
        if not self.ResourceManagementClient:
            audit.audit("connector.list.empty", {"provider": "azure", "reason": "sdk_missing"})
            return []
        client = self._resource_client()
        groups = [g.name for g in client.resource_groups.list()]
        audit.audit("connector.list.succeeded", {"provider": "azure", "count": len(groups)})
        return groups

    def run_safe_check(self, resource_id: str) -> Dict[str, Any]:
        audit.audit("connector.check", {"provider": "azure", "resource_id": resource_id})
        if not self.ResourceManagementClient:
            audit.audit(
                "connector.check.failed",
                {"provider": "azure", "resource_id": resource_id, "reason": "sdk_missing"},
            )
            return {"error": "azure sdk not available"}
        client = self._resource_client()
        rg = client.resource_groups.get(resource_id)
        result = {"name": rg.name, "location": rg.location}
        audit.audit("connector.check.succeeded", {"provider": "azure", "resource_id": resource_id})
        return result

    # -- security checks (CSPM) -----------------------------------------
    def run_security_checks(self) -> List[Finding]:
        findings: List[Finding] = []
        storage_client = self._storage_mgmt_client()
        if storage_client is not None:
            audit.audit("connector.security.start", {"provider": "azure", "domain": "storage"})
            for account in storage_client.storage_accounts.list():
                findings.extend(self._check_account(storage_client, account))
        else:
            audit.audit("connector.security.skipped", {"provider": "azure", "domain": "storage"})

        net_client = self._network_mgmt_client()
        if net_client is not None:
            audit.audit("connector.security.start", {"provider": "azure", "domain": "network"})
            findings.extend(self._network_findings(net_client))
        else:
            audit.audit("connector.security.skipped", {"provider": "azure", "domain": "network"})

        audit.audit(
            "connector.security.done",
            {"provider": "azure", "findings": len(findings), "failures": sum(f.is_failure for f in findings)},
        )
        return findings

    def _network_findings(self, client) -> List[Finding]:
        ctl = catalog.NETWORK_UNRESTRICTED_INGRESS
        out: List[Finding] = []
        for nsg in client.network_security_groups.list_all():
            name = getattr(nsg, "name", "unknown")
            open_rules = []
            admin = False
            for rule in getattr(nsg, "security_rules", None) or []:
                if _rule_str(rule, "direction").lower() != "inbound":
                    continue
                if _rule_str(rule, "access").lower() != "allow":
                    continue
                sources = _rule_list(rule, "source_address_prefix", "source_address_prefixes")
                if not any(network.is_open_source_token(s) for s in sources):
                    continue
                ports = _rule_list(rule, "destination_port_range", "destination_port_ranges")
                if network.any_token_covers_admin(ports):
                    admin = True
                open_rules.append(
                    {"name": getattr(rule, "name", None), "sources": sources, "ports": ports}
                )
            if not open_rules:
                out.append(
                    ctl.finding("azure", name, "network_security_group", status=STATUS_PASS, evidence={})
                )
                continue
            out.append(
                ctl.finding(
                    "azure",
                    name,
                    "network_security_group",
                    status=STATUS_FAIL,
                    evidence={"open_rules": open_rules},
                    severity=Severity.CRITICAL if admin else Severity.HIGH,
                )
            )
        return out

    # -- helpers ---------------------------------------------------------
    def _check_account(self, client, account) -> List[Finding]:
        name = getattr(account, "name", "unknown")
        rtype = "storage_account"
        out = [
            self._check_public_access(account, name, rtype),
            self._check_secure_transport(account, name, rtype),
            self._check_encryption(account, name, rtype),
            self._check_versioning(client, account, name, rtype),
        ]
        return out

    def _check_public_access(self, account, name: str, rtype: str) -> Finding:
        ctl = catalog.STORAGE_PUBLIC_ACCESS
        allow = getattr(account, "allow_blob_public_access", None)
        # Public allowed (True) or unset (None, historically defaulted to allow).
        violated = allow is None or bool(allow)
        return ctl.finding(
            provider="azure",
            resource_id=name,
            resource_type=rtype,
            status=STATUS_FAIL if violated else STATUS_PASS,
            evidence={"allow_blob_public_access": allow},
        )

    def _check_secure_transport(self, account, name: str, rtype: str) -> Finding:
        ctl = catalog.STORAGE_SECURE_TRANSPORT
        https_only = bool(getattr(account, "enable_https_traffic_only", False))
        return ctl.finding(
            provider="azure",
            resource_id=name,
            resource_type=rtype,
            status=STATUS_PASS if https_only else STATUS_FAIL,
            evidence={"enable_https_traffic_only": https_only},
        )

    def _check_encryption(self, account, name: str, rtype: str) -> Finding:
        ctl = catalog.STORAGE_ENCRYPTION
        key_source = _encryption_key_source(account)
        cmk = key_source == "Microsoft.Keyvault"
        # Azure encrypts at rest by default (platform key); missing CMK is lower risk.
        return ctl.finding(
            provider="azure",
            resource_id=name,
            resource_type=rtype,
            status=STATUS_PASS if cmk else STATUS_FAIL,
            evidence={"key_source": key_source},
            severity=Severity.LOW,
        )

    def _check_versioning(self, client, account, name: str, rtype: str) -> Finding:
        ctl = catalog.STORAGE_VERSIONING
        evidence: Dict[str, Any] = {}
        enabled = False
        rg = _resource_group_from_id(getattr(account, "id", None))
        try:
            props = client.blob_services.get_service_properties(rg, name)
            enabled = bool(getattr(props, "is_versioning_enabled", False))
            evidence["is_versioning_enabled"] = enabled
            evidence["resource_group"] = rg
        except Exception as exc:
            evidence["versioning_error"] = str(exc)
        return ctl.finding(
            provider="azure",
            resource_id=name,
            resource_type=rtype,
            status=STATUS_PASS if enabled else STATUS_FAIL,
            evidence=evidence,
        )


def _encryption_key_source(account) -> Optional[str]:
    enc = getattr(account, "encryption", None)
    if enc is None:
        return None
    return getattr(enc, "key_source", None)


def _resource_group_from_id(resource_id: Optional[str]) -> Optional[str]:
    """Extract the resource group name from an ARM resource id."""
    if not resource_id:
        return None
    parts = [p for p in resource_id.split("/") if p]
    for i, token in enumerate(parts):
        if token.lower() == "resourcegroups" and i + 1 < len(parts):
            return parts[i + 1]
    return None


def _rule_str(rule, attr: str) -> str:
    return str(getattr(rule, attr, "") or "")


def _rule_list(rule, single_attr: str, plural_attr: str) -> List[str]:
    """Merge an Azure rule's singular + plural address/port attributes."""
    values: List[str] = []
    single = getattr(rule, single_attr, None)
    if single:
        values.append(str(single))
    plural = getattr(rule, plural_attr, None)
    if plural:
        values.extend(str(p) for p in plural)
    return values
