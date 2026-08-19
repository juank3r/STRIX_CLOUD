"""Azure connector skeleton implementing CloudGateway.

Minimal, non-destructive example. Requires `azure-identity` and `azure-mgmt-resource`
to perform real queries. This skeleton avoids destructive actions and only shows
pattern for implementing a connector.
"""
from typing import Dict, Any
from agents.cloud_gateway import CloudGateway, GatewayError
from agents.common import audit
from agents.common import secrets


class Connector(CloudGateway):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        try:
            from azure.identity import DefaultAzureCredential  # type: ignore
            from azure.mgmt.resource import ResourceManagementClient  # type: ignore
            self.DefaultAzureCredential = DefaultAzureCredential
            self.ResourceManagementClient = ResourceManagementClient
        except Exception:
            self.DefaultAzureCredential = None
            self.ResourceManagementClient = None

    def validate_permissions(self) -> bool:
        audit.audit("connector.validate", {"provider": "azure", "config_keys": list(self.config.keys())})
        if not self.ResourceManagementClient:
            audit.audit("connector.validate.failed", {"provider": "azure", "reason": "sdk_missing"})
            raise GatewayError("Azure SDK not available; install optional deps to use Azure connector")
        if "subscription_id" not in self.config:
            # Attempt to read subscription id from Key Vault or env
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
        cred = self.DefaultAzureCredential()
        client = self.ResourceManagementClient(cred, self.config.get("subscription_id"))
        # Return resource groups as a safe example
        groups = [g.name for g in client.resource_groups.list()]
        audit.audit("connector.list.succeeded", {"provider": "azure", "count": len(groups)})
        return groups

    def run_safe_check(self, resource_id: str) -> Dict[str, Any]:
        # Example non-destructive check: get resource group details
        audit.audit("connector.check", {"provider": "azure", "resource_id": resource_id})
        if not self.ResourceManagementClient:
            audit.audit("connector.check.failed", {"provider": "azure", "resource_id": resource_id, "reason": "sdk_missing"})
            return {"error": "azure sdk not available"}
        cred = self.DefaultAzureCredential()
        client = self.ResourceManagementClient(cred, self.config.get("subscription_id"))
        rg = client.resource_groups.get(resource_id)
        result = {"name": rg.name, "location": rg.location}
        audit.audit("connector.check.succeeded", {"provider": "azure", "resource_id": resource_id})
        return result
