"""Azure connector skeleton implementing CloudGateway.

Minimal, non-destructive example. Requires `azure-identity` and `azure-mgmt-resource`
to perform real queries. This skeleton avoids destructive actions and only shows
pattern for implementing a connector.
"""
from typing import Dict, Any
from agents.cloud_gateway import CloudGateway, GatewayError


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
        if not self.ResourceManagementClient:
            raise GatewayError("Azure SDK not available; install optional deps to use Azure connector")
        if "subscription_id" not in self.config:
            raise GatewayError("Missing 'subscription_id' in connector config")
        return True

    def list_resources(self) -> Any:
        if not self.ResourceManagementClient:
            return []
        cred = self.DefaultAzureCredential()
        client = self.ResourceManagementClient(cred, self.config.get("subscription_id"))
        # Return resource groups as a safe example
        groups = [g.name for g in client.resource_groups.list()]
        return groups

    def run_safe_check(self, resource_id: str) -> Dict[str, Any]:
        # Example non-destructive check: get resource group details
        if not self.ResourceManagementClient:
            return {"error": "azure sdk not available"}
        cred = self.DefaultAzureCredential()
        client = self.ResourceManagementClient(cred, self.config.get("subscription_id"))
        rg = client.resource_groups.get(resource_id)
        return {"name": rg.name, "location": rg.location}
