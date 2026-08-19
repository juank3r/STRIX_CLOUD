"""GCP connector skeleton implementing CloudGateway.

Minimal, non-destructive example. Requires `google-cloud-resource-manager` or
`google-cloud-storage` for real queries. This skeleton keeps optional imports.
"""
from typing import Dict, Any
from agents.cloud_gateway import CloudGateway, GatewayError


class Connector(CloudGateway):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        try:
            from google.cloud import storage  # type: ignore
            self.storage = storage
        except Exception:
            self.storage = None

    def validate_permissions(self) -> bool:
        if not self.storage:
            raise GatewayError("google-cloud libraries not available; install optional deps to use GCP connector")
        return True

    def list_resources(self) -> Any:
        if not self.storage:
            return []
        client = self.storage.Client()
        buckets = [b.name for b in client.list_buckets()]
        return buckets

    def run_safe_check(self, resource_id: str) -> Dict[str, Any]:
        if not self.storage:
            return {"error": "gcp libs not available"}
        client = self.storage.Client()
        bucket = client.get_bucket(resource_id)
        return {"bucket": bucket.name, "location": bucket.location}
