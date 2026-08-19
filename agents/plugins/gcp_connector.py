"""GCP connector skeleton implementing CloudGateway.

Minimal, non-destructive example. Requires `google-cloud-resource-manager` or
`google-cloud-storage` for real queries. This skeleton keeps optional imports.
"""
from typing import Dict, Any
from agents.cloud_gateway import CloudGateway, GatewayError
from agents.common import audit


class Connector(CloudGateway):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        try:
            from google.cloud import storage  # type: ignore
            self.storage = storage
        except Exception:
            self.storage = None

    def validate_permissions(self) -> bool:
        audit.audit("connector.validate", {"provider": "gcp", "config_keys": list(self.config.keys())})
        if not self.storage:
            audit.audit("connector.validate.failed", {"provider": "gcp", "reason": "libs_missing"})
            raise GatewayError("google-cloud libraries not available; install optional deps to use GCP connector")
        audit.audit("connector.validate.succeeded", {"provider": "gcp"})
        return True

    def list_resources(self) -> Any:
        audit.audit("connector.list", {"provider": "gcp"})
        if not self.storage:
            audit.audit("connector.list.empty", {"provider": "gcp", "reason": "libs_missing"})
            return []
        client = self.storage.Client()
        buckets = [b.name for b in client.list_buckets()]
        audit.audit("connector.list.succeeded", {"provider": "gcp", "count": len(buckets)})
        return buckets

    def run_safe_check(self, resource_id: str) -> Dict[str, Any]:
        audit.audit("connector.check", {"provider": "gcp", "resource_id": resource_id})
        if not self.storage:
            audit.audit("connector.check.failed", {"provider": "gcp", "resource_id": resource_id, "reason": "libs_missing"})
            return {"error": "gcp libs not available"}
        client = self.storage.Client()
        bucket = client.get_bucket(resource_id)
        result = {"bucket": bucket.name, "location": bucket.location}
        audit.audit("connector.check.succeeded", {"provider": "gcp", "resource_id": resource_id})
        return result
