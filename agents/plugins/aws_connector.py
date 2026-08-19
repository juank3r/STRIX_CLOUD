"""AWS connector skeleton implementing CloudGateway.

This is a minimal, non-destructive example. Do NOT execute destructive
actions without explicit permission and safeguards.
"""
from typing import Dict, Any
from agents.cloud_gateway import CloudGateway, GatewayError
from agents.common import audit


class Connector(CloudGateway):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        # Lazy import boto3 to keep optional
        try:
            import boto3  # type: ignore
            self.boto3 = boto3
        except Exception:
            self.boto3 = None

    def validate_permissions(self) -> bool:
        # Audit attempt
        audit.audit("connector.validate", {"provider": "aws", "config_keys": list(self.config.keys())})
        # Basic check: boto3 available and config contains region
        if not self.boto3:
            audit.audit("connector.validate.failed", {"provider": "aws", "reason": "boto3_missing"})
            raise GatewayError("boto3 is not available; install optional deps to use AWS connector")
        if "region" not in self.config:
            audit.audit("connector.validate.failed", {"provider": "aws", "reason": "missing_region"})
            raise GatewayError("Missing 'region' in connector config")
        audit.audit("connector.validate.succeeded", {"provider": "aws"})
        return True

    def list_resources(self) -> Any:
        # Example: list S3 buckets (read-only)
        audit.audit("connector.list", {"provider": "aws"})
        if not self.boto3:
            audit.audit("connector.list.empty", {"provider": "aws", "reason": "boto3_missing"})
            return []
        s3 = self.boto3.client("s3", region_name=self.config.get("region"))
        resp = s3.list_buckets()
        names = [b["Name"] for b in resp.get("Buckets", [])]
        audit.audit("connector.list.succeeded", {"provider": "aws", "count": len(names)})
        return names

    def run_safe_check(self, resource_id: str) -> Dict[str, Any]:
        # Non-destructive check example: get bucket location
        audit.audit("connector.check", {"provider": "aws", "resource_id": resource_id})
        if not self.boto3:
            audit.audit("connector.check.failed", {"provider": "aws", "resource_id": resource_id, "reason": "boto3_missing"})
            return {"error": "boto3 not available"}
        s3 = self.boto3.client("s3", region_name=self.config.get("region"))
        resp = s3.get_bucket_location(Bucket=resource_id)
        result = {"bucket": resource_id, "location": resp.get("LocationConstraint")}
        audit.audit("connector.check.succeeded", {"provider": "aws", "resource_id": resource_id})
        return result
