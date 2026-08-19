"""CloudGateway interface and base classes for connectors.

Connectors must implement `CloudGateway` to provide safe, auditable actions.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict


class CloudGateway(ABC):
    """Abstract interface for cloud connector gateways."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config

    @abstractmethod
    def validate_permissions(self) -> bool:
        """Validate that required credentials/permissions are present and limited."""

    @abstractmethod
    def list_resources(self) -> Any:
        """Return a safe listing of target resources (read-only)."""

    @abstractmethod
    def run_safe_check(self, resource_id: str) -> Dict[str, Any]:
        """Run a non-destructive check and return findings."""


class GatewayError(Exception):
    pass
