"""CloudGateway interface and base classes for connectors.

Connectors must implement `CloudGateway` to provide safe, auditable actions.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List

from agents.common.findings import Finding


class CloudGateway(ABC):
    """Abstract interface for cloud connector gateways."""

    #: Neutral control ids (see ``agents.checks.catalog``) this connector
    #: implements. Used for coverage introspection and tests.
    implemented_controls: tuple = ()

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

    def run_security_checks(self) -> List[Finding]:
        """Run read-only CSPM-style security checks and return findings.

        Connectors override this to evaluate the neutral controls declared in
        :attr:`implemented_controls`. The default implementation returns no
        findings so existing connectors remain valid without changes.

        Implementations MUST be non-destructive: only read/describe APIs.
        """
        return []


class GatewayError(Exception):
    pass
