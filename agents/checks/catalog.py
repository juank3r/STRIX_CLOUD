"""Provider-neutral control catalog for STRIX_CLOUD.

A *control* is a security expectation ("storage must not be public") that is
implemented equivalently by each cloud connector. Keeping the catalog separate
from the connectors gives us a single source of truth for control ids,
severities, descriptions and remediation guidance, and lets tests assert that
every provider covers the same core controls.

Controls are neutral; connectors translate them into provider-specific,
read-only checks and emit :class:`~agents.common.findings.Finding` objects via
:meth:`Control.finding`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from agents.common.findings import Finding, Severity


@dataclass(frozen=True)
class Control:
    """A single, provider-neutral security control."""

    id: str
    title: str
    severity: Severity
    category: str
    description: str
    remediation: str
    references: List[str] = field(default_factory=list)
    #: ATT&CK technique ids this control maps to (see ``agents.checks.mitre``).
    mitre: List[str] = field(default_factory=list)

    def finding(
        self,
        provider: str,
        resource_id: str,
        resource_type: str,
        status: str = "fail",
        evidence: Optional[Dict[str, Any]] = None,
        severity: Optional[Severity] = None,
        remediation: Optional[str] = None,
        account_id: str = "",
        region: str = "",
        verification: str = "",
    ) -> Finding:
        """Build a :class:`Finding` for this control against one resource.

        ``severity`` / ``remediation`` may be overridden per provider when the
        residual risk differs. ``account_id`` / ``region`` / ``verification``
        carry the red-team enrichment (Phase A).
        """
        return Finding(
            check_id=self.id,
            title=self.title,
            provider=provider,
            resource_id=resource_id,
            resource_type=resource_type,
            severity=severity if severity is not None else self.severity,
            status=status,
            description=self.description,
            remediation=remediation if remediation is not None else self.remediation,
            references=list(self.references),
            evidence=evidence or {},
            account_id=account_id,
            region=region,
            mitre=list(self.mitre),
            verification=verification,
        )


# --- Control definitions -------------------------------------------------

STORAGE_PUBLIC_ACCESS = Control(
    id="STORAGE_PUBLIC_ACCESS",
    title="Object storage is publicly accessible",
    severity=Severity.HIGH,
    category="storage",
    description=(
        "The storage bucket/container grants read access to anonymous or all "
        "authenticated principals, exposing its objects to the public internet."
    ),
    remediation=(
        "Block public access at the account/bucket level and remove ACL or "
        "policy grants to anonymous principals (AllUsers/allUsers)."
    ),
    references=[
        "https://cloud.google.com/storage/docs/public-access-prevention",
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
        "https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent",
    ],
    mitre=["T1530"],
)

STORAGE_SECURE_TRANSPORT = Control(
    id="STORAGE_SECURE_TRANSPORT",
    title="Object storage does not enforce encrypted transport",
    severity=Severity.MEDIUM,
    category="storage",
    description=(
        "The storage resource does not require TLS/HTTPS for access, allowing "
        "data to be read or written over an unencrypted channel."
    ),
    remediation=(
        "Require secure transport (deny non-TLS requests / enable "
        "'secure transfer required' / HTTPS-only)."
    ),
    references=[
        "https://learn.microsoft.com/azure/storage/common/storage-require-secure-transfer",
    ],
)

STORAGE_ENCRYPTION = Control(
    id="STORAGE_ENCRYPTION",
    title="Object storage encryption at rest is not enforced with managed keys",
    severity=Severity.MEDIUM,
    category="storage",
    description=(
        "The storage resource does not have encryption-at-rest configured with "
        "a customer-managed / explicitly configured key."
    ),
    remediation=(
        "Enable default encryption at rest, preferably with a customer-managed "
        "key (KMS/Key Vault) for key lifecycle control."
    ),
    references=[
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html",
    ],
)

STORAGE_VERSIONING = Control(
    id="STORAGE_VERSIONING",
    title="Object storage versioning is disabled",
    severity=Severity.LOW,
    category="storage",
    description=(
        "Object versioning is not enabled, reducing resilience against "
        "accidental deletion, overwrite or ransomware."
    ),
    remediation="Enable object versioning (and lifecycle/retention as appropriate).",
    references=[],
)

STORAGE_LOGGING = Control(
    id="STORAGE_LOGGING",
    title="Object storage access logging is disabled",
    severity=Severity.LOW,
    category="storage",
    description=(
        "Access/audit logging is not enabled for the storage resource, "
        "limiting the ability to detect and investigate abuse."
    ),
    remediation="Enable server access logging / audit logs to a protected sink.",
    references=[],
    mitre=["T1562.008"],
)

NETWORK_UNRESTRICTED_INGRESS = Control(
    id="NETWORK_UNRESTRICTED_INGRESS",
    title="Firewall allows unrestricted inbound access from the internet",
    severity=Severity.HIGH,
    category="network",
    description=(
        "A firewall rule / security group / network security group permits "
        "inbound traffic from any address (0.0.0.0/0 or ::/0). When it exposes "
        "administrative ports (SSH 22 / RDP 3389) or all ports the risk is "
        "critical."
    ),
    remediation=(
        "Restrict inbound rules to known source ranges; never expose SSH/RDP "
        "or all ports to 0.0.0.0/0. Prefer a bastion/VPN and least-privilege "
        "network policy."
    ),
    references=[
        "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules.html",
        "https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview",
        "https://cloud.google.com/vpc/docs/firewalls",
    ],
    mitre=["T1190"],
)


# Registry of all controls, keyed by id.
CONTROLS: Dict[str, Control] = {
    c.id: c
    for c in (
        STORAGE_PUBLIC_ACCESS,
        STORAGE_SECURE_TRANSPORT,
        STORAGE_ENCRYPTION,
        STORAGE_VERSIONING,
        STORAGE_LOGGING,
        NETWORK_UNRESTRICTED_INGRESS,
    )
}

# Controls every provider connector is expected to implement equivalently.
# STORAGE_LOGGING is an optional extension (not uniformly cheap on all
# providers) and is intentionally excluded from the required core.
CORE_CONTROLS: tuple = (
    STORAGE_PUBLIC_ACCESS.id,
    STORAGE_SECURE_TRANSPORT.id,
    STORAGE_ENCRYPTION.id,
    STORAGE_VERSIONING.id,
    NETWORK_UNRESTRICTED_INGRESS.id,
)


def get(control_id: str) -> Control:
    """Return a control by id (raises KeyError if unknown)."""
    return CONTROLS[control_id]
