"""Provider-neutral security findings model for STRIX_CLOUD.

This module defines the data structures used by connectors to report the
results of read-only, non-destructive security checks (CSPM-style). It is
deliberately provider-agnostic: an AWS, Azure or GCP connector all emit the
same :class:`Finding` shape so the orchestrator can aggregate and report them
uniformly.

Findings are *observations*, not actions. Nothing in this module performs any
cloud operation; it only structures results produced elsewhere.
"""
from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class Severity(enum.IntEnum):
    """Ordered severity levels (higher value == more severe)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        try:
            return cls[name.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"Unknown severity: {name!r}") from exc

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


# Status values a check may report for a given resource.
STATUS_FAIL = "fail"  # the resource violates the control
STATUS_PASS = "pass"  # the resource satisfies the control
STATUS_ERROR = "error"  # the check could not be evaluated (e.g. access denied)
VALID_STATUSES = (STATUS_FAIL, STATUS_PASS, STATUS_ERROR)


@dataclass
class Finding:
    """A single security observation about one cloud resource."""

    check_id: str
    title: str
    provider: str
    resource_id: str
    resource_type: str
    severity: Severity
    status: str = STATUS_FAIL
    description: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.severity, Severity):
            self.severity = Severity.from_name(str(self.severity))
        if self.status not in VALID_STATUSES:
            raise ValueError(
                f"Invalid status {self.status!r}; expected one of {VALID_STATUSES}"
            )

    @property
    def is_failure(self) -> bool:
        return self.status == STATUS_FAIL

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "provider": self.provider,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "severity": self.severity.name,
            "status": self.status,
            "description": self.description,
            "remediation": self.remediation,
            "references": list(self.references),
            "evidence": dict(self.evidence),
        }


# SARIF severity level per our Severity (SARIF only has error/warning/note).
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


@dataclass
class Report:
    """A collection of findings with convenience aggregation/serialization."""

    findings: List[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend(self, findings: List[Finding]) -> None:
        self.findings.extend(findings)

    def failures(self) -> List[Finding]:
        return [f for f in self.findings if f.is_failure]

    def summary(self) -> Dict[str, Any]:
        """Return counts by status and by severity (failures only)."""
        by_status: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        for f in self.findings:
            by_status[f.status] = by_status.get(f.status, 0) + 1
            if f.is_failure:
                by_severity[f.severity.name] = by_severity.get(f.severity.name, 0) + 1
        return {
            "total": len(self.findings),
            "failures": len(self.failures()),
            "by_status": by_status,
            "by_severity": by_severity,
        }

    def highest_severity(self) -> Optional[Severity]:
        fails = self.failures()
        if not fails:
            return None
        return max(f.severity for f in fails)

    def to_dict(self, failures_only: bool = False) -> Dict[str, Any]:
        items = self.failures() if failures_only else self.findings
        return {
            "summary": self.summary(),
            "findings": [f.to_dict() for f in items],
        }

    def to_json(self, indent: int = 2, failures_only: bool = False) -> str:
        return json.dumps(self.to_dict(failures_only=failures_only), indent=indent, sort_keys=True)

    def to_sarif(self) -> Dict[str, Any]:
        """Export failures as a minimal SARIF 2.1.0 document.

        SARIF is broadly consumable by security dashboards and CI systems,
        which makes STRIX_CLOUD findings portable across tooling.
        """
        fails = self.failures()
        rules_by_id: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []
        for f in fails:
            if f.check_id not in rules_by_id:
                rules_by_id[f.check_id] = {
                    "id": f.check_id,
                    "name": f.check_id,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description or f.title},
                    "helpUri": f.references[0] if f.references else None,
                    "properties": {"security-severity": _security_severity(f.severity)},
                }
            results.append(
                {
                    "ruleId": f.check_id,
                    "level": _SARIF_LEVEL.get(f.severity, "warning"),
                    "message": {
                        "text": f"{f.title} on {f.resource_type} '{f.resource_id}' ({f.provider})."
                    },
                    "locations": [
                        {
                            "logicalLocations": [
                                {
                                    "name": f.resource_id,
                                    "kind": f.resource_type,
                                }
                            ]
                        }
                    ],
                    "properties": {"provider": f.provider, "evidence": f.evidence},
                }
            )
        rules = list(rules_by_id.values())
        for r in rules:
            if r.get("helpUri") is None:
                r.pop("helpUri", None)
        return {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "STRIX_CLOUD",
                            "informationUri": "https://example.com/STRIX_CLOUD",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }

    def to_sarif_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_sarif(), indent=indent, sort_keys=True)


def _security_severity(severity: Severity) -> str:
    """Map to the numeric CVSS-like band used by SARIF consumers (GitHub)."""
    return {
        Severity.CRITICAL: "9.5",
        Severity.HIGH: "8.0",
        Severity.MEDIUM: "5.0",
        Severity.LOW: "3.0",
        Severity.INFO: "0.0",
    }[severity]
