"""Provider-neutral security findings model for STRIX_CLOUD.

Findings are *observations*, not actions. This module only structures results
produced by connectors/analyzers so the orchestrator can aggregate, group and
report them uniformly (JSON, SARIF, Markdown, CSV).

Phase A of the red-team roadmap enriches findings so they are actionable for a
pentester: each carries the account/region it belongs to, the ATT&CK technique
ids it maps to, a `verification` step (how to reproduce it), and a stable
`fingerprint` for dedup and snapshot diffing.
"""
from __future__ import annotations

import csv
import enum
import io
import json
from dataclasses import dataclass, field
from hashlib import sha256
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
    # --- red-team enrichment (Phase A) ---
    account_id: str = ""
    region: str = ""
    mitre: List[str] = field(default_factory=list)
    verification: str = ""

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

    @property
    def fingerprint(self) -> str:
        """Stable id for dedup / snapshot diffing."""
        key = "|".join([self.provider, self.account_id, self.check_id, self.resource_id])
        return sha256(key.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "check_id": self.check_id,
            "title": self.title,
            "provider": self.provider,
            "account_id": self.account_id,
            "region": self.region,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "severity": self.severity.name,
            "status": self.status,
            "mitre": list(self.mitre),
            "description": self.description,
            "remediation": self.remediation,
            "verification": self.verification,
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
    """A collection of findings with aggregation/serialization helpers."""

    findings: List[Finding] = field(default_factory=list)
    run_id: str = ""
    operator: str = ""
    started_at: str = ""

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend(self, findings: List[Finding]) -> None:
        self.findings.extend(findings)

    def failures(self) -> List[Finding]:
        return [f for f in self.findings if f.is_failure]

    def deduplicate(self) -> "Report":
        """Return a new Report keeping one finding per fingerprint."""
        seen: Dict[str, Finding] = {}
        for f in self.findings:
            seen.setdefault(f.fingerprint, f)
        return Report(
            findings=list(seen.values()),
            run_id=self.run_id,
            operator=self.operator,
            started_at=self.started_at,
        )

    def by_account(self) -> Dict[str, List[Finding]]:
        groups: Dict[str, List[Finding]] = {}
        for f in self.findings:
            groups.setdefault(f.account_id or "(unknown)", []).append(f)
        return groups

    def by_resource(self) -> Dict[str, List[Finding]]:
        groups: Dict[str, List[Finding]] = {}
        for f in self.findings:
            groups.setdefault(f.resource_id, []).append(f)
        return groups

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

    def _meta(self) -> Dict[str, Any]:
        return {"run_id": self.run_id, "operator": self.operator, "started_at": self.started_at}

    def to_dict(self, failures_only: bool = False) -> Dict[str, Any]:
        items = self.failures() if failures_only else self.findings
        return {
            "run": self._meta(),
            "summary": self.summary(),
            "findings": [f.to_dict() for f in items],
        }

    def to_json(self, indent: int = 2, failures_only: bool = False) -> str:
        return json.dumps(self.to_dict(failures_only=failures_only), indent=indent, sort_keys=True)

    def to_markdown(self, failures_only: bool = True) -> str:
        """Human-readable report for a pentest deliverable."""
        items = self.failures() if failures_only else self.findings
        summary = self.summary()
        lines: List[str] = ["# STRIX_CLOUD findings", ""]
        if self.run_id or self.operator:
            lines.append(f"_run `{self.run_id}` · operator `{self.operator}` · {self.started_at}_")
            lines.append("")
        parts = ", ".join(f"{k}={v}" for k, v in sorted(summary["by_severity"].items()))
        lines.append(f"**{summary['failures']} failures** ({parts or 'none'}) of {summary['total']} checks.")
        lines.append("")
        for f in sorted(items, key=lambda x: (-int(x.severity), x.check_id)):
            mitre = f", ATT&CK {', '.join(f.mitre)}" if f.mitre else ""
            lines.append(f"## [{f.severity.name}] {f.title}{mitre}")
            loc = f"{f.provider}"
            if f.account_id:
                loc += f" · {f.account_id}"
            if f.region:
                loc += f" · {f.region}"
            lines.append(f"- **Resource:** `{f.resource_id}` ({f.resource_type}) — {loc}")
            lines.append(f"- **Check:** `{f.check_id}` · fingerprint `{f.fingerprint}`")
            if f.description:
                lines.append(f"- **Impact:** {f.description}")
            if f.verification:
                lines.append(f"- **Verify:** `{f.verification}`")
            if f.remediation:
                lines.append(f"- **Fix:** {f.remediation}")
            lines.append("")
        return "\n".join(lines)

    def to_csv(self, failures_only: bool = False) -> str:
        items = self.failures() if failures_only else self.findings
        buf = io.StringIO()
        cols = [
            "fingerprint", "severity", "status", "provider", "account_id", "region",
            "check_id", "resource_type", "resource_id", "mitre", "verification",
        ]
        writer = csv.writer(buf)
        writer.writerow(cols)
        for f in items:
            writer.writerow([
                f.fingerprint, f.severity.name, f.status, f.provider, f.account_id,
                f.region, f.check_id, f.resource_type, f.resource_id,
                " ".join(f.mitre), f.verification,
            ])
        return buf.getvalue()

    def to_html(self) -> str:
        """Self-contained single-file HTML report (operator-facing)."""
        from agents.report.html import render_html

        return render_html(self)

    def to_sarif(self) -> Dict[str, Any]:
        """Export failures as a minimal SARIF 2.1.0 document."""
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
                    "properties": {
                        "security-severity": _security_severity(f.severity),
                        "tags": list(f.mitre),
                    },
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
                                {"name": f.resource_id, "kind": f.resource_type}
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
