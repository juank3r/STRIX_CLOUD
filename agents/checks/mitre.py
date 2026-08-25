"""Minimal MITRE ATT&CK (Cloud matrix) catalog and resolver.

Adapted from the GLAMDRING project's ``mitre.py`` pattern (parent-technique
fallback), trimmed to the cloud techniques STRIX_CLOUD findings map to. It is
vendored (not imported) so STRIX_CLOUD stays independently installable.
"""
from __future__ import annotations

from typing import Dict, List, Tuple

# id -> (name, tactic slug)
TECHNIQUES: Dict[str, Tuple[str, str]] = {
    "T1078.004": ("Valid Accounts: Cloud Accounts", "initial-access"),
    "T1190": ("Exploit Public-Facing Application", "initial-access"),
    "T1199": ("Trusted Relationship", "initial-access"),
    "T1098": ("Account Manipulation", "persistence"),
    "T1098.001": ("Additional Cloud Credentials", "persistence"),
    "T1098.003": ("Additional Cloud Roles", "persistence"),
    "T1136.003": ("Create Account: Cloud Account", "persistence"),
    "T1548": ("Abuse Elevation Control Mechanism", "privilege-escalation"),
    "T1484.002": ("Trust Modification", "privilege-escalation"),
    "T1552": ("Unsecured Credentials", "credential-access"),
    "T1552.001": ("Credentials In Files", "credential-access"),
    "T1552.004": ("Private Keys", "credential-access"),
    "T1552.005": ("Cloud Instance Metadata API", "credential-access"),
    "T1528": ("Steal Application Access Token", "credential-access"),
    "T1580": ("Cloud Infrastructure Discovery", "discovery"),
    "T1526": ("Cloud Service Discovery", "discovery"),
    "T1619": ("Cloud Storage Object Discovery", "discovery"),
    "T1087.004": ("Account Discovery: Cloud Account", "discovery"),
    "T1530": ("Data from Cloud Storage", "collection"),
    "T1537": ("Transfer Data to Cloud Account", "exfiltration"),
    "T1578": ("Modify Cloud Compute Infrastructure", "defense-evasion"),
    "T1562.008": ("Impair Defenses: Disable or Modify Cloud Logs", "defense-evasion"),
    "T1496": ("Resource Hijacking", "impact"),
}


def technique(technique_id: str) -> Dict[str, str]:
    """Resolve an id to {id, name, tactic}, falling back to the parent technique."""
    tid = str(technique_id or "").strip().upper()
    if tid in TECHNIQUES:
        name, tactic = TECHNIQUES[tid]
        return {"id": tid, "name": name, "tactic": tactic}
    parent = tid.split(".", 1)[0]
    if parent in TECHNIQUES:
        name, tactic = TECHNIQUES[parent]
        return {"id": tid, "name": name, "tactic": tactic}
    return {"id": tid, "name": "", "tactic": ""}


def techniques(ids: List[str]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    seen = set()
    for raw in ids or []:
        item = technique(raw)
        if item["id"] and item["id"] not in seen:
            seen.add(item["id"])
            out.append(item)
    return out


def is_known(technique_id: str) -> bool:
    tid = str(technique_id or "").strip().upper()
    return tid in TECHNIQUES or tid.split(".", 1)[0] in TECHNIQUES
