"""Operator-facing narrative: 'start here' prioritization and target extract.

Turns a flat list of findings into what a red-teamer actually wants: a short,
ranked, plain-language "do this first" list — including *attack chains* that
correlate several findings (e.g. an internet-reachable host that also runs an
administrator identity in the same account) — plus a chainable list of concrete
targets (public IPs/ports, public buckets, admin principals) to feed other tools.

Inspired by the GLAMDRING narrative/story pattern: the same plain sentence is
reused everywhere so the report never contradicts itself.
"""
from __future__ import annotations

from typing import Any, Dict, List

from agents.common.findings import Finding, Report

EXPOSURE = "EXPOSURE_INSTANCE_ADMIN_PORT"
ADMIN = "IAM_ADMIN_PRINCIPAL"
PUBLIC_STORAGE = "STORAGE_PUBLIC_ACCESS"
OPEN_INGRESS = "NETWORK_UNRESTRICTED_INGRESS"

# Extra exploitability weight on top of severity: internet-reachable and
# admin-identity findings are what an attacker chains first.
_BONUS = {EXPOSURE: 5, ADMIN: 4, PUBLIC_STORAGE: 3, OPEN_INGRESS: 2}


def _weight(f: Finding) -> int:
    return int(f.severity) * 2 + _BONUS.get(f.check_id, 0)


def describe(f: Finding) -> str:
    """One plain-language sentence for a finding."""
    rid = f.resource_id
    if f.check_id == EXPOSURE:
        ports = f.evidence.get("open_admin_ports") or []
        ports_s = "/".join(str(p) for p in ports) or "admin ports"
        ip = f.evidence.get("public_ip", "")
        loc = f" at {ip}" if ip else ""
        return f"Instance {rid} is reachable from the internet on {ports_s}{loc}."
    if f.check_id == ADMIN:
        kind = f.resource_type.split("_")[-1] or "principal"
        return f"{kind.title()} {rid} has effective administrator access."
    if f.check_id == PUBLIC_STORAGE:
        return f"Storage {rid} is publicly readable."
    if f.check_id == OPEN_INGRESS:
        return f"Firewall {rid} allows inbound from 0.0.0.0/0."
    return f"{f.title} ({rid})."


def top_findings(report: Report, limit: int = 5) -> List[Finding]:
    fails = sorted(
        report.failures(),
        key=lambda f: (-_weight(f), -int(f.severity), f.check_id, f.resource_id),
    )
    return fails[:limit]


def attack_chains(report: Report) -> List[Dict[str, Any]]:
    """Correlate an exposed host with an admin identity in the same account."""
    chains: List[Dict[str, Any]] = []
    by_acct: Dict[str, List[Finding]] = {}
    for f in report.failures():
        by_acct.setdefault(f.account_id or "(unknown)", []).append(f)
    for acct, items in sorted(by_acct.items()):
        exposed = [f for f in items if f.check_id == EXPOSURE]
        admins = [f for f in items if f.check_id == ADMIN]
        if exposed and admins:
            chains.append(
                {
                    "title": f"Reachable host + admin identity in account {acct}",
                    "severity": "CRITICAL",
                    "account": acct,
                    "steps": [
                        describe(exposed[0]),
                        describe(admins[0]),
                        "Landing on the exposed host puts the admin identity within reach.",
                    ],
                    "fingerprints": [exposed[0].fingerprint, admins[0].fingerprint],
                }
            )
    return chains


def start_here(report: Report, limit: int = 6) -> List[Dict[str, Any]]:
    """Ranked 'do this first' list: attack chains, then the top single findings."""
    out: List[Dict[str, Any]] = []
    used = set()
    for c in attack_chains(report):
        out.append({"kind": "chain", "title": c["title"], "severity": c["severity"], "steps": c["steps"]})
        used.update(c["fingerprints"])
    for f in top_findings(report, limit):
        if f.fingerprint in used or len(out) >= limit:
            continue
        out.append(
            {
                "kind": "finding",
                "title": describe(f),
                "severity": f.severity.name,
                "verification": f.verification,
            }
        )
    return out


def targets(report: Report) -> Dict[str, List[Dict[str, Any]]]:
    """Concrete, chainable targets extracted from failing findings."""
    hosts: List[Dict[str, Any]] = []
    storage: List[Dict[str, Any]] = []
    principals: List[Dict[str, Any]] = []
    ingress: List[Dict[str, Any]] = []
    for f in report.failures():
        if f.check_id == EXPOSURE:
            ip = f.evidence.get("public_ip")
            if ip:
                hosts.append(
                    {"ip": ip, "ports": f.evidence.get("open_admin_ports") or [],
                     "resource": f.resource_id, "account": f.account_id}
                )
        elif f.check_id == PUBLIC_STORAGE:
            storage.append({"resource": f.resource_id, "provider": f.provider, "account": f.account_id})
        elif f.check_id == ADMIN:
            principals.append({"resource": f.resource_id, "account": f.account_id})
        elif f.check_id == OPEN_INGRESS:
            ingress.append({"resource": f.resource_id, "provider": f.provider})
    return {
        "public_hosts": hosts,
        "public_storage": storage,
        "admin_principals": principals,
        "open_ingress": ingress,
    }


def targets_text(report: Report) -> str:
    """Flat, greppable target list to pipe into other tooling."""
    t = targets(report)
    lines: List[str] = []
    if t["public_hosts"]:
        lines.append("# public hosts\tip\tports\tresource")
        for h in t["public_hosts"]:
            ports = "/".join(str(p) for p in h["ports"])
            lines.append(f"{h['ip']}\t{ports}\t{h['resource']}")
    if t["public_storage"]:
        lines.append("# public storage\tresource\tprovider")
        for b in t["public_storage"]:
            lines.append(f"{b['resource']}\t{b['provider']}")
    if t["admin_principals"]:
        lines.append("# admin principals\tresource\taccount")
        for p in t["admin_principals"]:
            lines.append(f"{p['resource']}\t{p['account']}")
    if t["open_ingress"]:
        lines.append("# open ingress\tresource\tprovider")
        for r in t["open_ingress"]:
            lines.append(f"{r['resource']}\t{r['provider']}")
    return "\n".join(lines) + ("\n" if lines else "")
