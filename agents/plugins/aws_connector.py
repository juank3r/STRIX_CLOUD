"""AWS connector implementing CloudGateway.

Read-only / non-destructive checks only. Do NOT add destructive actions
without explicit written authorization and safeguards.

Security checks operate on S3 buckets using describe/get APIs exclusively.
"""
import json
from typing import Any, Dict, List

from agents.checks import catalog, network
from agents.cloud_gateway import CloudGateway, GatewayError
from agents.common import audit
from agents.common.findings import STATUS_ERROR, STATUS_FAIL, STATUS_PASS, Finding, Severity

# Optional SDK: imported at module level so it can be monkeypatched in tests
# and so a missing dependency degrades gracefully instead of crashing import.
try:  # pragma: no cover - import side effect
    import boto3  # type: ignore
except Exception:  # pragma: no cover
    boto3 = None


class Connector(CloudGateway):
    implemented_controls = (
        catalog.STORAGE_PUBLIC_ACCESS.id,
        catalog.STORAGE_SECURE_TRANSPORT.id,
        catalog.STORAGE_ENCRYPTION.id,
        catalog.STORAGE_VERSIONING.id,
        catalog.STORAGE_LOGGING.id,
        catalog.NETWORK_UNRESTRICTED_INGRESS.id,
        catalog.EXPOSURE_INSTANCE_ADMIN_PORT.id,
    )

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        # Bind the (possibly monkeypatched) module-level SDK reference.
        self.boto3 = boto3

    # -- client seams (overridable in tests) -----------------------------
    def _s3_client(self):
        if not self.boto3:
            return None
        return self.boto3.client("s3", region_name=self.config.get("region"))

    def _ec2_client(self):
        if not self.boto3:
            return None
        return self.boto3.client("ec2", region_name=self.config.get("region"))

    # -- CloudGateway core ----------------------------------------------
    def validate_permissions(self) -> bool:
        audit.audit("connector.validate", {"provider": "aws", "config_keys": list(self.config.keys())})
        if not self.boto3:
            audit.audit("connector.validate.failed", {"provider": "aws", "reason": "boto3_missing"})
            raise GatewayError("boto3 is not available; install optional deps to use AWS connector")
        if "region" not in self.config:
            audit.audit("connector.validate.failed", {"provider": "aws", "reason": "missing_region"})
            raise GatewayError("Missing 'region' in connector config")
        audit.audit("connector.validate.succeeded", {"provider": "aws"})
        return True

    def list_resources(self) -> Any:
        audit.audit("connector.list", {"provider": "aws"})
        client = self._s3_client()
        if client is None:
            audit.audit("connector.list.empty", {"provider": "aws", "reason": "boto3_missing"})
            return []
        names = self._bucket_names(client)
        audit.audit("connector.list.succeeded", {"provider": "aws", "count": len(names)})
        return names

    def run_safe_check(self, resource_id: str) -> Dict[str, Any]:
        audit.audit("connector.check", {"provider": "aws", "resource_id": resource_id})
        client = self._s3_client()
        if client is None:
            audit.audit(
                "connector.check.failed",
                {"provider": "aws", "resource_id": resource_id, "reason": "boto3_missing"},
            )
            return {"error": "boto3 not available"}
        resp = client.get_bucket_location(Bucket=resource_id)
        result = {"bucket": resource_id, "location": resp.get("LocationConstraint")}
        audit.audit("connector.check.succeeded", {"provider": "aws", "resource_id": resource_id})
        return result

    # -- security checks (CSPM) -----------------------------------------
    def run_security_checks(self) -> List[Finding]:
        findings: List[Finding] = []
        s3 = self._s3_client()
        if s3 is not None:
            audit.audit("connector.security.start", {"provider": "aws", "domain": "storage"})
            for name in self._bucket_names(s3):
                findings.extend(self._check_bucket(s3, name))
        else:
            audit.audit("connector.security.skipped", {"provider": "aws", "domain": "storage"})

        ec2 = self._ec2_client()
        if ec2 is not None:
            audit.audit("connector.security.start", {"provider": "aws", "domain": "network"})
            findings.extend(self._network_findings(ec2))
            audit.audit("connector.security.start", {"provider": "aws", "domain": "exposure"})
            findings.extend(self._exposure_findings(ec2))
        else:
            audit.audit("connector.security.skipped", {"provider": "aws", "domain": "network"})

        audit.audit(
            "connector.security.done",
            {"provider": "aws", "findings": len(findings), "failures": sum(f.is_failure for f in findings)},
        )
        return findings

    def _open_admin_sgs(self, client) -> Dict[str, list]:
        """Map security-group id -> list of admin ports it opens to 0.0.0.0/0."""
        out: Dict[str, list] = {}
        resp = client.describe_security_groups()
        for sg in resp.get("SecurityGroups", []):
            sg_id = sg.get("GroupId") or sg.get("GroupName")
            ports: list = []
            for perm in sg.get("IpPermissions", []):
                cidrs = [r.get("CidrIp") for r in perm.get("IpRanges", [])]
                cidrs += [r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", [])]
                if not any(network.is_open_cidr(c) for c in cidrs):
                    continue
                proto = perm.get("IpProtocol")
                from_port = perm.get("FromPort")
                to_port = perm.get("ToPort")
                if proto in ("-1", -1):
                    ports.append("all")
                    continue
                lo = 0 if from_port is None else int(from_port)
                hi = 65535 if to_port is None else int(to_port)
                ports.extend(p for p in network.ADMIN_PORTS if lo <= p <= hi)
            if ports and sg_id:
                out[sg_id] = sorted(set(ports), key=str)
        return out

    def _exposure_findings(self, client) -> List[Finding]:
        """Correlate live public instances with world-open admin ports."""
        ctl = catalog.EXPOSURE_INSTANCE_ADMIN_PORT
        out: List[Finding] = []
        open_admin = self._open_admin_sgs(client)
        if not open_admin:
            return out
        resp = client.describe_instances()
        for reservation in resp.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                iid = inst.get("InstanceId", "unknown")
                public_ip = inst.get("PublicIpAddress") or _public_ip_from_nics(inst)
                sg_ids = [g.get("GroupId") for g in inst.get("SecurityGroups", [])]
                exposed = [s for s in sg_ids if s in open_admin]
                if not (public_ip and exposed):
                    continue
                ports = sorted({p for s in exposed for p in open_admin[s]}, key=str)
                out.append(
                    ctl.finding(
                        "aws",
                        iid,
                        "ec2_instance",
                        status=STATUS_FAIL,
                        evidence={
                            "public_ip": public_ip,
                            "security_groups": exposed,
                            "open_admin_ports": ports,
                        },
                        severity=Severity.CRITICAL,
                        verification=(
                            f"aws ec2 describe-instances --instance-ids {iid} "
                            "--query 'Reservations[].Instances[].[PublicIpAddress,SecurityGroups]'"
                        ),
                    )
                )
        return out

    def _network_findings(self, client) -> List[Finding]:
        ctl = catalog.NETWORK_UNRESTRICTED_INGRESS
        out: List[Finding] = []
        resp = client.describe_security_groups()
        for sg in resp.get("SecurityGroups", []):
            sg_id = sg.get("GroupId") or sg.get("GroupName") or "unknown"
            open_rules = []
            admin = False
            for perm in sg.get("IpPermissions", []):
                cidrs = [r.get("CidrIp") for r in perm.get("IpRanges", [])]
                cidrs += [r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", [])]
                if not any(network.is_open_cidr(c) for c in cidrs):
                    continue
                proto = perm.get("IpProtocol")
                from_port = perm.get("FromPort")
                to_port = perm.get("ToPort")
                # "-1" protocol means all traffic/all ports.
                all_ports = proto in ("-1", -1)
                if all_ports or network.range_covers_admin(from_port, to_port):
                    admin = True
                open_rules.append(
                    {"protocol": proto, "from_port": from_port, "to_port": to_port}
                )
            if not open_rules:
                out.append(
                    ctl.finding("aws", sg_id, "security_group", status=STATUS_PASS, evidence={})
                )
                continue
            out.append(
                ctl.finding(
                    "aws",
                    sg_id,
                    "security_group",
                    status=STATUS_FAIL,
                    evidence={"open_rules": open_rules},
                    severity=Severity.CRITICAL if admin else Severity.HIGH,
                )
            )
        return out

    # -- helpers ---------------------------------------------------------
    @staticmethod
    def _bucket_names(client) -> List[str]:
        resp = client.list_buckets()
        return [b["Name"] for b in resp.get("Buckets", [])]

    def _check_bucket(self, client, name: str) -> List[Finding]:
        rtype = "s3_bucket"
        out: List[Finding] = [
            self._check_public_access(client, name, rtype),
            self._check_secure_transport(client, name, rtype),
            self._check_encryption(client, name, rtype),
            self._check_versioning(client, name, rtype),
            self._check_logging(client, name, rtype),
        ]
        return out

    def _check_public_access(self, client, name: str, rtype: str) -> Finding:
        ctl = catalog.STORAGE_PUBLIC_ACCESS
        evidence: Dict[str, Any] = {}
        try:
            pab = client.get_public_access_block(Bucket=name)
            cfg = pab.get("PublicAccessBlockConfiguration", {})
            evidence["public_access_block"] = cfg
            fully_blocked = all(
                cfg.get(k)
                for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
            )
        except Exception as exc:
            evidence["public_access_block"] = None
            evidence["public_access_block_error"] = str(exc)
            fully_blocked = False
        is_public = False
        try:
            status = client.get_bucket_policy_status(Bucket=name)
            is_public = bool(status.get("PolicyStatus", {}).get("IsPublic", False))
            evidence["policy_is_public"] = is_public
        except Exception as exc:
            evidence["policy_is_public"] = None
            evidence["policy_status_error"] = str(exc)
        violated = is_public or not fully_blocked
        return ctl.finding(
            provider="aws",
            resource_id=name,
            resource_type=rtype,
            status=STATUS_FAIL if violated else STATUS_PASS,
            evidence=evidence,
        )

    def _check_secure_transport(self, client, name: str, rtype: str) -> Finding:
        ctl = catalog.STORAGE_SECURE_TRANSPORT
        evidence: Dict[str, Any] = {}
        enforced = False
        try:
            resp = client.get_bucket_policy(Bucket=name)
            policy = json.loads(resp.get("Policy", "{}"))
            enforced = _policy_denies_insecure_transport(policy)
            evidence["has_policy"] = True
            evidence["enforces_secure_transport"] = enforced
        except Exception as exc:
            evidence["has_policy"] = False
            evidence["policy_error"] = str(exc)
        return ctl.finding(
            provider="aws",
            resource_id=name,
            resource_type=rtype,
            status=STATUS_PASS if enforced else STATUS_FAIL,
            evidence=evidence,
        )

    def _check_encryption(self, client, name: str, rtype: str) -> Finding:
        ctl = catalog.STORAGE_ENCRYPTION
        evidence: Dict[str, Any] = {}
        try:
            resp = client.get_bucket_encryption(Bucket=name)
            rules = resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            evidence["rules"] = rules
            encrypted = bool(rules)
            status = STATUS_PASS if encrypted else STATUS_FAIL
        except Exception as exc:
            # boto raises ServerSideEncryptionConfigurationNotFoundError when absent.
            evidence["encryption_error"] = str(exc)
            status = STATUS_FAIL
        return ctl.finding(
            provider="aws",
            resource_id=name,
            resource_type=rtype,
            status=status,
            evidence=evidence,
        )

    def _check_versioning(self, client, name: str, rtype: str) -> Finding:
        ctl = catalog.STORAGE_VERSIONING
        evidence: Dict[str, Any] = {}
        try:
            resp = client.get_bucket_versioning(Bucket=name)
            state = resp.get("Status")
            evidence["status"] = state
            enabled = state == "Enabled"
        except Exception as exc:
            evidence["versioning_error"] = str(exc)
            enabled = False
        return ctl.finding(
            provider="aws",
            resource_id=name,
            resource_type=rtype,
            status=STATUS_PASS if enabled else STATUS_FAIL,
            evidence=evidence,
        )

    def _check_logging(self, client, name: str, rtype: str) -> Finding:
        ctl = catalog.STORAGE_LOGGING
        evidence: Dict[str, Any] = {}
        try:
            resp = client.get_bucket_logging(Bucket=name)
            enabled = "LoggingEnabled" in resp
            evidence["logging_enabled"] = enabled
            status = STATUS_PASS if enabled else STATUS_FAIL
        except Exception as exc:
            evidence["logging_error"] = str(exc)
            status = STATUS_ERROR
        return ctl.finding(
            provider="aws",
            resource_id=name,
            resource_type=rtype,
            status=status,
            evidence=evidence,
            severity=Severity.LOW,
        )


def _public_ip_from_nics(inst: Dict[str, Any]):
    """Extract a public IP from an instance's network interfaces, if any."""
    for nic in inst.get("NetworkInterfaces", []):
        ip = (nic.get("Association") or {}).get("PublicIp")
        if ip:
            return ip
    return None


def _policy_denies_insecure_transport(policy: Dict[str, Any]) -> bool:
    """True if the bucket policy denies requests where aws:SecureTransport is false."""
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for st in statements:
        if st.get("Effect") != "Deny":
            continue
        cond = st.get("Condition", {})
        for op in ("Bool", "BoolIfExists"):
            val = cond.get(op, {}).get("aws:SecureTransport")
            if val in ("false", False, ["false"]):
                return True
    return False
