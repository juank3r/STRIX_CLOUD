import json
import types

from agents.common.findings import STATUS_FAIL, STATUS_PASS, Severity
from agents.plugins import aws_connector, azure_connector, gcp_connector


def _by_check(findings):
    return {f.check_id: f for f in findings}


# --- AWS -----------------------------------------------------------------

class _FakeS3:
    def __init__(self, secure: bool):
        self.secure = secure

    def list_buckets(self):
        return {"Buckets": [{"Name": "the-bucket"}]}

    def get_public_access_block(self, Bucket):
        if self.secure:
            return {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            }
        raise Exception("NoSuchPublicAccessBlockConfiguration")

    def get_bucket_policy_status(self, Bucket):
        return {"PolicyStatus": {"IsPublic": not self.secure}}

    def get_bucket_policy(self, Bucket):
        if self.secure:
            policy = {
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                    }
                ]
            }
            return {"Policy": json.dumps(policy)}
        raise Exception("NoSuchBucketPolicy")

    def get_bucket_encryption(self, Bucket):
        if self.secure:
            return {"ServerSideEncryptionConfiguration": {"Rules": [{"x": 1}]}}
        raise Exception("ServerSideEncryptionConfigurationNotFoundError")

    def get_bucket_versioning(self, Bucket):
        return {"Status": "Enabled"} if self.secure else {}

    def get_bucket_logging(self, Bucket):
        return {"LoggingEnabled": {"TargetBucket": "logs"}} if self.secure else {}


def test_aws_insecure_bucket_flags_all_controls(monkeypatch):
    conn = aws_connector.Connector({"region": "us-east-1"})
    monkeypatch.setattr(conn, "_s3_client", lambda: _FakeS3(secure=False))
    findings = _by_check(conn.run_security_checks())
    assert findings["STORAGE_PUBLIC_ACCESS"].status == STATUS_FAIL
    assert findings["STORAGE_PUBLIC_ACCESS"].severity is Severity.HIGH
    assert findings["STORAGE_SECURE_TRANSPORT"].status == STATUS_FAIL
    assert findings["STORAGE_ENCRYPTION"].status == STATUS_FAIL
    assert findings["STORAGE_VERSIONING"].status == STATUS_FAIL
    assert findings["STORAGE_LOGGING"].status == STATUS_FAIL


def test_aws_secure_bucket_passes(monkeypatch):
    conn = aws_connector.Connector({"region": "us-east-1"})
    monkeypatch.setattr(conn, "_s3_client", lambda: _FakeS3(secure=True))
    findings = _by_check(conn.run_security_checks())
    assert all(f.status == STATUS_PASS for f in findings.values())


def test_aws_security_skips_without_sdk():
    conn = aws_connector.Connector({"region": "us-east-1"})
    # No client seam override and boto3 is None -> gracefully returns nothing.
    assert conn._s3_client() is None
    assert conn.run_security_checks() == []


# --- Azure ---------------------------------------------------------------

def _azure_account(secure: bool):
    return types.SimpleNamespace(
        name="acct",
        id="/subscriptions/s/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/acct",
        allow_blob_public_access=False if secure else True,
        enable_https_traffic_only=True if secure else False,
        encryption=types.SimpleNamespace(
            key_source="Microsoft.Keyvault" if secure else "Microsoft.Storage"
        ),
    )


def _azure_client(secure: bool):
    account = _azure_account(secure)
    blob_services = types.SimpleNamespace(
        get_service_properties=lambda rg, name: types.SimpleNamespace(is_versioning_enabled=secure)
    )
    return types.SimpleNamespace(
        storage_accounts=types.SimpleNamespace(list=lambda: [account]),
        blob_services=blob_services,
    )


def test_azure_insecure_account_flags_controls(monkeypatch):
    conn = azure_connector.Connector({"subscription_id": "sub"})
    monkeypatch.setattr(conn, "_storage_mgmt_client", lambda: _azure_client(secure=False))
    findings = _by_check(conn.run_security_checks())
    assert findings["STORAGE_PUBLIC_ACCESS"].status == STATUS_FAIL
    assert findings["STORAGE_SECURE_TRANSPORT"].status == STATUS_FAIL
    assert findings["STORAGE_ENCRYPTION"].status == STATUS_FAIL
    # CMK missing is downgraded to LOW because Azure encrypts at rest by default.
    assert findings["STORAGE_ENCRYPTION"].severity is Severity.LOW
    assert findings["STORAGE_VERSIONING"].status == STATUS_FAIL


def test_azure_secure_account_passes(monkeypatch):
    conn = azure_connector.Connector({"subscription_id": "sub"})
    monkeypatch.setattr(conn, "_storage_mgmt_client", lambda: _azure_client(secure=True))
    findings = _by_check(conn.run_security_checks())
    assert all(f.status == STATUS_PASS for f in findings.values())


# --- GCP -----------------------------------------------------------------

class _FakeGcsBucket:
    def __init__(self, secure: bool):
        self.name = "gcs-bucket"
        self.default_kms_key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k" if secure else None
        self.versioning_enabled = secure
        self.logging = {"logBucket": "logs"} if secure else None
        self._secure = secure

    def get_iam_policy(self):
        members = ["user:alice@example.com"] if self._secure else ["allUsers"]
        return types.SimpleNamespace(
            bindings=[{"role": "roles/storage.objectViewer", "members": members}]
        )


def _gcs_client(secure: bool):
    return types.SimpleNamespace(list_buckets=lambda: [_FakeGcsBucket(secure)])


def test_gcp_insecure_bucket_flags_controls(monkeypatch):
    conn = gcp_connector.Connector({})
    monkeypatch.setattr(conn, "_gcs_client", lambda: _gcs_client(secure=False))
    findings = _by_check(conn.run_security_checks())
    assert findings["STORAGE_PUBLIC_ACCESS"].status == STATUS_FAIL
    assert findings["STORAGE_SECURE_TRANSPORT"].status == STATUS_PASS  # GCS is HTTPS-only
    assert findings["STORAGE_ENCRYPTION"].status == STATUS_FAIL
    assert findings["STORAGE_ENCRYPTION"].severity is Severity.LOW
    assert findings["STORAGE_VERSIONING"].status == STATUS_FAIL
    assert findings["STORAGE_LOGGING"].status == STATUS_FAIL


def test_gcp_secure_bucket_passes(monkeypatch):
    conn = gcp_connector.Connector({})
    monkeypatch.setattr(conn, "_gcs_client", lambda: _gcs_client(secure=True))
    findings = _by_check(conn.run_security_checks())
    assert all(f.status == STATUS_PASS for f in findings.values())


# --- Network: AWS security groups ---------------------------------------

class _FakeEC2:
    def describe_security_groups(self):
        return {
            "SecurityGroups": [
                {
                    "GroupId": "sg-admin",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                },
                {
                    "GroupId": "sg-web",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 8080,
                            "ToPort": 8080,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                },
                {
                    "GroupId": "sg-ok",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                        }
                    ],
                },
            ]
        }


def _net(findings):
    return {
        f.resource_id: f
        for f in findings
        if f.check_id == "NETWORK_UNRESTRICTED_INGRESS"
    }


def test_aws_network_ingress(monkeypatch):
    conn = aws_connector.Connector({"region": "us-east-1"})
    monkeypatch.setattr(conn, "_s3_client", lambda: None)
    monkeypatch.setattr(conn, "_ec2_client", lambda: _FakeEC2())
    net = _net(conn.run_security_checks())
    assert net["sg-admin"].status == STATUS_FAIL
    assert net["sg-admin"].severity is Severity.CRITICAL  # SSH open to world
    assert net["sg-web"].status == STATUS_FAIL
    assert net["sg-web"].severity is Severity.HIGH
    assert net["sg-ok"].status == STATUS_PASS


# --- Network: Azure NSGs -------------------------------------------------

def _azure_rule(name, source, port):
    return types.SimpleNamespace(
        name=name,
        direction="Inbound",
        access="Allow",
        source_address_prefix=source,
        source_address_prefixes=None,
        destination_port_range=port,
        destination_port_ranges=None,
        protocol="Tcp",
    )


def _azure_net_client():
    nsgs = [
        types.SimpleNamespace(name="nsg-admin", security_rules=[_azure_rule("r", "*", "3389")]),
        types.SimpleNamespace(name="nsg-web", security_rules=[_azure_rule("r", "Internet", "8080")]),
        types.SimpleNamespace(name="nsg-ok", security_rules=[_azure_rule("r", "10.0.0.0/8", "22")]),
    ]
    return types.SimpleNamespace(
        network_security_groups=types.SimpleNamespace(list_all=lambda: nsgs)
    )


def test_azure_network_ingress(monkeypatch):
    conn = azure_connector.Connector({"subscription_id": "sub"})
    monkeypatch.setattr(conn, "_storage_mgmt_client", lambda: None)
    monkeypatch.setattr(conn, "_network_mgmt_client", lambda: _azure_net_client())
    net = _net(conn.run_security_checks())
    assert net["nsg-admin"].status == STATUS_FAIL
    assert net["nsg-admin"].severity is Severity.CRITICAL  # RDP open to world
    assert net["nsg-web"].status == STATUS_FAIL
    assert net["nsg-web"].severity is Severity.HIGH
    assert net["nsg-ok"].status == STATUS_PASS


# --- Network: GCP firewalls ---------------------------------------------

def _gcp_fw_client():
    firewalls = [
        types.SimpleNamespace(
            name="fw-admin",
            direction="INGRESS",
            disabled=False,
            source_ranges=["0.0.0.0/0"],
            allowed=[{"IPProtocol": "tcp", "ports": ["22"]}],
        ),
        types.SimpleNamespace(
            name="fw-web",
            direction="INGRESS",
            disabled=False,
            source_ranges=["0.0.0.0/0"],
            allowed=[{"IPProtocol": "tcp", "ports": ["8080"]}],
        ),
        types.SimpleNamespace(
            name="fw-ok",
            direction="INGRESS",
            disabled=False,
            source_ranges=["10.0.0.0/8"],
            allowed=[{"IPProtocol": "tcp", "ports": ["22"]}],
        ),
        types.SimpleNamespace(
            name="fw-egress",
            direction="EGRESS",
            disabled=False,
            source_ranges=["0.0.0.0/0"],
            allowed=[{"IPProtocol": "tcp", "ports": ["22"]}],
        ),
    ]
    return types.SimpleNamespace(list=lambda project=None: firewalls)


def test_gcp_network_ingress(monkeypatch):
    conn = gcp_connector.Connector({"project": "my-project"})
    monkeypatch.setattr(conn, "_gcs_client", lambda: None)
    monkeypatch.setattr(conn, "_firewalls_client", lambda: _gcp_fw_client())
    net = _net(conn.run_security_checks())
    assert net["fw-admin"].status == STATUS_FAIL
    assert net["fw-admin"].severity is Severity.CRITICAL  # SSH open to world
    assert net["fw-web"].status == STATUS_FAIL
    assert net["fw-web"].severity is Severity.HIGH
    assert net["fw-ok"].status == STATUS_PASS
    assert net["fw-egress"].status == STATUS_PASS  # egress is ignored


# --- Exposure: AWS live public instances --------------------------------

class _FakeEC2Exposure:
    def describe_security_groups(self):
        return {
            "SecurityGroups": [
                {
                    "GroupId": "sg-open",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                },
                {
                    "GroupId": "sg-restricted",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                        }
                    ],
                },
            ]
        }

    def describe_instances(self):
        return {
            "Reservations": [
                {
                    "Instances": [
                        {"InstanceId": "i-exposed", "PublicIpAddress": "1.2.3.4",
                         "SecurityGroups": [{"GroupId": "sg-open"}]},
                        {"InstanceId": "i-private",
                         "SecurityGroups": [{"GroupId": "sg-open"}]},
                        {"InstanceId": "i-safe", "PublicIpAddress": "5.6.7.8",
                         "SecurityGroups": [{"GroupId": "sg-restricted"}]},
                        {"InstanceId": "i-nic",
                         "SecurityGroups": [{"GroupId": "sg-open"}],
                         "NetworkInterfaces": [{"Association": {"PublicIp": "9.9.9.9"}}]},
                    ]
                }
            ]
        }


def test_aws_exposure_correlates_public_instance(monkeypatch):
    conn = aws_connector.Connector({"region": "us-east-1"})
    monkeypatch.setattr(conn, "_s3_client", lambda: None)
    monkeypatch.setattr(conn, "_ec2_client", lambda: _FakeEC2Exposure())
    findings = conn.run_security_checks()
    exp = {f.resource_id: f for f in findings if f.check_id == "EXPOSURE_INSTANCE_ADMIN_PORT"}
    # Only public instances behind a world-open admin SG are flagged.
    assert set(exp.keys()) == {"i-exposed", "i-nic"}
    assert exp["i-exposed"].severity is Severity.CRITICAL
    assert 22 in exp["i-exposed"].evidence["open_admin_ports"]
    assert exp["i-nic"].evidence["public_ip"] == "9.9.9.9"
    assert "T1190" in exp["i-exposed"].mitre
