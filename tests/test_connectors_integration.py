import types

from agents.plugins import aws_connector, azure_connector, gcp_connector


def test_aws_connector_with_mocked_boto3(monkeypatch):
    # Create fake boto3 with client that returns predictable data
    class FakeS3:
        def __init__(self, *args, **kwargs):
            pass

        def list_buckets(self):
            return {"Buckets": [{"Name": "bucket-a"}, {"Name": "bucket-b"}]}

        def get_bucket_location(self, Bucket):
            return {"LocationConstraint": "us-west-2"}

    fake_boto3 = types.SimpleNamespace()
    fake_boto3.client = lambda service, region_name=None: FakeS3()

    monkeypatch.setattr(aws_connector, "boto3", fake_boto3, raising=False)

    conn = aws_connector.Connector(config={"region": "us-west-2"})
    assert conn.validate_permissions()
    resources = conn.list_resources()
    assert "bucket-a" in resources
    res = conn.run_safe_check("bucket-a")
    assert res.get("location") == "us-west-2" or res.get("bucket") == "bucket-a"


def test_azure_connector_with_mocked_sdk(monkeypatch):
    # Fake Azure Credential and ResourceManagementClient
    class FakeRG:
        def __init__(self, name, location):
            self.name = name
            self.location = location

    class FakeRGClient:
        def __init__(self, cred, subscription_id):
            pass

        def resource_groups(self):
            # not used
            return None

        def list(self):
            return [types.SimpleNamespace(name="rg-a"), types.SimpleNamespace(name="rg-b")]

        def get(self, name):
            return FakeRG(name, "eastus")

    def fake_default_cred():
        return None

    def fake_rm_client(cred, sub):
        groups = [types.SimpleNamespace(name="rg-a"), types.SimpleNamespace(name="rg-b")]
        return types.SimpleNamespace(
            resource_groups=types.SimpleNamespace(
                list=lambda: groups,
                get=lambda n: types.SimpleNamespace(name=n, location="eastus"),
            )
        )

    monkeypatch.setattr(azure_connector, "DefaultAzureCredential", fake_default_cred, raising=False)
    monkeypatch.setattr(azure_connector, "ResourceManagementClient", fake_rm_client, raising=False)

    conn = azure_connector.Connector(config={"subscription_id": "sub-123"})
    assert conn.validate_permissions()
    groups = conn.list_resources()
    assert "rg-a" in groups
    details = conn.run_safe_check("rg-a")
    assert details.get("location") == "eastus"


def test_gcp_connector_with_mocked_storage(monkeypatch):
    class FakeBucket:
        def __init__(self, name):
            self.name = name
            self.location = "us-central1"

    class FakeClient:
        def list_buckets(self):
            return [FakeBucket("gcp-a"), FakeBucket("gcp-b")]

        def get_bucket(self, name):
            return FakeBucket(name)

    fake_storage = types.SimpleNamespace(Client=lambda: FakeClient())
    monkeypatch.setattr(gcp_connector, "storage", fake_storage, raising=False)

    conn = gcp_connector.Connector(config={})
    assert conn.validate_permissions()
    buckets = conn.list_resources()
    assert "gcp-a" in buckets
    info = conn.run_safe_check("gcp-a")
    assert info.get("bucket") == "gcp-a"
