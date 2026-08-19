from agents.plugins import loader


def test_all_connectors_discoverable():
    conns = loader.discover_connectors()
    # Expect at least aws, azure, gcp connectors
    for expected in ("aws_connector", "azure_connector", "gcp_connector"):
        assert expected in conns
