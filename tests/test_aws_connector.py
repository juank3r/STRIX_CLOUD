import pytest

from agents.plugins import loader


def test_discover_connectors():
    conns = loader.discover_connectors()
    # At least our aws_connector should be discoverable
    assert "aws_connector" in conns


def test_load_aws_connector_minimal():
    inst = loader.load_connector("aws_connector", {"region": "us-east-1"})
    assert inst.config["region"] == "us-east-1"
