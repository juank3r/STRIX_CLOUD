import pytest

from agents.plugins import aws_connector, azure_connector, gcp_connector
from agents.cloud_gateway import GatewayError


def test_aws_audit_called_on_validate(monkeypatch):
    calls = []

    def fake_audit(event, details):
        calls.append((event, details))

    monkeypatch.setattr("agents.common.audit.audit", fake_audit)

    conn = aws_connector.Connector(config={})
    with pytest.raises(GatewayError):
        conn.validate_permissions()

    # Expect that validate attempt and failed event were logged
    assert any(e[0] == "connector.validate" for e in calls)
    assert any("failed" in e[0] for e in calls)


def test_azure_audit_called_on_validate(monkeypatch):
    calls = []

    def fake_audit(event, details):
        calls.append((event, details))

    monkeypatch.setattr("agents.common.audit.audit", fake_audit)

    conn = azure_connector.Connector(config={})
    with pytest.raises(GatewayError):
        conn.validate_permissions()

    assert any(e[0] == "connector.validate" for e in calls)
    assert any("failed" in e[0] for e in calls)


def test_gcp_audit_called_on_validate(monkeypatch):
    calls = []

    def fake_audit(event, details):
        calls.append((event, details))

    monkeypatch.setattr("agents.common.audit.audit", fake_audit)

    conn = gcp_connector.Connector(config={})
    with pytest.raises(GatewayError):
        conn.validate_permissions()

    assert any(e[0] == "connector.validate" for e in calls)
    assert any("failed" in e[0] for e in calls)
