from agents.checks import catalog
from agents.plugins import aws_connector, azure_connector, gcp_connector

CONNECTORS = {
    "aws": aws_connector.Connector,
    "azure": azure_connector.Connector,
    "gcp": gcp_connector.Connector,
}


def test_core_controls_exist_in_catalog():
    for control_id in catalog.CORE_CONTROLS:
        assert control_id in catalog.CONTROLS


def test_every_connector_covers_core_controls():
    core = set(catalog.CORE_CONTROLS)
    for name, cls in CONNECTORS.items():
        implemented = set(cls.implemented_controls)
        missing = core - implemented
        assert not missing, f"{name} connector missing core controls: {missing}"


def test_implemented_controls_are_known():
    for name, cls in CONNECTORS.items():
        for control_id in cls.implemented_controls:
            assert control_id in catalog.CONTROLS, f"{name} declares unknown control {control_id}"


def test_control_finding_helper_defaults_and_overrides():
    ctl = catalog.STORAGE_ENCRYPTION
    f = ctl.finding("gcp", "b", "gcs_bucket")
    assert f.check_id == ctl.id
    assert f.severity is ctl.severity
    # Provider may downgrade residual risk via a severity override.
    lowered = ctl.finding("gcp", "b", "gcs_bucket", severity=catalog.Severity.LOW)
    assert lowered.severity is catalog.Severity.LOW
