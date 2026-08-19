def test_loader_audit_on_load(monkeypatch):
    calls = []

    def fake_audit(event, details):
        calls.append((event, details))

    monkeypatch.setattr("agents.common.audit.audit", fake_audit)

    # Import here to ensure loader uses monkeypatched audit
    from agents.plugins import loader

    # Load a known connector
    inst = loader.load_connector("aws_connector", {"region": "us-west-2"})
    assert inst is not None

    # Expect loader to have emitted a load audit entry
    assert any(e[0] == "connector.load" for e in calls)
