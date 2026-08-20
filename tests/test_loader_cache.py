from agents.plugins import loader


def test_discover_is_cached():
    loader.clear_cache()
    first = loader.discover_connectors()
    second = loader.discover_connectors()
    # Same cached object returned — no re-import on the second call.
    assert first is second
    assert "aws_connector" in first


def test_clear_cache_resets():
    loader.clear_cache()
    first = loader.discover_connectors()
    loader.clear_cache()
    fresh = loader.discover_connectors()
    assert first is not fresh
    assert set(first) == set(fresh)
