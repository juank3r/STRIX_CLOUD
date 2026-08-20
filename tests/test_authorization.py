import pytest

from agents.common import authorization as authz

SCOPE = {"authorized_by": "me@example.com", "allow": ["123456789012", "sub-1"]}


def test_authorize_allows_listed_target():
    ok, _ = authz.authorize_target(SCOPE, "123456789012")
    assert ok


def test_authorize_denies_unlisted_target():
    ok, reason = authz.authorize_target(SCOPE, "999999999999")
    assert not ok
    assert "allowlist" in reason


def test_authorize_denies_missing_target():
    ok, reason = authz.authorize_target(SCOPE, None)
    assert not ok
    assert "no target" in reason


def test_authorize_requires_authorized_by():
    ok, reason = authz.authorize_target({"allow": ["x"]}, "x")
    assert not ok
    assert "authorized_by" in reason


def test_window_expired_is_denied():
    scope = {"authorized_by": "me", "allow": ["x"], "not_after": "2000-01-01T00:00:00Z"}
    ok, reason = authz.authorize_target(scope, "x")
    assert not ok
    assert "expired" in reason


def test_window_not_started_is_denied():
    scope = {"authorized_by": "me", "allow": ["x"], "not_before": "2999-01-01T00:00:00Z"}
    ok, reason = authz.authorize_target(scope, "x")
    assert not ok
    assert "not started" in reason


def test_require_authorization_raises_on_deny():
    with pytest.raises(authz.AuthorizationError):
        authz.require_authorization(SCOPE, "repo", "aws", "999999999999")


def test_require_authorization_ok_does_not_raise():
    authz.require_authorization(SCOPE, "repo", "azure", "sub-1")


def test_target_id_from_config():
    assert authz.target_id_from_config({"subscription_id": "sub-1"}) == "sub-1"
    assert authz.target_id_from_config({"account_id": "123"}) == "123"
    assert authz.target_id_from_config({"region": "us-east-1"}) is None
