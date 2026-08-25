from agents.common import authorization as authz

SCOPE = {"authorized_by": "me@example.com", "allow": ["123", "456"], "deny": ["456"]}


def test_denylist_beats_allow():
    ok, reason = authz.authorize_target(SCOPE, "456")
    assert not ok
    assert "denylist" in reason


def test_allowed_target_still_authorized():
    ok, _ = authz.authorize_target(SCOPE, "123")
    assert ok


def test_require_authorization_records_operator_and_engagement(monkeypatch):
    events = []
    monkeypatch.setattr("agents.common.audit.audit", lambda e, d: events.append((e, d)))
    scope = {"authorized_by": "me", "allow": ["123"], "operator": "alice", "engagement": "ENG-7"}
    authz.require_authorization(scope, "repo", "aws", "123")
    granted = [d for e, d in events if e == "authorization.granted"]
    assert granted and granted[0]["operator"] == "alice"
    assert granted[0]["engagement"] == "ENG-7"
