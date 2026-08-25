"""Authorization gating for STRIX_CLOUD runs.

Ethics-by-code: before any connector touches a real cloud account, the run
must be covered by an explicit *scope* file that names the authorized target
accounts, who authorized it, and (optionally) a validity window. This turns
the project's ethical requirement ("authorized testing only") from a document
into an enforced precondition.

The scope file is YAML, e.g. ``examples/scope.yaml``:

    authorized_by: "security-team@example.com"
    not_before: "2026-01-01T00:00:00Z"
    not_after:  "2026-12-31T23:59:59Z"
    allow:
      - "00000000-0000-0000-0000-000000000000"   # Azure subscription id
      - "123456789012"                            # AWS account id
      - "my-gcp-project"                          # GCP project id
"""
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

import yaml

from agents.common import audit

# Connector-config keys that identify the cloud account being targeted.
TARGET_ID_KEYS = ("account_id", "subscription_id", "project_id", "project")


class AuthorizationError(Exception):
    """Raised when a run is not covered by an authorization scope."""


def load_scope(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise AuthorizationError(f"Scope file {path!r} must be a mapping")
    return data


def target_id_from_config(config: Dict[str, Any]) -> Optional[str]:
    """Extract the cloud account identifier from a connector config."""
    for key in TARGET_ID_KEYS:
        value = config.get(key)
        if value:
            return str(value)
    return None


def _parse_ts(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _within_window(scope: Dict[str, Any], now: datetime) -> Tuple[bool, str]:
    not_before = _parse_ts(scope.get("not_before"))
    not_after = _parse_ts(scope.get("not_after"))
    if not_before and now < not_before:
        return False, f"authorization window not started (not_before={not_before.isoformat()})"
    if not_after and now > not_after:
        return False, f"authorization window expired (not_after={not_after.isoformat()})"
    return True, "ok"


def authorize_target(
    scope: Dict[str, Any], target_id: Optional[str], now: Optional[datetime] = None
) -> Tuple[bool, str]:
    """Return (allowed, reason) for a single target id against the scope."""
    now = now or datetime.now(timezone.utc)

    if not scope.get("authorized_by"):
        return False, "scope is missing 'authorized_by'"

    ok, reason = _within_window(scope, now)
    if not ok:
        return False, reason

    allow = scope.get("allow") or []
    if not isinstance(allow, (list, tuple)):
        return False, "scope 'allow' must be a list of account ids"

    if target_id is None:
        return False, "connector config has no target account id to authorize"

    # A denylist marks explicitly out-of-scope targets (Rules of Engagement).
    deny = scope.get("deny") or []
    if str(target_id) in {str(d) for d in deny}:
        return False, f"target '{target_id}' is explicitly out of scope (denylist)"

    if target_id in {str(a) for a in allow}:
        return True, "authorized"
    return False, f"target '{target_id}' is not in the authorization allowlist"


def require_authorization(
    scope: Dict[str, Any],
    repo_name: str,
    provider: str,
    target_id: Optional[str],
    now: Optional[datetime] = None,
) -> None:
    """Authorize one repo/target or raise AuthorizationError. Always audits."""
    allowed, reason = authorize_target(scope, target_id, now=now)
    details = {
        "repo": repo_name,
        "provider": provider,
        "target": target_id,
        "authorized_by": scope.get("authorized_by"),
        "operator": scope.get("operator"),
        "engagement": scope.get("engagement"),
        "reason": reason,
    }
    if allowed:
        audit.audit("authorization.granted", details)
        return
    audit.audit("authorization.denied", details)
    raise AuthorizationError(f"{repo_name}: {reason}")
