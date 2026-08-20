"""Shared helpers for network-exposure checks.

Provider connectors parse their own SDK shapes, but the notion of "open to
the world" and "exposes an administrative port" is identical across clouds, so
that logic lives here to keep the connectors consistent.
"""
from __future__ import annotations

from typing import Optional

# CIDRs meaning "anywhere on the internet".
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}

# Non-CIDR source tokens some providers use for the public internet.
OPEN_SOURCE_TOKENS = {"*", "internet", "any"} | {c.lower() for c in OPEN_CIDRS}

# Administrative ports whose public exposure is treated as critical.
ADMIN_PORTS = (22, 3389)


def is_open_cidr(value: Optional[str]) -> bool:
    """True if a CIDR string represents the whole internet."""
    if not value:
        return False
    return value.strip() in OPEN_CIDRS


def is_open_source_token(value: Optional[str]) -> bool:
    """True if an Azure/GCP source token represents the whole internet."""
    if not value:
        return False
    return value.strip().lower() in OPEN_SOURCE_TOKENS


def range_covers_admin(from_port: Optional[int], to_port: Optional[int]) -> bool:
    """True if a numeric port range covers an admin port (None == all ports)."""
    if from_port is None and to_port is None:
        return True  # all ports
    lo = 0 if from_port is None else int(from_port)
    hi = 65535 if to_port is None else int(to_port)
    if lo > hi:
        lo, hi = hi, lo
    return any(lo <= p <= hi for p in ADMIN_PORTS)


def token_covers_admin(port_token: Optional[str]) -> bool:
    """True if a string port token (e.g. '22', '0-65535', '*') covers admin ports."""
    if port_token is None:
        return True
    token = str(port_token).strip()
    if token in ("*", "", "0-65535"):
        return True
    if "-" in token:
        parts = token.split("-", 1)
        try:
            lo, hi = int(parts[0]), int(parts[1])
        except ValueError:
            return False
        return range_covers_admin(lo, hi)
    try:
        port = int(token)
    except ValueError:
        return False
    return port in ADMIN_PORTS


def any_token_covers_admin(port_tokens) -> bool:
    """True if any token in an iterable covers an admin port. Empty == all ports."""
    tokens = list(port_tokens or [])
    if not tokens:
        return True  # no destination port restriction == all ports
    return any(token_covers_admin(t) for t in tokens)
