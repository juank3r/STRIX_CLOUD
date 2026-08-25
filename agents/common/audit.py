"""Structured, tamper-evident audit logger for agent/connector actions.

Every meaningful action emits a JSON audit entry so runs are traceable and can
serve as evidence of an authorized engagement. Entries are **hash-chained**:
each carries `seq`, `prev` (previous entry's hash) and `hash`, so any deletion
or edit of a past entry breaks the chain and is detectable (see
``verify_chain``). Entries go to stderr and, when ``STRIX_AUDIT_LOG`` is set,
are also appended as JSON lines to a rotating evidence file.
"""
import json
import logging
import os
from datetime import datetime, timezone
from hashlib import sha256
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, List, Optional

logger = logging.getLogger("strix_cloud.audit")

_stream_handler = logging.StreamHandler()
_stream_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
    logger.addHandler(_stream_handler)
logger.setLevel(logging.INFO)
logger.propagate = False

GENESIS = "0" * 64
_last_hash = GENESIS
_seq = 0


def reset_chain() -> None:
    """Reset the hash-chain state (mainly for tests)."""
    global _last_hash, _seq
    _last_hash = GENESIS
    _seq = 0


def configure_file_audit(path: Optional[str] = None) -> Optional[RotatingFileHandler]:
    """Attach a rotating JSON-lines evidence file handler.

    Uses ``path`` or the ``STRIX_AUDIT_LOG`` env var. Idempotent per path.
    """
    path = path or os.environ.get("STRIX_AUDIT_LOG")
    if not path:
        return None
    for h in logger.handlers:
        if isinstance(h, RotatingFileHandler) and getattr(h, "_strix_path", None) == path:
            return h
    handler = RotatingFileHandler(path, maxBytes=5_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler._strix_path = path  # type: ignore[attr-defined]
    logger.addHandler(handler)
    return handler


configure_file_audit()


def _entry_hash(entry: Dict[str, Any]) -> str:
    payload = json.dumps(entry, default=str, sort_keys=True)
    return sha256(payload.encode("utf-8")).hexdigest()


def audit(event: str, details: Dict[str, Any]) -> None:
    """Emit a hash-chained JSON audit entry with event name and details."""
    global _last_hash, _seq
    entry = {
        "seq": _seq,
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "details": details,
        "prev": _last_hash,
    }
    entry["hash"] = _entry_hash(entry)
    _last_hash = entry["hash"]
    _seq += 1
    logger.info(json.dumps(entry, default=str, sort_keys=True))


def verify_chain(entries: List[Dict[str, Any]]) -> bool:
    """Return True if a list of parsed audit entries forms an intact chain."""
    prev = GENESIS
    for e in entries:
        recomputed = dict(e)
        stored = recomputed.pop("hash", None)
        if recomputed.get("prev") != prev or _entry_hash(recomputed) != stored:
            return False
        prev = stored
    return True
