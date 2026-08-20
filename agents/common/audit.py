"""Structured audit logger for agent/connector actions.

Every meaningful action emits a JSON audit entry so runs are traceable and
can serve as evidence of an authorized audit. Entries always go to stderr;
when ``STRIX_AUDIT_LOG`` is set (or ``configure_file_audit`` is called), they
are also appended as JSON lines to a rotating evidence file.
"""
import json
import logging
import os
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, Optional

logger = logging.getLogger("strix_cloud.audit")

# Human-friendly stream handler (JSON payload prefixed with time/level).
_stream_handler = logging.StreamHandler()
_stream_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
    logger.addHandler(_stream_handler)
logger.setLevel(logging.INFO)
logger.propagate = False


def configure_file_audit(path: Optional[str] = None) -> Optional[RotatingFileHandler]:
    """Attach a rotating JSON-lines evidence file handler.

    Uses ``path`` or the ``STRIX_AUDIT_LOG`` env var. Idempotent per path.
    Returns the handler (or None if no path configured).
    """
    path = path or os.environ.get("STRIX_AUDIT_LOG")
    if not path:
        return None
    for h in logger.handlers:
        if isinstance(h, RotatingFileHandler) and getattr(h, "_strix_path", None) == path:
            return h
    handler = RotatingFileHandler(path, maxBytes=5_000_000, backupCount=3, encoding="utf-8")
    # Pure JSON per line — no prefix — so the file is machine-parseable evidence.
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler._strix_path = path  # type: ignore[attr-defined]
    logger.addHandler(handler)
    return handler


# Honor the env var at import time.
configure_file_audit()


def audit(event: str, details: Dict[str, Any]) -> None:
    """Emit a structured JSON audit entry with event name and details."""
    entry = {
        "event": event,
        "ts": datetime.now(timezone.utc).isoformat(),
        "details": details,
    }
    logger.info(json.dumps(entry, default=str, sort_keys=True))
