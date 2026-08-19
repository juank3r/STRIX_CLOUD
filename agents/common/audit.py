"""Simple audit/logger wrapper for agent actions.

Provides a consistent audit entry point so connectors and agents log
actions and decisions for traceability.
"""
import logging
from datetime import datetime
from typing import Dict, Any

logger = logging.getLogger("strix_cloud.audit")
handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
if not logger.handlers:
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


def audit(event: str, details: Dict[str, Any]):
    """Emit an audit log entry with event name and structured details."""
    entry = {"event": event, "ts": datetime.utcnow().isoformat() + "Z", "details": details}
    logger.info(entry)
