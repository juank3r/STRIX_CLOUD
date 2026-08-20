"""Plugin loader for cloud connectors.

This loader discovers connector modules in `agents/plugins` and allows
loading them dynamically. Connectors must expose a `Connector` class
implementing `CloudGateway`.

Discovery is cached after the first successful scan so repeated
`load_connector` calls do not re-import the whole package each time.
"""
import importlib
import os
import pkgutil
from typing import Any, Dict, Optional

from agents.common import audit

# Cache of discovered connectors: {module_name: Connector class}.
_CONNECTOR_CACHE: Optional[Dict[str, Any]] = None


def discover_connectors(package: str = "agents.plugins", use_cache: bool = True) -> Dict[str, Any]:
    global _CONNECTOR_CACHE
    if use_cache and _CONNECTOR_CACHE is not None:
        return _CONNECTOR_CACHE

    connectors: Dict[str, Any] = {}
    package_path = os.path.join(os.path.dirname(__file__))
    for finder, name, ispkg in pkgutil.iter_modules([package_path]):
        if name.startswith("__"):
            continue
        full_name = f"{package}.{name}"
        try:
            mod = importlib.import_module(full_name)
            if hasattr(mod, "Connector"):
                connectors[name] = mod.Connector
        except Exception as exc:
            # Discovery should not crash the loader; skip invalid modules but
            # record the real failure reason for audit/debugging.
            try:
                audit.audit("connector.discover.failed", {"module": full_name, "reason": str(exc)})
            except Exception:
                pass
            continue
    try:
        audit.audit("connector.discover", {"count": len(connectors), "connectors": list(connectors.keys())})
    except Exception:
        pass

    _CONNECTOR_CACHE = connectors
    return connectors


def clear_cache() -> None:
    """Reset the discovery cache (mainly for tests)."""
    global _CONNECTOR_CACHE
    _CONNECTOR_CACHE = None


def load_connector(name: str, config: Dict[str, Any]):
    connectors = discover_connectors()
    if name not in connectors:
        try:
            audit.audit("connector.load.failed", {"name": name, "reason": "not_found"})
        except Exception:
            pass
        raise ImportError(f"Connector '{name}' not found")
    cls = connectors[name]
    try:
        audit.audit("connector.load", {"name": name, "config_keys": list(config.keys())})
    except Exception:
        pass
    return cls(config)
