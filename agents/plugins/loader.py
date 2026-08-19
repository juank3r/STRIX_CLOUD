"""Plugin loader for cloud connectors.

This loader discovers connector modules in `agents/plugins` and allows
loading them dynamically. Connectors must expose a `Connector` class
implementing `CloudGateway`.
"""
import importlib
import pkgutil
import os
from typing import Dict, Any

from agents.common import audit


def discover_connectors(package: str = "agents.plugins") -> Dict[str, Any]:
    connectors = {}
    package_path = os.path.join(os.path.dirname(__file__))
    for finder, name, ispkg in pkgutil.iter_modules([package_path]):
        if name.startswith("__"):
            continue
        full_name = f"{package}.{name}"
        try:
            mod = importlib.import_module(full_name)
            if hasattr(mod, "Connector"):
                connectors[name] = mod.Connector
        except Exception:
            # discovery should not crash the loader; skip invalid modules
            # record discovery failure for audit/debugging
            try:
                audit.audit("connector.discover.failed", {"module": full_name, "reason": str(Exception)})
            except Exception:
                pass
            continue
    try:
        audit.audit("connector.discover", {"count": len(connectors), "connectors": list(connectors.keys())})
    except Exception:
        pass
    return connectors


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
