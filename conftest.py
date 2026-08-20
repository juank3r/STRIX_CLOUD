"""Ensure the repository root is importable as `agents.*` during tests.

pytest also honors `[tool.pytest.ini_options] pythonpath = ["."]` in
pyproject.toml; this conftest is a belt-and-suspenders fallback for
invocations that bypass that config (e.g. a bare `pytest` from a subdir).
"""
import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
