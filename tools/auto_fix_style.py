#!/usr/bin/env python3
"""Simple auto-fix script: trims trailing whitespace and ensures final newline.

Run before linting to reduce trivial style failures.
"""
import sys
from pathlib import Path


def fix_file(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf8")
    except Exception:
        return False
    # Remove trailing whitespace on each line
    changed = False
    lines = [line.rstrip() for line in text.splitlines()]
    new_text = "\n".join(lines) + "\n"
    if new_text != text:
        path.write_text(new_text, encoding="utf8")
        changed = True
    return changed


def main(argv):
    root = Path(".")
    files = list(root.rglob("*.py"))
    changed_any = False
    for f in files:
        if f.match(".venv/*"):
            continue
        if fix_file(f):
            print(f"fixed: {f}")
            changed_any = True
    if not changed_any:
        print("no changes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
