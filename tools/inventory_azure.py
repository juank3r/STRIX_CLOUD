#!/usr/bin/env python3
"""Inventory Azure container-related resources using `az` CLI.

This script prefers the Azure CLI (`az`) for inventory because it is
commonly available and handles authentication interactively (use
`az login` before running). It falls back to printing a helpful message
if `az` is not available.
"""
import json
import shutil
import subprocess
from typing import Any, Dict, List


def run_az(cmd: List[str]) -> Any:
    proc = subprocess.run(["az"] + cmd + ["-o", "json"], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"az command failed: {' '.join(cmd)}\n{proc.stderr}")
    return json.loads(proc.stdout)


def inventory_acr() -> List[Dict]:
    return run_az(["acr", "list"]) or []


def inventory_aks() -> List[Dict]:
    return run_az(["aks", "list"]) or []


def inventory_aci() -> List[Dict]:
    return run_az(["container", "list"]) or []


def main():
    if not shutil.which("az"):
        print("Azure CLI (az) not found. Install it and run 'az login' first.")
        return

    try:
        print("Listing Azure Container Registries (ACR)")
        acrs = inventory_acr()
        for a in acrs:
            print(
                f"- ACR: {a.get('name')} "
                f"(resourceGroup={a.get('resourceGroup')}, loginServer={a.get('loginServer')})"
            )

        print("\nListing AKS clusters")
        akses = inventory_aks()
        for k in akses:
            print(f"- AKS: {k.get('name')} (rg={k.get('resourceGroup')})")

        print("\nListing Container Instances (ACI)")
        acis = inventory_aci()
        for c in acis:
            print(f"- ACI: {c.get('name')} (rg={c.get('resourceGroup')})")

        print(
            "\nNote: To list repositories/images inside an ACR, run:\n"
            "  az acr repository list --name <acrName> -o json"
        )
    except Exception as e:
        print("Error during inventory:", e)


if __name__ == '__main__':
    main()
