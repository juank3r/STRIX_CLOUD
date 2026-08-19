"""Optional helpers for reading secrets from Azure Key Vault or env vars.

This module keeps Azure SDK usage optional: if the azure-keyvault-secret
package is not installed, functions fall back to environment variables.
"""
import os
from typing import Optional


def get_secret(name: str, env_fallback: Optional[str] = None) -> Optional[str]:
    """Retrieve secret by name. Prefer Key Vault if configured; otherwise env.

    To enable Key Vault usage set `AZURE_KEYVAULT_NAME` env var and ensure
    `azure.identity` and `azure.keyvault.secrets` are installed and usable.
    """
    kv_name = os.environ.get("AZURE_KEYVAULT_NAME")
    if kv_name:
        try:
            from azure.identity import DefaultAzureCredential  # type: ignore
            from azure.keyvault.secrets import SecretClient  # type: ignore

            credential = DefaultAzureCredential()
            url = f"https://{kv_name}.vault.azure.net"
            client = SecretClient(vault_url=url, credential=credential)
            sec = client.get_secret(name)
            return sec.value
        except Exception:
            # Fall back to environment variable
            pass
    if env_fallback:
        return os.environ.get(env_fallback)
    return os.environ.get(name)
