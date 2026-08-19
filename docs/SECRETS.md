# Secrets & Key Vault

This guide explains how the Orchestrator and connectors resolve secrets.

Key points
----------

- The code supports optional retrieval of secrets from Azure Key Vault. This is
  safe-guarded: if the Key Vault SDK is missing or Key Vault access fails, the
  system falls back to environment variables.
- To enable Key Vault lookups set the environment variable `AZURE_KEYVAULT_NAME`
  to the name of your vault (not the full URL). Example: `export AZURE_KEYVAULT_NAME=my-vault`.

How to store secrets
--------------------

1. Add secrets to Azure Key Vault:

```bash
az keyvault secret set --vault-name my-vault --name subscription_id --value "<your-subscription-id>"
```

2. Or set environment variables on the machine/runner:

```bash
export AZURE_SUBSCRIPTION_ID="<your-subscription-id>"
```

How to reference secrets in `agents.yaml`
-----------------------------------------

Use the `secret:` prefix in `connector_config` values. The orchestrator will
attempt to resolve the secret name from Key Vault first, then fall back to
the environment variable with the same name.

Example:

```yaml
repositories:
  - name: my-repo
    provider: azure
    connector: azure_connector
    connector_config:
      subscription_id: "secret:subscription_id"
```

Notes and safety
----------------

- The orchestrator resolves `secret:` markers before loading connectors. No
  secret values are written to disk by default; audit logs contain only events
  and metadata.
- Always use least-privilege Service Principals for CI runners. Do not hardcode
  secrets in repository files.
