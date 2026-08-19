# Service Principal and Key Vault setup for CI

This document shows how to create a Service Principal (SP) for CI and grant
the SP access to Key Vault secrets. The repository CI can then use the SP
credentials (stored in GitHub secrets) to retrieve secrets at runtime.

Steps
-----

1. Create or choose a resource group and a Key Vault. Example:

```bash
az group create -n my-rg -l eastus
az keyvault create -n my-vault -g my-rg -l eastus
```

2. Create a Service Principal and grant Reader role (script included):

```bash
./tools/create_service_principal.sh ci-sp <subscription-id> my-vault
```

This script saves the credentials JSON to `/tmp/ci-sp_creds.json`. Copy the
contents and add it as a repository secret named `AZURE_CREDENTIALS` in
GitHub. Also add the vault name as `AZURE_KEYVAULT_NAME` secret.

3. Verify in GitHub Actions

- The example workflow `.github/workflows/ci-keyvault.yml` demonstrates how to
  use `azure/login` with the `AZURE_CREDENTIALS` secret and then call the
  `az keyvault secret show` command to fetch secrets during the job.

Security notes
--------------

- Use least privilege: prefer assigning minimal roles (Reader + Key Vault
  secret access) rather than subscription Owner.
- Rotate and delete SP credentials regularly. Remove policies when no longer
  needed.
