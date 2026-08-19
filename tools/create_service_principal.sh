#!/usr/bin/env bash
set -euo pipefail

# Create a service principal with Reader role on a subscription and give it
# access to Key Vault secrets. Use carefully and delete when not needed.
# Usage:
#   ./tools/create_service_principal.sh <sp-name> <subscription-id> <keyvault-name>

SP_NAME=${1:-ci-sp}
SUB_ID=${2:-}
KV_NAME=${3:-}

if [ -z "$SUB_ID" ] || [ -z "$KV_NAME" ]; then
  echo "Usage: $0 <sp-name> <subscription-id> <keyvault-name>"
  exit 2
fi

echo "Creating service principal '$SP_NAME' with Reader role on subscription $SUB_ID"
az ad sp create-for-rbac --name "$SP_NAME" --role Reader --scopes /subscriptions/$SUB_ID \
  --sdk-auth > /tmp/${SP_NAME}_creds.json

echo "Service principal credentials saved to /tmp/${SP_NAME}_creds.json"
echo "Granting Key Vault access policy for secrets:get"
SP_APP_ID=$(jq -r .clientId /tmp/${SP_NAME}_creds.json)
az keyvault set-policy --name "$KV_NAME" --spn "$SP_APP_ID" --secret-permissions get list

echo "Done. Add the contents of /tmp/${SP_NAME}_creds.json as the GitHub secret 'AZURE_CREDENTIALS' for the repo."
