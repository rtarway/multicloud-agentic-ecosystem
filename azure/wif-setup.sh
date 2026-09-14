#!/usr/bin/env bash
# ==============================================================================
# azure/wif-setup.sh
# Automated Azure CLI provisioning for Azure Workload Identity Federation (WIF)
# & Storage configuration for the Agentic MCP POC.
# ==============================================================================
set -euo pipefail

RESOURCE_GROUP="${AZURE_RESOURCE_GROUP:-rg-azure-wif-poc}"
LOCATION="${AZURE_LOCATION:-centralus}"
if az group show --name "${RESOURCE_GROUP}" >/dev/null 2>&1; then
  DETECTED_LOC=$(az group show --name "${RESOURCE_GROUP}" --query location -o tsv)
  if [ -n "$DETECTED_LOC" ] && [ -z "${AZURE_LOCATION:-}" ]; then
    LOCATION="$DETECTED_LOC"
  fi
fi
STORAGE_ACCOUNT="${AZURE_STORAGE_ACCOUNT:-azwifstorage$RANDOM}"
IDENTITY_NAME="${AZURE_IDENTITY_NAME:-id-agent-orchestrator}"
FED_CRED_NAME="${AZURE_FED_CRED_NAME:-fed-cred-spire-orchestrator}"
SPIRE_ISSUER="${SPIRE_OIDC_ISSUER:-https://identity.azure.example.com/spire-oidc}"
SPIFFE_SUBJECT="${SPIFFE_SUBJECT:-spiffe://example.org/ns/agent-system/sa/orchestrator-sa}"

echo "================================================================="
echo " Azure Workload Identity Federation (WIF) Setup"
echo "================================================================="
echo " Resource Group:       ${RESOURCE_GROUP}"
echo " Location:             ${LOCATION}"
echo " Storage Account:      ${STORAGE_ACCOUNT}"
echo " Managed Identity:     ${IDENTITY_NAME}"
echo " SPIRE OIDC Issuer:    ${SPIRE_ISSUER}"
echo " Subject SPIFFE ID:    ${SPIFFE_SUBJECT}"
echo "================================================================="

# 1. Create Resource Group
echo "--> 1. Ensuring Resource Group exists..."
az group create --name "${RESOURCE_GROUP}" --location "${LOCATION}" --output table

# 2. Create Storage Account
echo "--> 2. Creating Storage Account ${STORAGE_ACCOUNT}..."
az storage account create \
  --name "${STORAGE_ACCOUNT}" \
  --resource-group "${RESOURCE_GROUP}" \
  --location "${LOCATION}" \
  --sku Standard_LRS \
  --min-tls-version TLS1_2 \
  --output table

# 3. Create Containers app1 and app2
echo "--> 3. Creating Storage Containers 'app1' and 'app2'..."
az storage container create --account-name "${STORAGE_ACCOUNT}" --name "app1" --auth-mode login --output table
az storage container create --account-name "${STORAGE_ACCOUNT}" --name "app2" --auth-mode login --output table

# 4. Create User Assigned Managed Identity
echo "--> 4. Creating User Assigned Managed Identity..."
az identity create --name "${IDENTITY_NAME}" --resource-group "${RESOURCE_GROUP}" --output table

CLIENT_ID=$(az identity show --name "${IDENTITY_NAME}" --resource-group "${RESOURCE_GROUP}" --query clientId -o tsv)
PRINCIPAL_ID=$(az identity show --name "${IDENTITY_NAME}" --resource-group "${RESOURCE_GROUP}" --query principalId -o tsv)
echo "    Managed Identity Client ID:    ${CLIENT_ID}"
echo "    Managed Identity Principal ID: ${PRINCIPAL_ID}"

# 5. Create Federated Identity Credential linking SPIRE OIDC to Azure Entra ID
echo "--> 5. Establishing Federated Identity Credential with SPIRE SVID..."
az identity federated-credential create \
  --name "${FED_CRED_NAME}" \
  --identity-name "${IDENTITY_NAME}" \
  --resource-group "${RESOURCE_GROUP}" \
  --issuer "${SPIRE_ISSUER}" \
  --subject "${SPIFFE_SUBJECT}" \
  --audiences "api://AzureADTokenExchange" \
  --output table

# 6. Assign RBAC Roles on Containers
echo "--> 6. Assigning Storage Blob Data Contributor to Managed Identity on app1 & app2..."
STORAGE_ID=$(az storage account show --name "${STORAGE_ACCOUNT}" --resource-group "${RESOURCE_GROUP}" --query id -o tsv)

az role assignment create \
  --role "Storage Blob Data Contributor" \
  --assignee-object-id "${PRINCIPAL_ID}" \
  --assignee-principal-type ServicePrincipal \
  --scope "${STORAGE_ID}/blobServices/default/containers/app1" \
  --output table

az role assignment create \
  --role "Storage Blob Data Contributor" \
  --assignee-object-id "${PRINCIPAL_ID}" \
  --assignee-principal-type ServicePrincipal \
  --scope "${STORAGE_ID}/blobServices/default/containers/app2" \
  --output table

echo "================================================================="
echo " Azure WIF Setup Successfully Configured!"
echo " Managed Identity Client ID: ${CLIENT_ID}"
echo " Target Containers: app1, app2 in ${STORAGE_ACCOUNT}"
echo "================================================================="
