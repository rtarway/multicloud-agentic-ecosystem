#!/usr/bin/env bash
# ==============================================================================
# scripts/setup-entra-wif.sh
# Automates Microsoft Entra ID (Azure AD) App Registrations, App Roles,
# and Workload Identity Federation (WIF) setup for the Azure MCP Server.
# ==============================================================================

set -euo pipefail

echo "================================================================="
echo " Setting up Microsoft Entra ID for Azure WIF & MCP Server"
echo "================================================================="

if ! command -v az >/dev/null 2>&1; then
  echo "❌ Error: Azure CLI ('az') is not installed."
  exit 1
fi

TENANT_ID=$(az account show --query tenantId -o tsv)
SUB_ID=$(az account show --query id -o tsv)
echo "   ✅ Authenticated to Tenant: $TENANT_ID"

# 1. MCP Server App Registration
MCP_APP_NAME="azure-mcp-server"
echo "--> 1. Checking Entra App Registration: $MCP_APP_NAME..."
MCP_APP_ID=$(az ad app list --filter "displayName eq '$MCP_APP_NAME'" --query "[0].appId" -o tsv 2>/dev/null || true)

if [ -z "$MCP_APP_ID" ] || [ "$MCP_APP_ID" = "None" ]; then
  echo "   Creating App Registration '$MCP_APP_NAME'..."
  MCP_APP_ID=$(az ad app create --display-name "$MCP_APP_NAME" --query appId -o tsv)
fi
echo "   ✅ MCP Server App ID: $MCP_APP_ID"

# Ensure API Identifier URI
IDENTIFIER_URI="api://$MCP_APP_ID"
az ad app update --id "$MCP_APP_ID" --identifier-uris "$IDENTIFIER_URI" >/dev/null 2>&1 || true

# Ensure Service Principal
MCP_SP_ID=$(az ad sp list --filter "appId eq '$MCP_APP_ID'" --query "[0].id" -o tsv 2>/dev/null || true)
if [ -z "$MCP_SP_ID" ] || [ "$MCP_SP_ID" = "None" ]; then
  echo "   Creating Service Principal for $MCP_APP_NAME..."
  MCP_SP_ID=$(az ad sp create --id "$MCP_APP_ID" --query id -o tsv)
fi
echo "   ✅ MCP Server Service Principal ID: $MCP_SP_ID"

# Define App Roles (mcp:tool1 and mcp:tool2)
echo "--> 2. Configuring App Roles (mcp:tool1, mcp:tool2)..."
APP_ROLES='[
  {
    "allowedMemberTypes": ["Application"],
    "description": "Permits invoking MCP Tool 1 (Read/Write Storage)",
    "displayName": "Tool1.ReadWrite",
    "id": "c3e54b61-4545-4202-b258-000000000001",
    "isEnabled": true,
    "value": "mcp:tool1"
  },
  {
    "allowedMemberTypes": ["Application"],
    "description": "Permits invoking MCP Tool 2 (Audit App1)",
    "displayName": "Tool2.Audit",
    "id": "c3e54b61-4545-4202-b258-000000000002",
    "isEnabled": true,
    "value": "mcp:tool2"
  }
]'
az ad app update --id "$MCP_APP_ID" --app-roles "$APP_ROLES" >/dev/null 2>&1 || true
echo "   ✅ App Roles successfully configured on $MCP_APP_NAME"

# 2. Kubernetes Agent Orchestrator App Registration
AGENT_APP_NAME="k8s-agent-orchestrator"
echo "--> 3. Checking Entra App Registration: $AGENT_APP_NAME..."
AGENT_APP_ID=$(az ad app list --filter "displayName eq '$AGENT_APP_NAME'" --query "[0].appId" -o tsv 2>/dev/null || true)

if [ -z "$AGENT_APP_ID" ] || [ "$AGENT_APP_ID" = "None" ]; then
  echo "   Creating App Registration '$AGENT_APP_NAME'..."
  AGENT_APP_ID=$(az ad app create --display-name "$AGENT_APP_NAME" --query appId -o tsv)
fi
echo "   ✅ Agent Orchestrator App ID: $AGENT_APP_ID"

# Ensure Agent Service Principal
AGENT_SP_ID=$(az ad sp list --filter "appId eq '$AGENT_APP_ID'" --query "[0].id" -o tsv 2>/dev/null || true)
if [ -z "$AGENT_SP_ID" ] || [ "$AGENT_SP_ID" = "None" ]; then
  echo "   Creating Service Principal for $AGENT_APP_NAME..."
  AGENT_SP_ID=$(az ad sp create --id "$AGENT_APP_ID" --query id -o tsv)
fi
echo "   ✅ Agent Service Principal ID: $AGENT_SP_ID"

# 3. Configure Federated Identity Credential
echo "--> 4. Configuring Workload Identity Federation (WIF) Credential..."
FED_NAME="k8s-orchestrator-wif"
EXISTING_FED=$(az ad app federated-credential list --id "$AGENT_APP_ID" --query "[?name=='$FED_NAME'].id | [0]" -o tsv 2>/dev/null || true)

ISSUER_URL="${SPIFFE_ISSUER_URL:-https://token.actions.githubusercontent.com}"
SUBJECT_IDENTIFIER="${SPIFFE_SUBJECT:-repo:rtarway/azure-wif-poc:environment:Production}"

if [ -z "$EXISTING_FED" ] || [ "$EXISTING_FED" = "None" ]; then
  FED_PARAMS=$(cat <<EOF
{
  "name": "$FED_NAME",
  "issuer": "$ISSUER_URL",
  "subject": "$SUBJECT_IDENTIFIER",
  "description": "Federated credential for Kubernetes Agent Orchestrator WIF",
  "audiences": ["api://AzureADTokenExchange"]
}
EOF
)
  az ad app federated-credential create --id "$AGENT_APP_ID" --parameters "$FED_PARAMS" >/dev/null 2>&1 || true
  echo "   ✅ Created Federated Identity Credential '$FED_NAME'"
else
  echo "   ✅ Found existing Federated Identity Credential '$FED_NAME'"
fi

echo ""
echo "================================================================="
echo " Entra ID WIF Setup Completed!"
echo "   * Tenant ID:                 $TENANT_ID"
echo "   * MCP Server App ID:         $MCP_APP_ID"
echo "   * MCP Identifier URI:        $IDENTIFIER_URI"
echo "   * Agent Orchestrator App ID: $AGENT_APP_ID"
echo "================================================================="
