#!/usr/bin/env bash
# ==============================================================================
# scripts/deploy-azure-mcp.sh
# Deploys the Low-Code MCP Server to Azure App Service (Linux Node.js 22 LTS)
# strictly checking Azure authentication, subscription, and deployment health.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MCP_DIR="$PROJECT_ROOT/app/mcp-server"

echo "================================================================="
echo " Deploying Azure MCP Server for OBO Token Access"
echo " (Protocol Specification: July 2026 / 2026-07-15)"
echo "================================================================="

# 1. Verify Azure CLI is installed
if ! command -v az >/dev/null 2>&1; then
  echo ""
  echo "❌ Error: Azure CLI ('az') is not installed."
  echo "Please install it: brew install azure-cli (macOS) or visit https://aka.ms/azure-cli"
  exit 1
fi

# 2. Verify Azure CLI authentication (NO SILENT SKIPS)
echo "--> 1. Checking Azure CLI authentication..."
if ! az account show >/dev/null 2>&1; then
  echo ""
  echo "❌ Error: You are not logged into Azure."
  echo "Please authenticate by running:"
  echo "   az login"
  echo "Then re-run this deployment script."
  exit 1
fi

SUBSCRIPTION_ID=$(az account show --query id -o tsv)
SUBSCRIPTION_NAME=$(az account show --query name -o tsv)
echo "   ✅ Authenticated to Azure Subscription: $SUBSCRIPTION_NAME ($SUBSCRIPTION_ID)"

# 3. Parameters
RESOURCE_GROUP="${AZURE_RESOURCE_GROUP:-rg-azure-wif-poc}"
LOCATION="${AZURE_LOCATION:-centralus}"
if [ -z "${AZURE_STORAGE_ACCOUNT:-}" ]; then
  DETECTED_STORAGE=$(az storage account list --resource-group "$RESOURCE_GROUP" --query "[?starts_with(name, 'azwifstorage')].name | [0]" -o tsv 2>/dev/null || true)
  STORAGE_ACCOUNT="${DETECTED_STORAGE:-azwifstoragepocrt}"
else
  STORAGE_ACCOUNT="$AZURE_STORAGE_ACCOUNT"
fi
PLAN_NAME="${AZURE_APP_PLAN:-plan-$RESOURCE_GROUP}"
PLAN_SKU="${AZURE_APP_PLAN_SKU:-B1}"
RUNTIME="NODE:22-lts"

# Auto-detect location if Resource Group exists
if az group show --name "$RESOURCE_GROUP" >/dev/null 2>&1; then
  DETECTED_LOC=$(az group show --name "$RESOURCE_GROUP" --query location -o tsv)
  if [ -n "$DETECTED_LOC" ] && [ -z "${AZURE_LOCATION:-}" ]; then
    LOCATION="$DETECTED_LOC"
  fi
  echo "   ✅ Found Resource Group: $RESOURCE_GROUP in $LOCATION"
else
  echo "--> Resource Group '$RESOURCE_GROUP' does not exist. Creating in $LOCATION..."
  az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --output table
fi

# Detect existing app or generate stable unique name
if [ -n "${MCP_APP_NAME:-}" ]; then
  APP_NAME="$MCP_APP_NAME"
else
  EXISTING_APP=$(az webapp list --resource-group "$RESOURCE_GROUP" --query "[?starts_with(name, 'az-mcp-server')].name | [0]" -o tsv 2>/dev/null || true)
  if [ -n "$EXISTING_APP" ]; then
    APP_NAME="$EXISTING_APP"
    echo "   ✅ Found existing Web App: $APP_NAME"
  else
    SUB_HASH=$(echo -n "$SUBSCRIPTION_ID" | md5 -q 2>/dev/null || echo -n "$SUBSCRIPTION_ID" | md5sum | cut -c1-6)
    SUB_SUFFIX=$(echo "$SUB_HASH" | cut -c1-6)
    APP_NAME="az-mcp-server-${SUB_SUFFIX}"
  fi
fi

echo ""
echo "Deployment Target:"
echo "  * Resource Group:       $RESOURCE_GROUP"
echo "  * Location:             $LOCATION"
echo "  * App Service Plan:     $PLAN_NAME ($PLAN_SKU, Linux)"
echo "  * Azure App Name:       $APP_NAME"
echo "  * Azure Storage Acct:   $STORAGE_ACCOUNT"
echo "  * Node Runtime:         $RUNTIME"
echo ""

# 4. Validate tools.yaml
if [ ! -f "$MCP_DIR/tools.yaml" ]; then
  echo "❌ Error: tools.yaml not found at $MCP_DIR/tools.yaml"
  exit 1
fi
echo "--> 2. Validating declarative tools.yaml..."
echo "   - tool1: app1/app2 read/write (mcp:tool1 scope)"
echo "   - tool2: app1 read-only audit (mcp:tool2 scope)"

# 5. Ensure App Service Plan
echo ""
echo "--> 3. Checking Azure App Service Plan ($PLAN_NAME)..."
if ! az appservice plan show --name "$PLAN_NAME" --resource-group "$RESOURCE_GROUP" >/dev/null 2>&1; then
  echo "   Creating Linux App Service Plan '$PLAN_NAME' (SKU: $PLAN_SKU) in $LOCATION..."
  az appservice plan create \
    --name "$PLAN_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --location "$LOCATION" \
    --is-linux \
    --sku "$PLAN_SKU" \
    --output table
else
  echo "   ✅ Found App Service Plan: $PLAN_NAME"
fi

# 6. Ensure Web App
echo ""
echo "--> 4. Checking Azure Web App ($APP_NAME)..."
if ! az webapp show --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" >/dev/null 2>&1; then
  echo "   Creating Linux Web App '$APP_NAME' with runtime $RUNTIME..."
  az webapp create \
    --name "$APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --plan "$PLAN_NAME" \
    --runtime "$RUNTIME" \
    --startup-file "node src/index.js" \
    --output table
else
  echo "   ✅ Found Web App: $APP_NAME"
fi

# 7. Configure App Settings & Environment Variables
echo ""
echo "--> 5. Setting Environment Variables and Storage Configuration..."
az webapp config appsettings set \
  --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --settings \
    PORT=8080 \
    WEBSITES_PORT=8080 \
    SCM_DO_BUILD_DURING_DEPLOYMENT=false \
    WEBSITE_RUN_FROM_PACKAGE=1 \
    MCP_PROTOCOL_VERSION="2026-07-15" \
    AZURE_STORAGE_ACCOUNT="$STORAGE_ACCOUNT" \
    JWT_SECRET="${JWT_SECRET:-demo-obo-token-secret-key-2026}" \
    ENTRA_TENANT_ID="${ENTRA_TENANT_ID:-81f26b58-159c-4879-80a0-bab30b5b4dd3}" \
    ENTRA_CLIENT_ID="${ENTRA_CLIENT_ID:-d5850aa0-a667-41c3-8dd0-16f2dee4da25}" \
    ENTRA_AUDIENCE="${ENTRA_AUDIENCE:-api://d5850aa0-a667-41c3-8dd0-16f2dee4da25}" \
    NODE_ENV="production" \
  --output table

# 8. Package and Deploy Artifact
echo ""
echo "--> 6. Packaging and Deploying MCP server code to $APP_NAME..."
TEMP_FILE=$(mktemp /tmp/mcp-deploy-XXXXXX)
rm -f "$TEMP_FILE"
ZIP_FILE="${TEMP_FILE}.zip"

(
  cd "$MCP_DIR"
  zip -q -r "$ZIP_FILE" . \
    -x ".git/*" \
    -x "test/*" \
    -x "test.sock" \
    -x "*.log"
)

echo "   Deploying package ($(du -h "$ZIP_FILE" | cut -f1)) to Azure Web App..."
az webapp deploy \
  --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --src-path "$ZIP_FILE" \
  --type zip \
  --clean true \
  --restart true \
  --async true \
  --output table

rm -f "$ZIP_FILE"

# 9. Health Verification
APP_URL="https://$APP_NAME.azurewebsites.net"
MCP_ENDPOINT="$APP_URL/mcp"
HEALTH_URL="$APP_URL/healthz"

echo ""
echo "--> 7. Verifying deployment health at $HEALTH_URL..."
sleep 5

MAX_RETRIES=10
RETRY_COUNT=0
HEALTHY=false

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
  HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$HEALTH_URL" || true)
  if [ "$HTTP_STATUS" = "200" ]; then
    HEALTHY=true
    break
  fi
  echo "   Waiting for webapp startup (attempt $((RETRY_COUNT+1))/$MAX_RETRIES, status: $HTTP_STATUS)..."
  sleep 10
  RETRY_COUNT=$((RETRY_COUNT+1))
done

if [ "$HEALTHY" = true ]; then
  echo "   ✅ Health check passed: HTTP 200 OK!"
else
  echo "   ⚠️ Note: Webapp is still warming up. You can check logs using:"
  echo "      az webapp log tail --name $APP_NAME --resource-group $RESOURCE_GROUP"
fi

# 10. Auto-sync to Rancher Desktop Kubernetes (if connected)
echo ""
echo "--> 8. Synchronizing endpoint with Kubernetes (agent-config ConfigMap)..."
if command -v kubectl >/dev/null 2>&1 && kubectl cluster-info >/dev/null 2>&1; then
  kubectl create configmap agent-config -n agent-system \
    --from-literal=MCP_SERVER_URL="$MCP_ENDPOINT" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1 || true
  kubectl rollout restart deployment/agent-orchestrator -n agent-system >/dev/null 2>&1 || true
  echo "   ✅ Automatically synced MCP_SERVER_URL to Kubernetes ConfigMap 'agent-config' in namespace 'agent-system'!"
else
  echo "   ℹ️ Kubernetes cluster not reachable currently. When deploying to Rancher Desktop, the ConfigMap or AZURE_MCP_ENDPOINT env var will be used."
fi

echo ""
echo "================================================================="
echo " 🎉 Azure MCP Server Deployed Successfully!"
echo "================================================================="
echo "  * MCP Server Endpoint:  $MCP_ENDPOINT"
echo "  * Health Check URL:     $HEALTH_URL"
echo "  * Azure Portal Link:    https://portal.azure.com/#@/resource/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Web/sites/$APP_NAME"
echo ""
echo "👉 CONFIGURE YOUR RANCHER DESKTOP AGENT ORCHESTRATOR:"
echo "   Option 1 (ConfigMap - No file edits required):"
echo "   kubectl create configmap agent-config -n agent-system --from-literal=MCP_SERVER_URL=\"$MCP_ENDPOINT\" --dry-run=client -o yaml | kubectl apply -f -"
echo "   kubectl rollout restart deployment/agent-orchestrator -n agent-system"
echo ""
echo "   Option 2 (Environment variable for local/CLI demo):"
echo "   export AZURE_MCP_ENDPOINT=\"$MCP_ENDPOINT\""
echo "   ./scripts/run-demo.sh"
echo "================================================================="
