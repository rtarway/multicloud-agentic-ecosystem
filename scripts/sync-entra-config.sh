#!/usr/bin/env bash
# ==============================================================================
# scripts/sync-entra-config.sh
# Publishes the non-secret Entra identifiers (tenant, application client ids) from Terraform outputs into the cluster as
# the 'entra-config' ConfigMap, then restarts the orchestrator and the web frontend. Run after
# `terraform -chdir=terraform/identity/entra apply -var manage_entra_apps=true`.
# There are no secrets here: the apps authenticate with federated credentials.
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENTRA_DIR="${ROOT_DIR}/terraform/identity/entra"

out() { terraform -chdir="$ENTRA_DIR" output -raw "$1"; }

TENANT_ID="$(out tenant_id)"
ORCH_APP="$(out orchestrator_app_client_id)"
MCP_APP="$(out azure_mcp_app_client_id)"
WEB_APP="$(out web_app_client_id)"

for v in TENANT_ID ORCH_APP MCP_APP WEB_APP; do
  if [ -z "${!v}" ] || [ "${!v}" = "null" ]; then
    echo "ERROR: $v is empty. Apply terraform/identity/entra with -var manage_entra_apps=true first." >&2
    exit 1
  fi
done

kubectl create configmap entra-config -n agent-system \
  --from-literal=ENTRA_TENANT_ID="$TENANT_ID" \
  --from-literal=ENTRA_AGENT_CLIENT_ID="$ORCH_APP" \
  --from-literal=ENTRA_ORCHESTRATOR_APP_ID="$ORCH_APP" \
  --from-literal=ENTRA_MCP_APP_ID="$MCP_APP" \
  --from-literal=ENTRA_BFF_CLIENT_ID="$WEB_APP" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n agent-system rollout restart deployment/agent-orchestrator deployment/web-frontend
echo "entra-config updated; orchestrator and web frontend restarted."
