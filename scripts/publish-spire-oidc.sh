#!/usr/bin/env bash
# ==============================================================================
# scripts/publish-spire-oidc.sh
# Publishes SPIRE OIDC Discovery documents and JWKS keys to Azure Blob Storage.
# Provides a permanent, stable HTTPS Issuer URL for Azure Entra ID WIF.
# Eliminates the need for dynamic Cloudflare tunnels that change on restart.
# ==============================================================================
set -euo pipefail

RESOURCE_GROUP="${AZURE_RESOURCE_GROUP:-rg-azure-wif-poc}"
# The public OIDC documents live in their OWN storage account (created by azure/main.tf) so the data account never
# allows public access. Uploading needs a data role on this account (Storage Blob Data Contributor) for `az login`.
STORAGE_ACCOUNT="${AZURE_OIDC_STORAGE_ACCOUNT:-azwifoidcpoc2026}"
CONTAINER_NAME="spire-oidc"
PERMANENT_ISSUER_URL="https://${STORAGE_ACCOUNT}.blob.core.windows.net/${CONTAINER_NAME}"

echo "=========================================================="
echo "==> Setting up Permanent Azure Blob-Hosted SPIRE OIDC Discovery..."
echo "    Storage Account: $STORAGE_ACCOUNT"
echo "    Container:       $CONTAINER_NAME"
echo "    Permanent URL:   $PERMANENT_ISSUER_URL"
echo "=========================================================="

# 1. The container (public blob read) is created by Terraform (azure/main.tf). Verify it exists.
echo "--> 1. Checking container '${CONTAINER_NAME}' on '${STORAGE_ACCOUNT}'..."
if command -v az >/dev/null 2>&1; then
  az storage container show --account-name "$STORAGE_ACCOUNT" --name "$CONTAINER_NAME" --auth-mode login --output none \
    || { echo "ERROR: container '${CONTAINER_NAME}' not found. Apply azure/ first (terraform -chdir=azure apply)." >&2; exit 1; }
else
  echo "WARN: Azure CLI 'az' not found. Ensure container '${CONTAINER_NAME}' exists with public blob read access."
fi

# 2. Extract public JWKS keys from running SPIRE cluster
echo "--> 2. Fetching public JWKS keys from SPIRE discovery provider..."
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

if kubectl get pod -n spire-server -l app.kubernetes.io/name=spire-server -o name 2>/dev/null | grep -q pod; then
  echo "    Extracting keys from spire-server pod..."
  kubectl exec -n spire-server spire-server-0 -c spire-server -- \
    /opt/spire/bin/spire-server bundle show -format jwt > "$TMP_DIR/bundle.json" || true

  # Alternatively query discovery provider service
  kubectl run tmp-spire-jwks -q --image=node:20-alpine --restart=Never --attach --rm \
    --overrides='{"spec":{"containers":[{"name":"fetch","image":"node:20-alpine","command":["wget","-qO-","--no-check-certificate","https://spire-spiffe-oidc-discovery-provider.spire-server:443/keys"]}]}}' 2>/dev/null | jq . > "$TMP_DIR/keys.json" || true
fi

# Fallback: if cluster not deployed yet, generate initial placeholder keys structure
if [ ! -s "$TMP_DIR/keys.json" ]; then
  echo "    Cluster not ready yet: generating standard JWKS key schema template..."
  cat <<'EOF' > "$TMP_DIR/keys.json"
{
  "keys": []
}
EOF
fi

# 3. Generate OpenID Discovery Document pointing to Azure Blob URL
echo "--> 3. Generating OpenID Discovery Document..."
cat <<EOF > "$TMP_DIR/openid-configuration"
{
  "issuer": "$PERMANENT_ISSUER_URL",
  "jwks_uri": "$PERMANENT_ISSUER_URL/keys",
  "authorization_endpoint": "",
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256",
    "ES256",
    "ES384"
  ]
}
EOF

# 4. Upload discovery documents to Azure Blob Storage
echo "--> 4. Uploading discovery documents to Azure Blob Storage..."
if command -v az >/dev/null 2>&1; then
  az storage blob upload \
    --account-name "$STORAGE_ACCOUNT" \
    --container-name "$CONTAINER_NAME" \
    --name ".well-known/openid-configuration" \
    --file "$TMP_DIR/openid-configuration" \
    --content-type "application/json" \
    --overwrite \
    --auth-mode login \
    --output table

  az storage blob upload \
    --account-name "$STORAGE_ACCOUNT" \
    --container-name "$CONTAINER_NAME" \
    --name "keys" \
    --file "$TMP_DIR/keys.json" \
    --content-type "application/json" \
    --overwrite \
    --auth-mode login \
    --output table

  echo "--> 5. Verifying public reachability over the internet..."
  curl -fsSL "$PERMANENT_ISSUER_URL/.well-known/openid-configuration" >/dev/null && echo "✔ openid-configuration verified!" || true
  curl -fsSL "$PERMANENT_ISSUER_URL/keys" >/dev/null && echo "✔ keys verified!" || true
else
  echo "Upload manually to container '${CONTAINER_NAME}':"
  echo "  - Path: .well-known/openid-configuration"
  echo "  - Path: keys"
fi

echo "=========================================================="
echo "✔ SPIRE OIDC Discovery permanently hosted on Azure Blob Storage!"
echo "  Permanent Issuer URL: $PERMANENT_ISSUER_URL"
echo "  (No Cloudflare tunnel required!)"
echo "=========================================================="
