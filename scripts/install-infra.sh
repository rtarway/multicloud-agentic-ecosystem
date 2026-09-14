#!/usr/bin/env bash
# ==============================================================================
# scripts/install-infra.sh
# 1-Click End-to-End Infrastructure and Workload Installer for Rancher Desktop.
# Provisions SPIRE, Istio, Keycloak, and deploys the Azure WIF POC microservices.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TERRAFORM_DIR="${ROOT_DIR}/terraform"

echo "================================================================="
echo " Azure WIF POC: Rancher Desktop Infrastructure Setup"
echo "================================================================="

# Step 1: Pre-flight checks
echo "--> 1. Pre-flight CLI verification..."
for cmd in kubectl terraform helm docker; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: Required command '$cmd' is not installed or not in PATH."
    exit 1
  fi
done

# Auto-heal Rancher Desktop VM connectivity if localhost port-forwarder dropped
if ! kubectl cluster-info >/dev/null 2>&1; then
  if curl -k -s --connect-timeout 2 https://192.168.64.2:6443/version >/dev/null 2>&1; then
    echo "    Reconnecting kubectl to active Rancher Desktop VM (192.168.64.2:6443)..."
    kubectl config set-cluster rancher-desktop --server=https://192.168.64.2:6443 >/dev/null 2>&1 || true
  fi
fi

if ! kubectl cluster-info >/dev/null 2>&1; then
  echo "ERROR: Cannot connect to Kubernetes. Ensure Rancher Desktop is running."
  exit 1
fi
echo "    Connected to Kubernetes: $(kubectl config current-context)"

# Auto-heal Docker socket connectivity if host forwarder dropped
if ! docker ps >/dev/null 2>&1; then
  LIMA_SSH_CFG="$HOME/Library/Application Support/rancher-desktop/lima/0/ssh.config"
  if [ -f "$LIMA_SSH_CFG" ]; then
    echo "    Reconnecting Docker daemon socket from Rancher Desktop VM..."
    rm -f "$HOME/.rd/docker.sock"
    ssh -F "$LIMA_SSH_CFG" -f -N -L "$HOME/.rd/docker.sock:/var/run/docker.sock" -L 127.0.0.1:6443:127.0.0.1:6443 lima-0 >/dev/null 2>&1 || true
    sleep 1
  fi
fi

if ! docker ps >/dev/null 2>&1; then
  echo "ERROR: Cannot connect to Docker daemon. Ensure Rancher Desktop container runtime is running."
  exit 1
fi
echo "    Connected to Docker daemon."

# Step 2: Helm Repositories
echo "--> 2. Ensuring Helm chart repositories are up to date..."
helm repo add spiffe https://spiffe.github.io/helm-charts-hardened/ >/dev/null 2>&1 || true
helm repo add istio https://istio-release.storage.googleapis.com/charts >/dev/null 2>&1 || true
helm repo update >/dev/null 2>&1
echo "    Helm repositories updated."

# Step 3: Verify or Apply Terraform Infrastructure (SPIRE, Istio, Keycloak)
echo "--> 3. Checking core infrastructure (SPIRE, Istio, Keycloak)..."
HAS_SPIRE=$(kubectl get statefulset -n spire-server spire-server -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)
HAS_KEYCLOAK=$(kubectl get deployment -n keycloak keycloak -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)
HAS_ISTIO=$(kubectl get deployment -n istio-system istiod -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)

if [ "${HAS_SPIRE:-0}" -gt 0 ] && [ "${HAS_KEYCLOAK:-0}" -gt 0 ] && [ "${HAS_ISTIO:-0}" -gt 0 ]; then
  echo "    ✅ SPIRE, Istio, and Keycloak are already deployed and running in the cluster. Skipping Terraform apply."
else
  echo "    Applying Terraform Infrastructure (SPIRE, Istio, Keycloak)..."
  terraform -chdir="${TERRAFORM_DIR}" init
  terraform -chdir="${TERRAFORM_DIR}" apply -auto-approve
fi

# Step 4: Build Microservice Docker Images
echo "--> 4. Building local Docker images in Rancher Desktop..."
echo "    Building azure-mcp-server:v1.0.0..."
docker build -t azure-mcp-server:v1.0.0 "${ROOT_DIR}/app/mcp-server"

echo "    Building agent-orchestrator:v1.0.0..."
docker build -t agent-orchestrator:v1.0.0 "${ROOT_DIR}/app/agent-orchestrator"

echo "    Building web-frontend:v1.0.0..."
docker build -t web-frontend:v1.0.0 "${ROOT_DIR}/app/web-frontend"

echo "    Building gcp-mcp-server:v1.0.0..."
docker build -t gcp-mcp-server:v1.0.0 "${ROOT_DIR}/app/gcp-mcp-server"

# Step 5: Deploy Kubernetes Workloads
echo "--> 5. Deploying microservices to Kubernetes..."
kubectl apply -f "${ROOT_DIR}/k8s/namespaces.yaml"
kubectl apply -f "${ROOT_DIR}/k8s/mcp-server-deployment.yaml"
kubectl apply -f "${ROOT_DIR}/k8s/gcp-mcp-server-deployment.yaml"
kubectl apply -f "${ROOT_DIR}/k8s/agent-orchestrator-deployment.yaml"
kubectl apply -f "${ROOT_DIR}/k8s/web-frontend-deployment.yaml"

# Auto-configure Azure MCP Endpoint if available in environment
TARGET_MCP_URL="${AZURE_MCP_ENDPOINT:-${MCP_SERVER_URL:-}}"
if [ -n "$TARGET_MCP_URL" ]; then
  echo "    Configuring agent-config ConfigMap with Azure MCP Endpoint: $TARGET_MCP_URL"
  kubectl create configmap agent-config -n agent-system \
    --from-literal=MCP_SERVER_URL="$TARGET_MCP_URL" \
    --dry-run=client -o yaml | kubectl apply -f -
  kubectl -n agent-system rollout restart deployment/agent-orchestrator >/dev/null 2>&1 || true
fi

# Step 5b: Publish SPIRE OIDC Discovery to Azure Blob Storage
echo "--> 5b. Publishing SPIRE OIDC Discovery documents to Azure Blob Storage..."
if [ -f "${SCRIPT_DIR}/publish-spire-oidc.sh" ]; then
  "${SCRIPT_DIR}/publish-spire-oidc.sh" || echo "WARN: publish-spire-oidc.sh encountered a warning, continuing."
fi

# Step 6: Wait for Pods
echo "--> 6. Waiting for pods to reach Ready state..."
kubectl -n agent-system rollout status deployment/mcp-azure-server --timeout=90s || true
kubectl -n agent-system rollout status deployment/mcp-gcp-server --timeout=90s || true
kubectl -n agent-system rollout status deployment/agent-orchestrator --timeout=90s || true
kubectl -n agent-system rollout status deployment/web-frontend --timeout=90s || true

# Step 7: Port Forwarding
echo "--> 7. Port forwarding configuration..."
if command -v rdctl >/dev/null 2>&1; then
  rdctl api -X POST /v1/port_forwarding -b '{"namespace":"agent-system","service":"web-frontend-service","k8sPort":3000,"hostPort":3000}' 2>/dev/null || true
  rdctl api -X POST /v1/port_forwarding -b '{"namespace":"keycloak","service":"keycloak-service","k8sPort":8080,"hostPort":8080}' 2>/dev/null || true
  rdctl api -X POST /v1/port_forwarding -b '{"namespace":"agent-system","service":"gcp-mcp-service","k8sPort":8081,"hostPort":8081}' 2>/dev/null || true
fi


echo "================================================================="
echo " Infrastructure Installation Successfully Completed!"
echo "================================================================="
echo " Access Points:"
echo "   * Web Frontend UI:     http://localhost:3000 (Outside SPIRE)"
echo "   * Keycloak IdP:        http://localhost:8080 (Realm: azure-wif-realm)"
echo "   * Agent Orchestrator:  http://localhost:3001 (Inside SPIRE + Istio)"
echo "   * Azure MCP Server:    http://localhost:8080 (Low-Code Declarative MCP)"
echo ""
echo " Run Demo via CLI:"
echo "   ./scripts/run-demo.sh"
echo "================================================================="
