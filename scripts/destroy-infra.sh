#!/usr/bin/env bash
# ==============================================================================
# scripts/destroy-infra.sh
# 1-Click Teardown script for Rancher Desktop demo infrastructure.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TERRAFORM_DIR="${ROOT_DIR}/terraform"

echo "================================================================="
echo " Destroying Azure WIF POC Infrastructure"
echo "================================================================="

echo "--> 1. Removing Kubernetes Workloads..."
kubectl delete -f "${ROOT_DIR}/k8s/web-frontend-deployment.yaml" --ignore-not-found=true
kubectl delete -f "${ROOT_DIR}/k8s/agent-orchestrator-deployment.yaml" --ignore-not-found=true
kubectl delete -f "${ROOT_DIR}/k8s/mcp-server-deployment.yaml" --ignore-not-found=true
kubectl delete -f "${ROOT_DIR}/k8s/namespaces.yaml" --ignore-not-found=true

echo "--> 2. Destroying Terraform Releases..."
if [ -d "${TERRAFORM_DIR}/.terraform" ]; then
  terraform -chdir="${TERRAFORM_DIR}" destroy -auto-approve || true
fi

echo "================================================================="
echo " Teardown completed successfully."
echo "================================================================="
