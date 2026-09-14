#!/usr/bin/env bash
# ==============================================================================
# scripts/cleanup.sh
# Resets the demo namespace between runs
# ==============================================================================
set -euo pipefail

echo "Resetting agent-system deployments..."
kubectl -n agent-system rollout restart deployment/web-frontend || true
kubectl -n agent-system rollout restart deployment/agent-orchestrator || true
kubectl -n agent-system rollout restart deployment/mcp-azure-server || true
echo "Cleaned up."
