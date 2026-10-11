#!/usr/bin/env bash
# ==============================================================================
# scripts/test-all.sh
# Runs automated testing, linting, and build verification across all microservices
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "================================================================="
echo " Running Automated Verification Suite for Multi-Cloud Ecosystem"
echo " (Azure WIF + GCP BigQuery WIF + RFC 8693 Multi-Hop Chains)"
echo "================================================================="

NODE_BIN="$(command -v /usr/local/bin/node || command -v node)"

echo "--> 0. Verifying shared helpers are in sync and no secrets are committed..."
"${ROOT_DIR}/scripts/sync-shared.sh" --check
"${ROOT_DIR}/scripts/check-no-secrets.sh"

echo "--> 0b. Testing the identity seed (users.yaml, mapping, consistency, offboarding)..."
"$NODE_BIN" "${ROOT_DIR}/scripts/identity-build-map.js" --check
"$NODE_BIN" "${ROOT_DIR}/scripts/identity-check.js"
"$NODE_BIN" --test "${ROOT_DIR}"/identity/test/*.test.js
if command -v terraform >/dev/null 2>&1; then
  terraform fmt -check -recursive "${ROOT_DIR}/terraform/identity"
fi

echo "--> 1. Testing Azure Low-Code Declarative MCP Server (Spec 2026-07-15)..."
cd "${ROOT_DIR}/app/mcp-server"
"$NODE_BIN" --test test/*.test.js

echo "--> 2. Testing GCP BigQuery Declarative MCP Server (Spec 2026-07-15)..."
cd "${ROOT_DIR}/app/gcp-mcp-server"
"$NODE_BIN" --test test/*.test.js

echo "--> 3. Testing Multi-Cloud Agent Orchestrator & RFC 8693 Token Exchange..."
cd "${ROOT_DIR}/app/agent-orchestrator"
"$NODE_BIN" --test test/*.test.js

echo "--> 4. Testing Web Frontend Dashboard (Outside SPIRE)..."
cd "${ROOT_DIR}/app/web-frontend"
"$NODE_BIN" --test test/*.test.js

echo "--> 5. Validating Kubernetes Manifests..."
for f in "${ROOT_DIR}"/k8s/*.yaml; do
  echo "    Checking syntax: $(basename "$f")"
  "$NODE_BIN" -e "
    const yaml = require(require.resolve('js-yaml', { paths: ['${ROOT_DIR}/app/mcp-server'] }));
    const docs = yaml.loadAll(require('fs').readFileSync(process.argv[1], 'utf8')).filter(Boolean);
    if (docs.length === 0) { console.error('no YAML documents'); process.exit(1); }
  " "$f"
done

echo "================================================================="
echo " ALL TESTS AND VALIDATIONS PASSED SUCCESSFULLY!"
echo "================================================================="
