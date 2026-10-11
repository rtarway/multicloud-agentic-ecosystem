#!/usr/bin/env bash
# ==============================================================================
# scripts/sync-shared.sh
# Copies the canonical files in shared/ into each app's src/ directory (each service is built
# from its own directory, so the code is vendored). Use --check to fail if any copy has drifted.
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-sync}"

# file -> services that vendor it
declare -A TARGETS=(
  [simulation.js]="agent-orchestrator gcp-mcp-server mcp-server web-frontend"
  [demoKeys.js]="agent-orchestrator gcp-mcp-server mcp-server web-frontend"
  [redact.js]="agent-orchestrator web-frontend"
)

status=0
for file in "${!TARGETS[@]}"; do
  for svc in ${TARGETS[$file]}; do
    dest="${ROOT_DIR}/app/${svc}/src/${file}"
    if [ "$MODE" = "--check" ]; then
      if ! cmp -s "${ROOT_DIR}/shared/${file}" "$dest"; then
        echo "DRIFT: app/${svc}/src/${file} differs from shared/${file} (run scripts/sync-shared.sh)"
        status=1
      fi
    else
      cp "${ROOT_DIR}/shared/${file}" "$dest"
    fi
  done
done
[ "$MODE" = "--check" ] && [ $status -eq 0 ] && echo "shared/ copies are in sync."
exit $status
