#!/usr/bin/env bash
# ==============================================================================
# scripts/check-no-secrets.sh
# Regression guard: fails if tracked files contain private key material or known hard-coded default
# secrets. Docs (which describe the history) and this script itself are excluded.
# ==============================================================================
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

EXCLUDES=(':(exclude)docs' ':(exclude)scripts/check-no-secrets.sh' ':(exclude,glob)app/*/test/**')
status=0

if git grep -nE -e '-----BEGIN ([A-Z]+ )?PRIVATE KEY-----' -- . "${EXCLUDES[@]}"; then
  echo "ERROR: private key material is committed (lines listed above)."
  status=1
fi

if git grep -nE -e 'demo-obo-token-secret-key|demo-spire-secret-key|orchestrator-secret-key-2026|alicepassword|bobpassword' -- . "${EXCLUDES[@]}"; then
  echo "ERROR: a known hard-coded default secret or password is present (lines listed above)."
  status=1
fi

if git ls-files | grep -E '\.pem$|\.key$'; then
  echo "ERROR: key/PEM files are tracked (listed above)."
  status=1
fi

if [ $status -eq 0 ]; then
  echo "No committed private keys or known default secrets found."
fi
exit $status
