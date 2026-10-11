#!/usr/bin/env bash
# ==============================================================================
# scripts/gen-demo-keys.sh
# Generates throwaway RSA keypairs for the DEMO profile (ALLOW_SIMULATION=true) into .demo-keys/.
# The directory is git-ignored. Nothing in this repository ships key material; run this only if you
# want keys that persist across processes (otherwise each process generates its own in memory).
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${DEMO_KEYS_DIR:-${ROOT_DIR}/.demo-keys}"
mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"

for name in azure-test:azure-test google-sts:google-sts; do
  base="${name%%:*}"
  key="${OUT_DIR}/${base}-key.pem"
  pub="${OUT_DIR}/${base}-pub.pem"
  if [ -f "$key" ]; then
    echo "exists: $key"
    continue
  fi
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$key" 2>/dev/null
  openssl pkey -in "$key" -pubout -out "$pub"
  chmod 600 "$key"
  echo "created: $key / $pub"
done
echo "Demo keys are in ${OUT_DIR} (git-ignored). Use with ALLOW_SIMULATION=true only."
