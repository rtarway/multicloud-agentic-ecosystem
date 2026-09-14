#!/usr/bin/env bash
# ==============================================================================
# Live Google Cloud BigQuery & RFC 8693 MCP Verification Runner
# ==============================================================================
# Tests the GCP BigQuery MCP Server directly against live Google Cloud APIs:
# 1. Loads .env.gcp if present
# 2. Obtains live Google Access Token (via gcloud auth print-access-token if available)
# 3. Executes test-live-gcp.js with live or simulation mode
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$ROOT_DIR/.env.gcp"

# 1. Load configuration from .env.gcp if present
if [ -f "$ENV_FILE" ]; then
  echo "📄 Loading configuration from $ENV_FILE..."
  set -a
  source "$ENV_FILE"
  set +a
fi

GCP_PROJECT_ID="${GCP_PROJECT_ID:-${1:-}}"

# 2. Check gcloud access token if available
if command -v gcloud &>/dev/null; then
  if [ -z "${GCP_ACCESS_TOKEN:-}" ]; then
    echo "🔑 Attempting to fetch live access token from 'gcloud auth print-access-token'..."
    TOKEN=$(gcloud auth print-access-token 2>/dev/null || true)
    if [ -n "$TOKEN" ]; then
      export GCP_ACCESS_TOKEN="$TOKEN"
      export GCP_LIVE_MODE="true"
      echo "   ✅ Live GCP Access Token detected."
    fi
  fi

  if [ -z "$GCP_PROJECT_ID" ]; then
    GCP_PROJECT_ID=$(gcloud config get-value project 2>/dev/null || echo "")
  fi
fi

if [ -n "${GCP_ACCESS_TOKEN:-}" ]; then
  export GCP_LIVE_MODE="true"
fi

exec node "$SCRIPT_DIR/test-live-gcp.js" "$GCP_PROJECT_ID"
