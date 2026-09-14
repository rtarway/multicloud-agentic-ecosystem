#!/usr/bin/env bash
# ==============================================================================
# Setup Script: Google Cloud Workload Identity Federation & BigQuery MCP
# ==============================================================================
# This script provisions:
# 1. Required GCP APIs (IAM, STS, IAMCredentials, BigQuery)
# 2. Workload Identity Pool ('k8s-agent-pool')
# 3. Workload Identity Provider ('spire-oidc-provider' or Keycloak OIDC)
# 4. BigQuery Service Account ('gcp-mcp-sa') with BigQuery DataViewer/JobUser
# 5. Workload Identity User IAM binding for impersonation
# 6. BigQuery dataset ('analytics_data') and table ('regional_sales') with sample rows
# 7. Generates .env.gcp configuration file for live testing
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$ROOT_DIR/.env.gcp"

echo "================================================================="
echo " 🌐 Google Cloud Workload Identity Federation (WIF) Setup Wizard"
echo "================================================================="

# Check gcloud CLI
if ! command -v gcloud &> /dev/null; then
  echo "❌ Error: 'gcloud' CLI is not installed or not in PATH."
  echo ""
  echo "To install the Google Cloud SDK on macOS:"
  echo "  brew install --cask google-cloud-sdk"
  echo "Or download from: https://cloud.google.com/sdk/docs/install"
  echo ""
  echo "After installing, run: gcloud auth login"
  exit 1
fi

# Prompt for or detect GCP Project ID
CURRENT_PROJECT=$(gcloud config get-value project 2>/dev/null || echo "wifdemoproject-507002")
CURRENT_PROJECT="${CURRENT_PROJECT:-wifdemoproject-507002}"
read -p "Enter your Google Cloud Project ID [${CURRENT_PROJECT}]: " INPUT_PROJECT
GCP_PROJECT_ID="${INPUT_PROJECT:-$CURRENT_PROJECT}"


if [ -z "$GCP_PROJECT_ID" ]; then
  echo "❌ Error: GCP Project ID cannot be empty."
  exit 1
fi

read -p "Enter GCP Region [us-central1]: " INPUT_REGION
GCP_REGION="${INPUT_REGION:-us-central1}"

POOL_ID="k8s-agent-pool"
PROVIDER_ID="spire-oidc-provider"
SA_NAME="gcp-mcp-sa"
SA_EMAIL="${SA_NAME}@${GCP_PROJECT_ID}.iam.gserviceaccount.com"
DATASET_NAME="analytics_data"
TABLE_NAME="regional_sales"

echo ""
echo "Configuration Summary:"
echo "  Project ID:       $GCP_PROJECT_ID"
echo "  Region:           $GCP_REGION"
echo "  Pool ID:          $POOL_ID"
echo "  Provider ID:      $PROVIDER_ID"
echo "  Service Account:  $SA_EMAIL"
echo "  BigQuery Dataset: $DATASET_NAME.$TABLE_NAME"
echo ""

read -p "Proceed with provisioning in Google Cloud? (y/N): " CONFIRM
if [[ ! "$CONFIRM" =~ ^[yY]$ ]]; then
  echo "Setup aborted by user."
  exit 0
fi

echo ""
echo "--> 1. Setting active project..."
gcloud config set project "$GCP_PROJECT_ID"

echo "--> 2. Enabling required Google Cloud APIs..."
gcloud services enable \
  iam.googleapis.com \
  iamcredentials.googleapis.com \
  sts.googleapis.com \
  bigquery.googleapis.com

PROJECT_NUMBER=$(gcloud projects describe "$GCP_PROJECT_ID" --format="value(projectNumber)")
echo "    Project Number: $PROJECT_NUMBER"

echo "--> 3. Creating Workload Identity Pool ($POOL_ID)..."
if gcloud iam workload-identity-pools describe "$POOL_ID" --location="global" &>/dev/null; then
  echo "    Workload Identity Pool '$POOL_ID' already exists."
else
  gcloud iam workload-identity-pools create "$POOL_ID" \
    --location="global" \
    --display-name="Agent Orchestrator Workload Identity Pool" \
    --description="Workload identity pool for SPIRE and K8s agent orchestrators"
  echo "    Created Workload Identity Pool '$POOL_ID'."
fi

echo "--> 4. Creating Workload Identity Provider ($PROVIDER_ID)..."
# SPIRE public issuer or Keycloak OIDC issuer URL
read -p "Enter your OIDC Issuer URL (e.g. SPIRE/Keycloak public HTTPS URL) [https://identity.example.com/realms/azure-wif-realm]: " INPUT_ISSUER
OIDC_ISSUER="${INPUT_ISSUER:-https://identity.example.com/realms/azure-wif-realm}"

if gcloud iam workload-identity-pools providers describe "$PROVIDER_ID" \
    --workload-identity-pool="$POOL_ID" --location="global" &>/dev/null; then
  echo "    Workload Identity Provider '$PROVIDER_ID' already exists."
else
  gcloud iam workload-identity-pools providers create-oidc "$PROVIDER_ID" \
    --workload-identity-pool="$POOL_ID" \
    --location="global" \
    --display-name="SPIRE / Keycloak OIDC Provider" \
    --issuer-uri="$OIDC_ISSUER" \
    --attribute-mapping="google.subject=assertion.sub,attribute.spiffe_id=assertion.sub,attribute.role=assertion.roles" \
    --allowed-audiences="urn:mcp:server:gcp-bigquery,https://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/providers/${PROVIDER_ID}"
  echo "    Created Workload Identity Provider '$PROVIDER_ID'."
fi

echo "--> 5. Creating Service Account ($SA_NAME)..."
if gcloud iam service-accounts describe "$SA_EMAIL" &>/dev/null; then
  echo "    Service Account '$SA_EMAIL' already exists."
else
  gcloud iam service-accounts create "$SA_NAME" \
    --display-name="GCP BigQuery MCP Server Service Account" \
    --description="Service Account for BigQuery MCP execution"
  echo "    Created Service Account '$SA_EMAIL'."
fi

echo "--> 6. Granting BigQuery Roles to Service Account..."
gcloud projects add-iam-policy-binding "$GCP_PROJECT_ID" \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/bigquery.dataViewer" \
  --condition=None --quiet >/dev/null

gcloud projects add-iam-policy-binding "$GCP_PROJECT_ID" \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/bigquery.jobUser" \
  --condition=None --quiet >/dev/null

echo "--> 7. Granting Workload Identity User impersonation role to pool..."
POOL_SUBJECT="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/*"
gcloud iam service-accounts add-iam-policy-binding "$SA_EMAIL" \
  --role="roles/iam.workloadIdentityUser" \
  --member="$POOL_SUBJECT" \
  --quiet >/dev/null
echo "    Bound $POOL_SUBJECT to $SA_EMAIL"

echo "--> 8. Creating BigQuery Dataset & Regional Sales Table..."
if bq show --dataset "${GCP_PROJECT_ID}:${DATASET_NAME}" &>/dev/null; then
  echo "    Dataset '${DATASET_NAME}' already exists."
else
  bq --location="$GCP_REGION" mk -d \
    --description="Enterprise Analytics Data for Agentic AI" \
    "${GCP_PROJECT_ID}:${DATASET_NAME}"
  echo "    Created dataset '${DATASET_NAME}'."
fi

if bq show --table "${GCP_PROJECT_ID}:${DATASET_NAME}.${TABLE_NAME}" &>/dev/null; then
  echo "    Table '${TABLE_NAME}' already exists."
else
  bq mk -t \
    --schema="quarter:STRING,region:STRING,total_revenue:STRING,active_accounts:INTEGER,churn_risk:STRING" \
    "${GCP_PROJECT_ID}:${DATASET_NAME}.${TABLE_NAME}"
  echo "    Created table '${TABLE_NAME}'."

  echo "--> 9. Inserting sample sales records into BigQuery..."
  bq query --use_legacy_sql=false \
    "INSERT INTO \`${GCP_PROJECT_ID}.${DATASET_NAME}.${TABLE_NAME}\` (quarter, region, total_revenue, active_accounts, churn_risk) VALUES
     ('Q2-2026', 'north-america', '\$14,250,000', 18420, '1.8%'),
     ('Q2-2026', 'emea', '\$8,940,000', 12150, '2.4%'),
     ('Q2-2026', 'apac', '\$6,750,000', 9800, '3.1%'),
     ('Q2-2026', 'latam', '\$2,310,000', 4200, '4.2%');"
fi

echo "--> 10. Writing configuration to $ENV_FILE..."
cat <<EOF > "$ENV_FILE"
# Google Cloud WIF & BigQuery Environment Configuration
GCP_PROJECT_ID=$GCP_PROJECT_ID
GCP_PROJECT_NUMBER=$PROJECT_NUMBER
GCP_REGION=$GCP_REGION
GCP_WORKLOAD_POOL_ID=$POOL_ID
GCP_WORKLOAD_PROVIDER_ID=$PROVIDER_ID
GCP_SERVICE_ACCOUNT_EMAIL=$SA_EMAIL
GCP_DATASET_ANALYTICS=$DATASET_NAME
GCP_DATASET_AUDIT=audit_logs
GCP_STS_AUDIENCE=//iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/providers/${PROVIDER_ID}
GCP_LIVE_MODE=true
EOF

chmod 600 "$ENV_FILE"

echo ""
echo "================================================================="
echo " ✅ Google Cloud WIF & BigQuery Setup Completed Successfully!"
echo "================================================================="
echo " Configuration saved in: $ENV_FILE"
echo ""
echo "Next Step: Run the live Google Cloud test suite:"
echo "  ./scripts/test-live-gcp.sh"
echo "================================================================="
