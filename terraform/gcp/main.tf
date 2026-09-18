# Terraform Configuration for Google Cloud Platform (GCP)
# Provisions Workload Identity Federation (WIF) Pool, Provider, and BigQuery Datasets

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.30.0"
    }
  }
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

# 1. Google Cloud Workload Identity Pool for Kubernetes / SPIRE
resource "google_iam_workload_identity_pool" "agent_pool" {
  workload_identity_pool_id = var.workload_identity_pool_id
  display_name              = "Agent WIF Pool"
  description               = "Workload identity pool for SPIRE and K8s agent orchestrators"
  disabled                  = false
}

# 2. OIDC Provider for SPIRE Trust Domain
resource "google_iam_workload_identity_pool_provider" "spire_provider" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.agent_pool.workload_identity_pool_id
  workload_identity_pool_provider_id = var.workload_identity_provider_id
  display_name                       = "SPIRE OIDC Provider"
  description                        = "Federates SPIRE JWT-SVIDs into Google Cloud STS"
  disabled                           = false

  attribute_mapping = {
    "google.subject"      = "assertion.sub"
    "attribute.spiffe_id" = "assertion.sub"
    "attribute.aud"       = "assertion.aud"
  }

  oidc {
    issuer_uri = var.oidc_issuer_url
  }
}

# 3. Google Cloud BigQuery Analytics Dataset (analytics_data)
resource "google_bigquery_dataset" "analytics_data" {
  dataset_id                  = "analytics_data"
  friendly_name               = "Enterprise Analytics Data"
  description                 = "Regional sales revenue and customer telemetry for Agentic AI analysis"
  location                    = var.gcp_region
  default_table_expiration_ms = null

  labels = {
    env      = "poc"
    security = "rfc8693-governed"
  }
}

# 4. Regional Sales Table
resource "google_bigquery_table" "regional_sales" {
  dataset_id = google_bigquery_dataset.analytics_data.dataset_id
  table_id   = "regional_sales"

  schema = jsonencode([
    { name = "quarter", type = "STRING" },
    { name = "region", type = "STRING" },
    { name = "total_revenue", type = "STRING" },
    { name = "active_accounts", type = "INTEGER" },
    { name = "churn_risk", type = "STRING" }
  ])
}

# 5. Google Cloud BigQuery Audit Dataset (audit_logs - Admin Only)
resource "google_bigquery_dataset" "audit_logs" {
  dataset_id                  = "audit_logs"
  friendly_name               = "Security & Query Audit Logs"
  description                 = "Immutable audit records restricted to administrators"
  location                    = var.gcp_region
  default_table_expiration_ms = null

  labels = {
    security_tier = "admin-audit"
  }
}

# 6. Google Service Account for BigQuery MCP Server
resource "google_service_account" "gcp_mcp_sa" {
  account_id   = "gcp-mcp-sa"
  display_name = "GCP BigQuery MCP Server Service Account"
  description  = "Service Account impersonated by Workload Identity Federation for BigQuery access"
}

# 7. Grant BigQuery Permissions to the Service Account
resource "google_project_iam_member" "bq_data_viewer" {
  project = var.gcp_project_id
  role    = "roles/bigquery.dataViewer"
  member  = "serviceAccount:${google_service_account.gcp_mcp_sa.email}"
}

resource "google_project_iam_member" "bq_job_user" {
  project = var.gcp_project_id
  role    = "roles/bigquery.jobUser"
  member  = "serviceAccount:${google_service_account.gcp_mcp_sa.email}"
}

# 8. Allow Workload Identity Pool principals to impersonate the Service Account
resource "google_service_account_iam_member" "wif_impersonation" {
  service_account_id = google_service_account.gcp_mcp_sa.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.agent_pool.name}/*"
}

# 9. Google Cloud IAM Policy Grants for Federated Workload Principals (Alice & Bob)
# Explicitly grants BigQuery access directly to Alice and Bob in Google Cloud IAM via Workload Identity Pool subjects

# Alice: Full BigQuery Data Viewer
resource "google_project_iam_member" "alice_bq_viewer" {
  project = var.gcp_project_id
  role    = "roles/bigquery.dataViewer"
  member  = "principal://iam.googleapis.com/projects/${var.gcp_project_number}/locations/global/workloadIdentityPools/${var.workload_identity_pool_id}/subject/alice@rtarwaygmail.onmicrosoft.com"
}

# Alice: Full BigQuery Admin (includes audit logs & admin operations)
resource "google_project_iam_member" "alice_bq_admin" {
  project = var.gcp_project_id
  role    = "roles/bigquery.admin"
  member  = "principal://iam.googleapis.com/projects/${var.gcp_project_number}/locations/global/workloadIdentityPools/${var.workload_identity_pool_id}/subject/alice@rtarwaygmail.onmicrosoft.com"
}

# Bob: BigQuery Data Viewer ONLY (Blocked on admin operations)
resource "google_project_iam_member" "bob_bq_viewer" {
  project = var.gcp_project_id
  role    = "roles/bigquery.dataViewer"
  member  = "principal://iam.googleapis.com/projects/${var.gcp_project_number}/locations/global/workloadIdentityPools/${var.workload_identity_pool_id}/subject/bob@rtarwaygmail.onmicrosoft.com"
}

