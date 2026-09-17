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
  display_name              = "Agent Orchestrator Workload Identity Pool"
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
    { name = "quarter", type = "STRING", mode = "REQUIRED" },
    { name = "region", type = "STRING", mode = "REQUIRED" },
    { name = "total_revenue", type = "STRING", mode = "REQUIRED" },
    { name = "active_accounts", type = "INTEGER", mode = "NULLABLE" },
    { name = "churn_risk", type = "STRING", mode = "NULLABLE" }
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

# 9. Google Cloud Workforce Identity Pool (Option 1: Human User Federation for Keycloak)
# Provides authentic Google Cloud IAM subjects for Alice and Bob without Google Workspace accounts
resource "google_iam_workforce_pool" "enterprise_workforce_pool" {
  workforce_pool_id = var.workforce_pool_id
  parent            = "locations/global"
  location          = "global"
  display_name      = "Enterprise Corporate Workforce Identity Pool"
  description       = "Federates Keycloak enterprise human users into authentic Google Cloud IAM subjects"
  session_duration  = "3600s"
  disabled          = false
}

# 10. Workforce Identity Pool Provider for Keycloak OIDC
resource "google_iam_workforce_pool_provider" "keycloak_provider" {
  workforce_pool_id = google_iam_workforce_pool.enterprise_workforce_pool.workforce_pool_id
  location          = "global"
  provider_id       = var.workforce_provider_id
  display_name      = "Corporate Keycloak IdP Provider"
  description       = "OIDC federation provider mapping Keycloak user assertions into Google IAM subjects"
  disabled          = false

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "google.groups"        = "assertion.roles"
    "attribute.email"      = "assertion.email"
    "attribute.first_name" = "assertion.given_name"
  }

  oidc {
    issuer_uri = var.keycloak_issuer_url
    client_id  = "multicloud-orchestrator-client"
    web_sso_config {
      response_type             = "CODE"
      assertion_claims_behavior = "MERGE_USER_INFO_OVER_ID_TOKEN"
    }
  }
}

# 11. Google Cloud IAM Policy Grants for Federated Workforce Principals (Alice & Bob)
# Explicitly grants BigQuery access to Alice and Bob in Google Cloud IAM without Console accounts

# Alice: Full BigQuery Data Viewer on Analytics Dataset
resource "google_bigquery_dataset_iam_member" "alice_analytics_viewer" {
  dataset_id = google_bigquery_dataset.analytics_data.dataset_id
  role       = "roles/bigquery.dataViewer"
  member     = "principal://iam.googleapis.com/locations/global/workforcePools/${google_iam_workforce_pool.enterprise_workforce_pool.workforce_pool_id}/subject/alice@rtarwaygmail.onmicrosoft.com"
}

# Alice: Full BigQuery Admin on Audit Logs Dataset
resource "google_bigquery_dataset_iam_member" "alice_audit_admin" {
  dataset_id = google_bigquery_dataset.audit_logs.dataset_id
  role       = "roles/bigquery.admin"
  member     = "principal://iam.googleapis.com/locations/global/workforcePools/${google_iam_workforce_pool.enterprise_workforce_pool.workforce_pool_id}/subject/alice@rtarwaygmail.onmicrosoft.com"
}

# Bob: BigQuery Data Viewer on Analytics Dataset ONLY (Blocked on Audit Logs)
resource "google_bigquery_dataset_iam_member" "bob_analytics_viewer" {
  dataset_id = google_bigquery_dataset.analytics_data.dataset_id
  role       = "roles/bigquery.dataViewer"
  member     = "principal://iam.googleapis.com/locations/global/workforcePools/${google_iam_workforce_pool.enterprise_workforce_pool.workforce_pool_id}/subject/bob@rtarwaygmail.onmicrosoft.com"
}

