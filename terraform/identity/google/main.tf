# Google Cloud identity seed: dataset-scoped BigQuery roles bound to each user's own Google account.
# Terraform cannot create Google accounts (they come from Cloud Identity/Workspace in the enterprise, or are personal
# accounts in the POC), so every account listed in identity/users.yaml must already exist. Roles are granted per dataset
# (never project-wide) and removed automatically when a user is disabled or offboarded.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.30"
    }
  }
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

module "directory" {
  source         = "../modules/directory"
  users_file     = "${path.module}/../../../identity/users.yaml"
  offboard_users = var.offboard_users
}

locals {
  # One entry per (enabled user, group, dataset role)
  dataset_grants = {
    for grant in flatten([
      for u in module.directory.users : [
        for gid in u.groups : [
          for b in module.directory.groups[gid].bigquery : {
            key     = "${u.id}/${b.dataset}/${b.role}"
            dataset = b.dataset
            role    = b.role
            member  = "user:${u.google_email}"
          }
        ]
      ] if u.enabled && u.google_email != ""
    ]) : grant.key => grant
  }

  # Users who run queries need job-creation rights on the project (they still see only their granted datasets).
  query_users = {
    for u in module.directory.users : u.id => "user:${u.google_email}"
    if u.enabled && u.google_email != "" && anytrue([for gid in u.groups : length(module.directory.groups[gid].bigquery) > 0])
  }

  placeholder_accounts = [
    for u in module.directory.users : u.google_email
    if u.enabled && (endswith(u.google_email, "@example.com") || endswith(u.google_email, "@example.org"))
  ]
}

# Refuses to apply with the placeholder Google accounts shipped in identity/users.yaml.
resource "terraform_data" "require_real_google_accounts" {
  lifecycle {
    precondition {
      condition     = length(local.placeholder_accounts) == 0
      error_message = "identity/users.yaml still contains placeholder Google accounts (${join(", ", local.placeholder_accounts)}). Replace them with real Google accounts first (docs/poc-setup-guide.md, section 4)."
    }
  }
}

resource "google_bigquery_dataset_iam_member" "grant" {
  for_each   = local.dataset_grants
  project    = var.gcp_project_id
  dataset_id = each.value.dataset
  role       = each.value.role
  member     = each.value.member

  depends_on = [terraform_data.require_real_google_accounts]
}

resource "google_project_iam_member" "job_user" {
  for_each = local.query_users
  project  = var.gcp_project_id
  role     = "roles/bigquery.jobUser"
  member   = each.value

  depends_on = [terraform_data.require_real_google_accounts]
}
