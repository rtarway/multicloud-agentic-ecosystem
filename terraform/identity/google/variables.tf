variable "gcp_project_id" {
  type        = string
  description = "Google Cloud project that hosts the BigQuery datasets (created by terraform/gcp)"
}

variable "gcp_region" {
  type        = string
  description = "Default region"
  default     = "us-central1"
}

variable "offboard_users" {
  type        = list(string)
  description = "User ids whose Google grants are removed (set by scripts/identity-offboard.js)"
  default     = []
}
