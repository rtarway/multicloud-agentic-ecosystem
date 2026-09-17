variable "gcp_project_id" {
  type        = string
  description = "Target Google Cloud Project ID"
  default     = "wifdemoproject-507002"
}

variable "gcp_project_number" {
  type        = string
  description = "Target Google Cloud Project Number"
  default     = "834200279688"
}


variable "gcp_region" {
  type        = string
  description = "Target Google Cloud Region"
  default     = "us-central1"
}

variable "workload_identity_pool_id" {
  type        = string
  description = "Workload identity pool identifier"
  default     = "k8s-agent-pool"
}

variable "workload_identity_provider_id" {
  type        = string
  description = "Workload identity provider identifier"
  default     = "spire-oidc-provider"
}

variable "oidc_issuer_url" {
  type        = string
  description = "Public OIDC Issuer URL for SPIRE server"
  default     = "https://spire.example.org"
}

variable "workforce_pool_id" {
  type        = string
  description = "Google Cloud Workforce Identity Pool identifier for human users"
  default     = "enterprise-workforce-pool"
}

variable "workforce_provider_id" {
  type        = string
  description = "Workforce Identity Provider identifier for Keycloak IdP"
  default     = "keycloak-workforce-provider"
}

variable "keycloak_issuer_url" {
  type        = string
  description = "Public OIDC Issuer URL for Keycloak Corporate IdP"
  default     = "http://localhost:8080/realms/azure-wif-realm"
}
