variable "keycloak_url" {
  type        = string
  description = "Keycloak base URL reachable from where Terraform runs (for example a kubectl port-forward)"
  default     = "http://localhost:8080"
}

variable "keycloak_admin_user" {
  type        = string
  description = "Keycloak admin username. Set TF_VAR_keycloak_admin_user (no default)."
}

variable "keycloak_admin_password" {
  type        = string
  description = "Keycloak admin password. Set TF_VAR_keycloak_admin_password (no default)."
  sensitive   = true
}

variable "ssl_required" {
  type        = string
  description = "Keycloak sslRequired setting for the realm (none|external|all)"
  default     = "external"
}

variable "web_redirect_uris" {
  type        = list(string)
  description = "Allowed redirect URIs for the web-frontend client"
  default     = ["http://localhost:3000/*"]
}

variable "web_origins" {
  type        = list(string)
  description = "Allowed web origins (CORS) for the web-frontend client"
  default     = ["http://localhost:3000"]
}

variable "offboard_users" {
  type        = list(string)
  description = "User ids to disable (set by scripts/identity-offboard.js)"
  default     = []
}

variable "orchestrator_spiffe_id" {
  type        = string
  description = "SPIFFE ID of the orchestrator workload; stamped into act.sub of the tokens it obtains"
  default     = "spiffe://example.org/ns/agent-system/sa/orchestrator-sa"
}
