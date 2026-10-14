variable "tenant_id" {
  type        = string
  description = "Entra tenant ID. Empty uses the tenant of the current `az login` session."
  default     = ""
}

variable "subscription_id" {
  type        = string
  description = "Azure subscription ID that contains the storage account. Empty uses the `az` default."
  default     = ""
}

variable "resource_group_name" {
  type        = string
  description = "Resource group of the storage account (created by azure/main.tf)"
  default     = "rg-azure-wif-poc"
}

variable "storage_account_name" {
  type        = string
  description = "Storage account holding the app1/app2 containers"
  default     = "azwifstoragepoc2026"
}

variable "manage_entra_apps" {
  type        = bool
  description = "Create the orchestrator and Azure MCP app registrations and admin consent (see apps.tf)"
  default     = false
}

variable "bff_redirect_uris" {
  type        = list(string)
  description = "Redirect URIs of the web app (backend-for-frontend), a public client (only used with manage_entra_apps)"
  default     = ["http://localhost:3000/auth/entra/callback"]
}

variable "spire_oidc_issuer_url" {
  type        = string
  description = "Public HTTPS issuer URL of SPIRE's OIDC discovery (scripts/publish-spire-oidc.sh). Empty skips the orchestrator's federated credential."
  default     = ""
}

variable "spiffe_orchestrator_id" {
  type        = string
  description = "SPIFFE ID of the orchestrator workload (the subject of its federated credential)"
  default     = "spiffe://example.org/ns/agent-system/sa/orchestrator-sa"
}

variable "mcp_managed_identity_principal_id" {
  type        = string
  description = "Object (principal) id of the Azure MCP App Service's managed identity (azure/ output). Empty skips its federated credential."
  default     = ""
}

variable "grant_mail_send" {
  type        = bool
  description = "Also request and admin-consent Microsoft Graph Mail.Send for the orchestrator. Off by default: sending mail is a gated capability."
  default     = false
}

variable "offboard_users" {
  type        = list(string)
  description = "User ids to disable and remove from groups (set by scripts/identity-offboard.js)"
  default     = []
}
