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

variable "orchestrator_redirect_uris" {
  type        = list(string)
  description = "Web redirect URIs for the orchestrator/BFF app registration (only used with manage_entra_apps)"
  default     = ["http://localhost:3000/auth/entra/callback"]
}

variable "offboard_users" {
  type        = list(string)
  description = "User ids to disable and remove from groups (set by scripts/identity-offboard.js)"
  default     = []
}
