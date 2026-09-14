variable "azure_location" {
  type        = string
  description = "Azure region for deployment"
  default     = "centralus"
}

variable "resource_group_name" {
  type        = string
  description = "Resource group name"
  default     = "rg-azure-wif-poc"
}

variable "storage_account_name" {
  type        = string
  description = "Globally unique Azure Storage Account Name (alphanumeric only)"
  default     = "azwifstoragepoc2026"
}

variable "spire_oidc_issuer_url" {
  type        = string
  description = "Publicly accessible SPIRE OIDC Discovery Issuer URL (Azure Blob Storage hosted)"
  default     = "https://azwifstoragepoc2026.blob.core.windows.net/spire-oidc"
}

variable "spiffe_workload_subject" {
  type        = string
  description = "Subject SPIFFE ID for the Agent Orchestrator"
  default     = "spiffe://example.org/ns/agent-system/sa/orchestrator-sa"
}
