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

variable "oidc_storage_account_name" {
  type        = string
  description = "Separate storage account that publishes SPIRE's public OIDC discovery documents"
  default     = "azwifoidcpoc2026"
}

variable "restrict_network" {
  type        = bool
  description = "Deny network access to the data storage account by default (only allow-listed IPs and trusted Azure services)"
  default     = true
}

variable "allowed_ip_ranges" {
  type        = list(string)
  description = "Public IPs / CIDRs allowed to reach the data storage account: the machine running Terraform and the Azure MCP App Service's outbound IPs"
  default     = []
}
