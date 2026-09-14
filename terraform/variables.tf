variable "kubeconfig_path" {
  type        = string
  description = "Path to the kubeconfig file"
  default     = "~/.kube/config"
}

variable "kube_context" {
  type        = string
  description = "Kubernetes context to use"
  default     = "rancher-desktop"
}

variable "spire_trust_domain" {
  type        = string
  description = "SPIFFE Trust Domain"
  default     = "example.org"
}

variable "spire_jwt_issuer" {
  type        = string
  description = "JWT Issuer URL for SPIRE Workload OIDC Discovery (Azure Blob Storage hosted)"
  default     = "https://azwifstoragepoc2026.blob.core.windows.net/spire-oidc"
}

variable "azure_storage_account_name" {
  type        = string
  description = "Azure Storage Account Name"
  default     = "azwifstoragepoc"
}
