output "storage_account_name" {
  value = azurerm_storage_account.storage.name
}

output "mcp_managed_identity_id" {
  description = "Resource id of the identity to assign to the Azure MCP App Service"
  value       = azurerm_user_assigned_identity.mcp_identity.id
}

output "mcp_managed_identity_client_id" {
  description = "AZURE_MI_CLIENT_ID for the Azure MCP App Service"
  value       = azurerm_user_assigned_identity.mcp_identity.client_id
}

output "mcp_managed_identity_principal_id" {
  description = "mcp_managed_identity_principal_id for terraform/identity/entra (the federated credential's subject)"
  value       = azurerm_user_assigned_identity.mcp_identity.principal_id
}

output "oidc_issuer_url" {
  description = "Public issuer URL for SPIRE's OIDC discovery (spire_oidc_issuer_url / SPIRE_OIDC_ISSUER)"
  value       = "https://${azurerm_storage_account.oidc.name}.blob.core.windows.net/${azurerm_storage_container.spire_oidc.name}"
}

output "log_analytics_workspace_id" {
  value = azurerm_log_analytics_workspace.logs.id
}

output "app1_container_url" {
  value = azurerm_storage_container.app1.id
}

output "app2_container_url" {
  value = azurerm_storage_container.app2.id
}
