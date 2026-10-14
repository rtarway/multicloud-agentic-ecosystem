output "users" {
  description = "Provisioned Entra users and whether their accounts are enabled"
  value       = { for k, u in azuread_user.user : k => { upn = u.user_principal_name, enabled = u.account_enabled } }
}

output "groups" {
  description = "Entra security group object IDs"
  value       = { for k, g in azuread_group.group : k => g.object_id }
}

output "initial_passwords" {
  description = "Initial (change-on-first-sign-in) passwords. Read deliberately: terraform output -json initial_passwords"
  value       = { for k, p in random_password.user : k => p.result }
  sensitive   = true
}

output "tenant_id" {
  value = data.azuread_client_config.current.tenant_id
}

output "web_app_client_id" {
  description = "Client id of the public client the BFF signs users in with (ENTRA_BFF_CLIENT_ID)"
  value       = var.manage_entra_apps ? azuread_application.web[0].client_id : null
}

output "orchestrator_app_client_id" {
  description = "Client id of the orchestrator's application (ENTRA_AGENT_CLIENT_ID / ENTRA_ORCHESTRATOR_APP_ID)"
  value       = var.manage_entra_apps ? azuread_application.orchestrator[0].client_id : null
}

output "azure_mcp_app_client_id" {
  description = "Client id of the Azure MCP server's application (ENTRA_MCP_APP_ID on the orchestrator, ENTRA_CLIENT_ID on the MCP)"
  value       = var.manage_entra_apps ? azuread_application.mcp[0].client_id : null
}

output "delegated_storage_scopes" {
  description = "Fine-grained delegated permissions of the Azure MCP application"
  value       = [for k in keys(local.storage_scopes) : "Mcp.Storage.${k}"]
}
