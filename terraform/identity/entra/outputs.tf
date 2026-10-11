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

output "orchestrator_app_client_id" {
  value = var.manage_entra_apps ? azuread_application.orchestrator[0].client_id : null
}

output "azure_mcp_app_client_id" {
  value = var.manage_entra_apps ? azuread_application.mcp[0].client_id : null
}
