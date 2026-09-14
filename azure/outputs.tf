output "storage_account_name" {
  value = azurerm_storage_account.storage.name
}

output "managed_identity_client_id" {
  value = azurerm_user_assigned_identity.agent_identity.client_id
}

output "managed_identity_principal_id" {
  value = azurerm_user_assigned_identity.agent_identity.principal_id
}

output "app1_container_url" {
  value = azurerm_storage_container.app1.id
}

output "app2_container_url" {
  value = azurerm_storage_container.app2.id
}
