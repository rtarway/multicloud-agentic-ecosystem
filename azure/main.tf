terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100.0"
    }
  }
}

provider "azurerm" {
  features {}
}

# 1. Resource Group
resource "azurerm_resource_group" "rg" {
  name     = var.resource_group_name
  location = var.azure_location
}

# 2. Azure Storage Account
resource "azurerm_storage_account" "storage" {
  name                     = var.storage_account_name
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"
}

# 3. Storage Containers: app1 and app2
resource "azurerm_storage_container" "app1" {
  name                  = "app1"
  storage_account_name  = azurerm_storage_account.storage.name
  container_access_type = "private"
}

resource "azurerm_storage_container" "app2" {
  name                  = "app2"
  storage_account_name  = azurerm_storage_account.storage.name
  container_access_type = "private"
}

# 4. User Assigned Managed Identity for Workload Identity Federation
resource "azurerm_user_assigned_identity" "agent_identity" {
  name                = "id-agent-orchestrator"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

# 5. Azure Entra ID Federated Identity Credential linking SPIRE OIDC to Managed Identity
resource "azurerm_federated_identity_credential" "spire_federation" {
  name                = "fed-cred-spire-orchestrator"
  resource_group_name = azurerm_resource_group.rg.name
  audience            = ["api://AzureADTokenExchange"]
  issuer              = var.spire_oidc_issuer_url
  parent_id           = azurerm_user_assigned_identity.agent_identity.id
  subject             = var.spiffe_workload_subject
}

# 6. IAM Role Assignment: Storage Blob Data Contributor on app1 & app2
resource "azurerm_role_assignment" "app1_contributor" {
  scope                = azurerm_storage_container.app1.resource_manager_id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.agent_identity.principal_id
}

resource "azurerm_role_assignment" "app2_contributor" {
  scope                = azurerm_storage_container.app2.resource_manager_id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.agent_identity.principal_id
}
