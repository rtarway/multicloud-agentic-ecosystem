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

  # Shared-key access is disabled on the storage account, so data-plane operations (creating containers, ...) authenticate
  # with Entra ID. The identity running Terraform needs a data role (for example Storage Blob Data Owner) and its IP must
  # be in var.allowed_ip_ranges while the network default action is Deny.
  storage_use_azuread = true
}

# 1. Resource Group
resource "azurerm_resource_group" "rg" {
  name     = var.resource_group_name
  location = var.azure_location
}

# 2. Azure Storage Account (hardened)
#    - no account keys or SAS: only Entra ID (user OBO tokens) can reach the data plane
#    - no public blob access; the network default is Deny (allow-list below); trusted Azure services bypass
resource "azurerm_storage_account" "storage" {
  name                     = var.storage_account_name
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  shared_access_key_enabled       = false
  default_to_oauth_authentication = true
  allow_nested_items_to_be_public = false
  enable_https_traffic_only       = true

  network_rules {
    default_action = var.restrict_network ? "Deny" : "Allow"
    bypass         = ["AzureServices", "Logging", "Metrics"]
    ip_rules       = var.allowed_ip_ranges
  }
}

# 3. Storage Containers: app1 and app2 (access is granted to GROUPS of users in terraform/identity/entra, never here)
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

# 4. Diagnostic logs: every blob read, write and delete is recorded with the caller's identity
resource "azurerm_log_analytics_workspace" "logs" {
  name                = "law-${var.storage_account_name}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

resource "azurerm_monitor_diagnostic_setting" "blob" {
  name                       = "blob-audit"
  target_resource_id         = "${azurerm_storage_account.storage.id}/blobServices/default/"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.logs.id

  enabled_log {
    category = "StorageRead"
  }

  enabled_log {
    category = "StorageWrite"
  }

  enabled_log {
    category = "StorageDelete"
  }
}

# 5. Managed identity of the Azure MCP App Service. It holds NO storage roles: it is only the credential the MCP's Entra
#    application trusts (federated credential, see terraform/identity/entra), so it can do the on-behalf-of exchange
#    without a client secret. Users reach storage with their own tokens and their own group-based roles.
resource "azurerm_user_assigned_identity" "mcp_identity" {
  name                = "id-azure-mcp"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

# 6. SPIRE OIDC discovery documents must be publicly readable (Entra fetches them to trust the orchestrator's SVIDs).
#    They live in their OWN storage account so the data account above never allows public access.
resource "azurerm_storage_account" "oidc" {
  name                     = var.oidc_storage_account_name
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  shared_access_key_enabled       = false
  default_to_oauth_authentication = true
  allow_nested_items_to_be_public = true
}

resource "azurerm_storage_container" "spire_oidc" {
  name                  = "spire-oidc"
  storage_account_name  = azurerm_storage_account.oidc.name
  container_access_type = "blob"
}
