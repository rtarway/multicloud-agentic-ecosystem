# Optional app registrations for the orchestrator and the Azure MCP server, with tenant-wide (admin) consent so users
# never see a consent prompt and the MCP app pre-authorises the orchestrator. Off by default because the repo's
# existing apps were created by scripts/setup-entra-wif.sh and their client IDs are referenced elsewhere. Enable with
# -var manage_entra_apps=true on a fresh tenant, then use the outputs to configure the services.
#
# No client secret is created here: the orchestrator authenticates with a federated credential (Phase 3).

resource "random_uuid" "mcp_scope" {
  count = var.manage_entra_apps ? 1 : 0
}

resource "random_uuid" "orchestrator_scope" {
  count = var.manage_entra_apps ? 1 : 0
}

resource "azuread_application" "mcp" {
  count            = var.manage_entra_apps ? 1 : 0
  display_name     = "azure-mcp-server-poc"
  sign_in_audience = "AzureADMyOrg"

  api {
    requested_access_token_version = 2

    oauth2_permission_scope {
      id                         = random_uuid.mcp_scope[0].result
      value                      = "user_impersonation"
      type                       = "User"
      enabled                    = true
      admin_consent_display_name = "Access the Azure MCP server as the signed-in user"
      admin_consent_description  = "Allows the agent orchestrator to call the Azure MCP server on behalf of the signed-in user."
      user_consent_display_name  = "Access the Azure MCP server as you"
      user_consent_description   = "Allows the agent to call the Azure MCP server on your behalf."
    }
  }
}

resource "azuread_application_identifier_uri" "mcp" {
  count          = var.manage_entra_apps ? 1 : 0
  application_id = azuread_application.mcp[0].id
  identifier_uri = "api://${azuread_application.mcp[0].client_id}"
}

resource "azuread_service_principal" "mcp" {
  count     = var.manage_entra_apps ? 1 : 0
  client_id = azuread_application.mcp[0].client_id
}

resource "azuread_application" "orchestrator" {
  count            = var.manage_entra_apps ? 1 : 0
  display_name     = "agent-orchestrator-poc"
  sign_in_audience = "AzureADMyOrg"

  api {
    requested_access_token_version = 2

    oauth2_permission_scope {
      id                         = random_uuid.orchestrator_scope[0].result
      value                      = "access_as_user"
      type                       = "User"
      enabled                    = true
      admin_consent_display_name = "Use the agent as the signed-in user"
      admin_consent_description  = "Allows the web app to call the agent orchestrator as the signed-in user."
      user_consent_display_name  = "Use the agent as you"
      user_consent_description   = "Allows the web app to call the agent on your behalf."
    }
  }

  web {
    redirect_uris = var.orchestrator_redirect_uris
  }

  required_resource_access {
    resource_app_id = azuread_application.mcp[0].client_id

    resource_access {
      id   = random_uuid.mcp_scope[0].result
      type = "Scope"
    }
  }
}

resource "azuread_application_identifier_uri" "orchestrator" {
  count          = var.manage_entra_apps ? 1 : 0
  application_id = azuread_application.orchestrator[0].id
  identifier_uri = "api://${azuread_application.orchestrator[0].client_id}"
}

resource "azuread_service_principal" "orchestrator" {
  count     = var.manage_entra_apps ? 1 : 0
  client_id = azuread_application.orchestrator[0].client_id
}

# The MCP app trusts the orchestrator to request user_impersonation without a user prompt.
resource "azuread_application_pre_authorized" "mcp_orchestrator" {
  count                = var.manage_entra_apps ? 1 : 0
  application_id       = azuread_application.mcp[0].id
  authorized_client_id = azuread_application.orchestrator[0].client_id
  permission_ids       = [random_uuid.mcp_scope[0].result]
}

# Tenant-wide admin consent for orchestrator -> MCP (user_impersonation).
resource "azuread_service_principal_delegated_permission_grant" "orchestrator_to_mcp" {
  count                                = var.manage_entra_apps ? 1 : 0
  service_principal_object_id          = azuread_service_principal.orchestrator[0].object_id
  resource_service_principal_object_id = azuread_service_principal.mcp[0].object_id
  claim_values                         = ["user_impersonation"]
}
