# App registrations for the agent's Azure path, with tenant-wide (admin) consent, fine-grained delegated permissions and
# secretless credentials. Off by default (manage_entra_apps = false) because the repo's earlier apps were created by
# scripts/setup-entra-wif.sh and their client IDs are referenced elsewhere; enable on a fresh tenant.
#
#   web-frontend-poc  (public client, PKCE)  --signs the user in-->  agent-orchestrator-poc  (access_as_user)
#   agent-orchestrator-poc  --OBO, authenticated by its SPIFFE JWT-SVID-->  azure-mcp-server-poc  (Mcp.Storage.*)
#   azure-mcp-server-poc    --OBO, authenticated by its managed identity-->  Azure Storage (user_impersonation)
#   (optional)  agent-orchestrator-poc  --OBO-->  Microsoft Graph Mail.Send    (gated by grant_mail_send)
#
# No client secret is created: the orchestrator trusts SPIRE (federated credential on its subject), and the MCP server
# trusts its App Service managed identity (federated credential on the identity's object id).

data "azuread_client_config" "current" {}

locals {
  # One delegated permission per (action, container). Azure RBAC on the container still decides what the user can do.
  storage_scopes = {
    ReadApp1  = "Read blobs in container app1"
    ReadApp2  = "Read blobs in container app2"
    WriteApp1 = "Write blobs in container app1"
    WriteApp2 = "Write blobs in container app2"
  }
  apps = var.manage_entra_apps
  well_known = {
    azure_storage_client_id = "e406a681-f3d4-42a8-90b6-c2b029497af1"
    graph_client_id         = "00000003-0000-0000-c000-000000000000"
  }
}

resource "random_uuid" "mcp_scope" {
  for_each = local.apps ? local.storage_scopes : {}
}

resource "random_uuid" "orchestrator_scope" {
  count = local.apps ? 1 : 0
}

# Microsoft first-party APIs the apps call on behalf of users (adopted if they already exist in the tenant)
resource "azuread_service_principal" "azure_storage" {
  count        = local.apps ? 1 : 0
  client_id    = local.well_known.azure_storage_client_id
  use_existing = true
}

resource "azuread_service_principal" "graph" {
  count        = local.apps && var.grant_mail_send ? 1 : 0
  client_id    = local.well_known.graph_client_id
  use_existing = true
}

# ---------------- Azure MCP server ----------------

resource "azuread_application" "mcp" {
  count            = local.apps ? 1 : 0
  display_name     = "azure-mcp-server-poc"
  sign_in_audience = "AzureADMyOrg"

  api {
    requested_access_token_version = 2

    dynamic "oauth2_permission_scope" {
      for_each = local.storage_scopes
      content {
        id                         = random_uuid.mcp_scope[oauth2_permission_scope.key].result
        value                      = "Mcp.Storage.${oauth2_permission_scope.key}"
        type                       = "User"
        enabled                    = true
        admin_consent_display_name = oauth2_permission_scope.value
        admin_consent_description  = "${oauth2_permission_scope.value} on behalf of the signed-in user. Azure RBAC still applies."
        user_consent_display_name  = oauth2_permission_scope.value
        user_consent_description   = "${oauth2_permission_scope.value} on your behalf."
      }
    }
  }

  # The MCP server reaches Storage as the user (on-behalf-of)
  required_resource_access {
    resource_app_id = local.well_known.azure_storage_client_id

    resource_access {
      id   = azuread_service_principal.azure_storage[0].oauth2_permission_scope_ids["user_impersonation"]
      type = "Scope"
    }
  }
}

resource "azuread_application_identifier_uri" "mcp" {
  count          = local.apps ? 1 : 0
  application_id = azuread_application.mcp[0].id
  identifier_uri = "api://${azuread_application.mcp[0].client_id}"
}

resource "azuread_service_principal" "mcp" {
  count     = local.apps ? 1 : 0
  client_id = azuread_application.mcp[0].client_id
}

# The MCP server authenticates to Entra with its App Service managed identity (no secret): created only once the
# identity's object id is known (azure/ output `mcp_managed_identity_principal_id`).
resource "azuread_application_federated_identity_credential" "mcp_managed_identity" {
  count          = local.apps && var.mcp_managed_identity_principal_id != "" ? 1 : 0
  application_id = azuread_application.mcp[0].id
  display_name   = "mcp-app-service-managed-identity"
  description    = "The Azure MCP server's managed identity authenticates as this application"
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://login.microsoftonline.com/${data.azuread_client_config.current.tenant_id}/v2.0"
  subject        = var.mcp_managed_identity_principal_id
}

# ---------------- Orchestrator ----------------

resource "azuread_application" "orchestrator" {
  count            = local.apps ? 1 : 0
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

  required_resource_access {
    resource_app_id = azuread_application.mcp[0].client_id

    dynamic "resource_access" {
      for_each = local.storage_scopes
      content {
        id   = random_uuid.mcp_scope[resource_access.key].result
        type = "Scope"
      }
    }
  }

  # Sending mail is a separate, deliberately gated permission (grant_mail_send); the agent also needs the user's Keycloak
  # consent for Mail.Send and an approval at the time of the action.
  dynamic "required_resource_access" {
    for_each = var.grant_mail_send ? [1] : []
    content {
      resource_app_id = local.well_known.graph_client_id

      resource_access {
        id   = azuread_service_principal.graph[0].oauth2_permission_scope_ids["Mail.Send"]
        type = "Scope"
      }
    }
  }
}

resource "azuread_application_identifier_uri" "orchestrator" {
  count          = local.apps ? 1 : 0
  application_id = azuread_application.orchestrator[0].id
  identifier_uri = "api://${azuread_application.orchestrator[0].client_id}"
}

resource "azuread_service_principal" "orchestrator" {
  count     = local.apps ? 1 : 0
  client_id = azuread_application.orchestrator[0].client_id
}

# The orchestrator authenticates to Entra with its SPIFFE JWT-SVID: SPIRE's OIDC issuer + the workload's SPIFFE ID.
resource "azuread_application_federated_identity_credential" "orchestrator_spire" {
  count          = local.apps && var.spire_oidc_issuer_url != "" ? 1 : 0
  application_id = azuread_application.orchestrator[0].id
  display_name   = "spire-orchestrator"
  description    = "The orchestrator workload authenticates as this application with its SPIFFE JWT-SVID"
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = var.spire_oidc_issuer_url
  subject        = var.spiffe_orchestrator_id
}

# ---------------- Web app (backend-for-frontend), public client ----------------

resource "azuread_application" "web" {
  count                          = local.apps ? 1 : 0
  display_name                   = "web-frontend-poc"
  sign_in_audience               = "AzureADMyOrg"
  fallback_public_client_enabled = true

  public_client {
    redirect_uris = var.bff_redirect_uris
  }

  required_resource_access {
    resource_app_id = azuread_application.orchestrator[0].client_id

    resource_access {
      id   = random_uuid.orchestrator_scope[0].result
      type = "Scope"
    }
  }
}

resource "azuread_service_principal" "web" {
  count     = local.apps ? 1 : 0
  client_id = azuread_application.web[0].client_id
}

# ---------------- Trust between the apps (pre-authorisation) and tenant-wide consent ----------------

resource "azuread_application_pre_authorized" "mcp_trusts_orchestrator" {
  count                = local.apps ? 1 : 0
  application_id       = azuread_application.mcp[0].id
  authorized_client_id = azuread_application.orchestrator[0].client_id
  permission_ids       = [for k in keys(local.storage_scopes) : random_uuid.mcp_scope[k].result]
}

resource "azuread_application_pre_authorized" "orchestrator_trusts_web" {
  count                = local.apps ? 1 : 0
  application_id       = azuread_application.orchestrator[0].id
  authorized_client_id = azuread_application.web[0].client_id
  permission_ids       = [random_uuid.orchestrator_scope[0].result]
}

resource "azuread_service_principal_delegated_permission_grant" "orchestrator_to_mcp" {
  count                                = local.apps ? 1 : 0
  service_principal_object_id          = azuread_service_principal.orchestrator[0].object_id
  resource_service_principal_object_id = azuread_service_principal.mcp[0].object_id
  claim_values                         = [for k in keys(local.storage_scopes) : "Mcp.Storage.${k}"]
}

resource "azuread_service_principal_delegated_permission_grant" "web_to_orchestrator" {
  count                                = local.apps ? 1 : 0
  service_principal_object_id          = azuread_service_principal.web[0].object_id
  resource_service_principal_object_id = azuread_service_principal.orchestrator[0].object_id
  claim_values                         = ["access_as_user"]
}

resource "azuread_service_principal_delegated_permission_grant" "mcp_to_storage" {
  count                                = local.apps ? 1 : 0
  service_principal_object_id          = azuread_service_principal.mcp[0].object_id
  resource_service_principal_object_id = azuread_service_principal.azure_storage[0].object_id
  claim_values                         = ["user_impersonation"]
}

resource "azuread_service_principal_delegated_permission_grant" "orchestrator_to_graph_mail" {
  count                                = local.apps && var.grant_mail_send ? 1 : 0
  service_principal_object_id          = azuread_service_principal.orchestrator[0].object_id
  resource_service_principal_object_id = azuread_service_principal.graph[0].object_id
  claim_values                         = ["Mail.Send"]
}
