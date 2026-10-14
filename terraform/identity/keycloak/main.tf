# Keycloak identity seed: realm, groups, users, roles, clients and consent-required agent scopes.
# Stands in for the enterprise IdP and its directory sync. No passwords are set here: users are created without
# credentials and an admin sets/resets them (docs/poc-setup-guide.md, section 5).

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    keycloak = {
      source  = "keycloak/keycloak"
      version = "~> 5.0"
    }
  }
}

provider "keycloak" {
  url       = var.keycloak_url
  realm     = "master"
  client_id = "admin-cli"
  username  = var.keycloak_admin_user
  password  = var.keycloak_admin_password
}

module "directory" {
  source         = "../modules/directory"
  users_file     = "${path.module}/../../../identity/users.yaml"
  offboard_users = var.offboard_users
}

locals {
  scope_role_names = { for s in module.directory.agent_scopes : s => "agent-scope-${replace(lower(s), "/[^a-z0-9]+/", "-")}" }
}

resource "keycloak_realm" "poc" {
  realm        = module.directory.settings.keycloak_realm
  enabled      = true
  display_name = "Multicloud agentic POC"

  ssl_required             = var.ssl_required
  registration_allowed     = false
  login_with_email_allowed = true
  duplicate_emails_allowed = false
  reset_password_allowed   = false
  edit_username_allowed    = false
  access_token_lifespan    = "5m"
  sso_session_idle_timeout = "30m"
  sso_session_max_lifespan = "10h"
  password_policy          = "length(12) and notUsername"

  security_defenses {
    brute_force_detection {
      permanent_lockout                = false
      max_login_failures               = 5
      failure_reset_time_seconds       = 900
      wait_increment_seconds           = 60
      max_failure_wait_seconds         = 900
      quick_login_check_milli_seconds  = 1000
      minimum_quick_login_wait_seconds = 60
    }
  }
}

# ---- roles: one realm role per agent scope; users are eligible for a scope only through group membership ----

resource "keycloak_role" "agent_scope" {
  for_each    = local.scope_role_names
  realm_id    = keycloak_realm.poc.id
  name        = each.value
  description = "Eligible to consent to the agent using scope ${each.key}"
}

# ---- groups (mirror the enterprise groups) ----

resource "keycloak_group" "group" {
  for_each = module.directory.groups
  realm_id = keycloak_realm.poc.id
  name     = each.key
}

resource "keycloak_group_roles" "group" {
  for_each = { for k, g in module.directory.groups : k => g if length(g.agent_scopes) > 0 }
  realm_id = keycloak_realm.poc.id
  group_id = keycloak_group.group[each.key].id
  role_ids = [for s in each.value.agent_scopes : keycloak_role.agent_scope[s].id]
}

# ---- users (no credentials; offboarded users are disabled) ----

resource "keycloak_user" "user" {
  for_each       = module.directory.users
  realm_id       = keycloak_realm.poc.id
  username       = each.key
  enabled        = each.value.enabled
  email          = each.value.email
  email_verified = true
  first_name     = title(each.key)
  last_name      = "POC"
}

resource "keycloak_user_groups" "user" {
  for_each  = { for k, u in module.directory.users : k => u if u.enabled }
  realm_id  = keycloak_realm.poc.id
  user_id   = keycloak_user.user[each.key].id
  group_ids = [for gid in each.value.groups : keycloak_group.group[gid].id]
}

# ---- claims: realm roles -> "roles", group membership -> "groups" ----

resource "keycloak_openid_client_scope" "identity" {
  realm_id               = keycloak_realm.poc.id
  name                   = "agent-identity"
  description            = "Adds the user's agent-eligibility roles and groups to tokens"
  include_in_token_scope = false
}

resource "keycloak_openid_user_realm_role_protocol_mapper" "roles" {
  realm_id        = keycloak_realm.poc.id
  client_scope_id = keycloak_openid_client_scope.identity.id
  name            = "realm-roles"
  claim_name      = "roles"
  multivalued     = true
}

resource "keycloak_openid_group_membership_protocol_mapper" "groups" {
  realm_id        = keycloak_realm.poc.id
  client_scope_id = keycloak_openid_client_scope.identity.id
  name            = "groups"
  claim_name      = "groups"
  full_path       = false
}

# Tokens issued to the web app are accepted by the orchestrator (its client id appears in `aud`).
resource "keycloak_openid_audience_protocol_mapper" "orchestrator_audience" {
  realm_id                 = keycloak_realm.poc.id
  client_scope_id          = keycloak_openid_client_scope.identity.id
  name                     = "orchestrator-audience"
  included_client_audience = keycloak_openid_client.orchestrator.client_id
  add_to_id_token          = false
  add_to_access_token      = true
}

# ---- agent scopes: optional, shown on the consent screen ----

resource "keycloak_openid_client_scope" "agent" {
  for_each               = local.scope_role_names
  realm_id               = keycloak_realm.poc.id
  name                   = each.key
  description            = "Allow the agent to act for you with scope ${each.key}"
  include_in_token_scope = true
  consent_screen_text    = "Let the assistant act on your behalf: ${each.key}"
  gui_order              = 10
}

# ---- clients ----

# Browser/BFF client: authorization code + PKCE, user must consent to the agent scopes.
resource "keycloak_openid_client" "web_frontend" {
  realm_id  = keycloak_realm.poc.id
  client_id = "web-frontend"
  name      = "Web frontend (BFF)"
  enabled   = true

  access_type                  = "PUBLIC"
  standard_flow_enabled        = true
  implicit_flow_enabled        = false
  direct_access_grants_enabled = false
  service_accounts_enabled     = false
  pkce_code_challenge_method   = "S256"
  consent_required             = true

  valid_redirect_uris = var.web_redirect_uris
  web_origins         = var.web_origins
}

resource "keycloak_openid_client_default_scopes" "web_frontend" {
  realm_id  = keycloak_realm.poc.id
  client_id = keycloak_openid_client.web_frontend.id
  default_scopes = [
    "profile",
    "email",
    "roles",
    keycloak_openid_client_scope.identity.name,
  ]
}

resource "keycloak_openid_client_optional_scopes" "web_frontend" {
  realm_id        = keycloak_realm.poc.id
  client_id       = keycloak_openid_client.web_frontend.id
  optional_scopes = [for s in keys(local.scope_role_names) : keycloak_openid_client_scope.agent[s].name]
}

# Confidential client used by the orchestrator for RFC 8693 token exchange (Keycloak "standard token exchange", 26.2+).
# It may exchange a user's access token (whose audience includes this client) for a token for ONE resource server and ONE
# of the agent scopes it is allowed to request below. Its token carries `act.sub` = the orchestrator's SPIFFE ID, which
# resource servers compare with the JWT-SVID the workload presents.
resource "keycloak_openid_client" "orchestrator" {
  realm_id  = keycloak_realm.poc.id
  client_id = "agent-orchestrator-client"
  name      = "Agent orchestrator"
  enabled   = true

  access_type                  = "CONFIDENTIAL"
  standard_flow_enabled        = false
  implicit_flow_enabled        = false
  direct_access_grants_enabled = false
  service_accounts_enabled     = false

  extra_config = {
    "standard.token.exchange.enabled" = "true"
  }
}

# Only profile/email by default: no `roles` scope, so exchanged tokens do not pick up extra audiences such as `account`.
resource "keycloak_openid_client_default_scopes" "orchestrator" {
  realm_id       = keycloak_realm.poc.id
  client_id      = keycloak_openid_client.orchestrator.id
  default_scopes = ["profile", "email"]
}

# The agent scopes the orchestrator may request in an exchange (each exchange requests exactly one).
resource "keycloak_openid_client_optional_scopes" "orchestrator" {
  realm_id        = keycloak_realm.poc.id
  client_id       = keycloak_openid_client.orchestrator.id
  optional_scopes = [for s in keys(local.scope_role_names) : keycloak_openid_client_scope.agent[s].name]
}

# Delegation claim: the acting agent. Static because only this client can use the mapper.
resource "keycloak_openid_hardcoded_claim_protocol_mapper" "orchestrator_actor" {
  realm_id            = keycloak_realm.poc.id
  client_id           = keycloak_openid_client.orchestrator.id
  name                = "actor-spiffe-id"
  claim_name          = "act.sub"
  claim_value         = var.orchestrator_spiffe_id
  claim_value_type    = "String"
  add_to_id_token     = false
  add_to_access_token = true
  add_to_userinfo     = false
}

# Audience for tokens minted for the Azure MCP server (no interactive flows).
resource "keycloak_openid_client" "azure_mcp" {
  realm_id  = keycloak_realm.poc.id
  client_id = "mcp-azure-service"
  name      = "Azure MCP server"
  enabled   = true

  access_type                  = "CONFIDENTIAL"
  standard_flow_enabled        = false
  implicit_flow_enabled        = false
  direct_access_grants_enabled = false
  service_accounts_enabled     = false
}

# Audience for tokens minted for the GCP MCP server (no interactive flows).
resource "keycloak_openid_client" "gcp_mcp" {
  realm_id  = keycloak_realm.poc.id
  client_id = "mcp-gcp-service"
  name      = "GCP MCP server"
  enabled   = true

  access_type                  = "CONFIDENTIAL"
  standard_flow_enabled        = false
  implicit_flow_enabled        = false
  direct_access_grants_enabled = false
  service_accounts_enabled     = false
}
