# Reads identity/users.yaml (the single source of truth for the POC identity seed) and normalises it.
# Every field is always present so callers can rely on the shape. Nothing secret is read or produced here.

variable "users_file" {
  type        = string
  description = "Path to identity/users.yaml"
}

variable "offboard_users" {
  type        = list(string)
  description = "User ids to treat as deprovisioned regardless of the file (see scripts/identity-offboard.js)"
  default     = []
}

locals {
  doc = yamldecode(file(var.users_file))

  groups = {
    for g in local.doc.groups : g.id => {
      id           = g.id
      description  = try(g.description, "")
      agent_scopes = try(g.agent_scopes, [])
      azure_roles  = try(g.azure_roles, [])
      bigquery     = try(g.bigquery, [])
    }
  }

  users = {
    for u in local.doc.users : u.id => {
      id           = u.id
      display_name = try(u.display_name, u.id)
      enabled      = try(u.enabled, true) && !contains(var.offboard_users, u.id)
      email        = lower(u.emails.keycloak)
      entra_upn    = lower(u.emails.entra_upn)
      google_email = try(lower(u.emails.google), "")
      groups       = try(u.groups, [])
    }
  }

  # Unique agent scopes across all groups, e.g. ["Mail.Send", "mcp:bigquery:audit", ...]
  agent_scopes = distinct(flatten([for g in local.groups : g.agent_scopes]))

  # Flattened (user, group) membership for enabled users only
  memberships = {
    for pair in flatten([
      for u in local.users : [
        for gid in u.groups : { key = "${u.id}/${gid}", user = u.id, group = gid }
      ] if u.enabled
    ]) : pair.key => pair
  }
}

output "settings" {
  value = local.doc.settings
}

output "groups" {
  value = local.groups
}

output "users" {
  value = local.users
}

output "agent_scopes" {
  value = local.agent_scopes
}

output "memberships" {
  value = local.memberships
}
