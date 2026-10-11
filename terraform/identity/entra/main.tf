# Microsoft Entra ID identity seed: users, security groups, memberships and storage RBAC assigned to GROUPS.
# Stands in for the enterprise directory sync (and, in the enterprise, for the federated domain: here test users
# are cloud-only and sign in to Entra interactively). Authenticate with `az login` as a tenant admin.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.53"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "azuread" {
  tenant_id = var.tenant_id == "" ? null : var.tenant_id
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id == "" ? null : var.subscription_id
}

module "directory" {
  source         = "../modules/directory"
  users_file     = "${path.module}/../../../identity/users.yaml"
  offboard_users = var.offboard_users
}

# ---- users ----
# azuread_user requires an initial password. It is random, never shown in logs, kept only in local Terraform state
# and must be changed on first sign-in (an admin can also reset it in the portal).

resource "random_password" "user" {
  for_each         = module.directory.users
  length           = 24
  special          = true
  override_special = "!@#%^*-_=+"
}

resource "azuread_user" "user" {
  for_each              = module.directory.users
  user_principal_name   = each.value.entra_upn
  display_name          = each.value.display_name
  mail_nickname         = each.key
  account_enabled       = each.value.enabled
  password              = random_password.user[each.key].result
  force_password_change = true
}

# ---- groups and membership (offboarded users are removed from every group) ----

resource "azuread_group" "group" {
  for_each         = module.directory.groups
  display_name     = "poc-${each.key}"
  description      = each.value.description
  security_enabled = true
  mail_enabled     = false
}

resource "azuread_group_member" "member" {
  for_each         = module.directory.memberships
  group_object_id  = azuread_group.group[each.value.group].object_id
  member_object_id = azuread_user.user[each.value.user].object_id
}

# ---- storage RBAC: roles are assigned to groups at container scope, never to users or to the workload identity ----

data "azurerm_storage_account" "storage" {
  name                = var.storage_account_name
  resource_group_name = var.resource_group_name
}

locals {
  container_role_assignments = {
    for pair in flatten([
      for g in module.directory.groups : [
        for r in g.azure_roles : { key = "${g.id}/${r.container}/${r.role}", group = g.id, container = r.container, role = r.role }
      ]
    ]) : pair.key => pair
  }
  containers = toset([for a in values(local.container_role_assignments) : a.container])
}

data "azurerm_storage_container" "container" {
  for_each             = local.containers
  name                 = each.value
  storage_account_name = data.azurerm_storage_account.storage.name
}

resource "azurerm_role_assignment" "group_container_role" {
  for_each             = local.container_role_assignments
  scope                = data.azurerm_storage_container.container[each.value.container].resource_manager_id
  role_definition_name = each.value.role
  principal_id         = azuread_group.group[each.value.group].object_id
}
