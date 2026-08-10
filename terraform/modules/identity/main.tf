# The platform identity, and the two workload identities that stand in
# for the applications consuming secrets.
#
# The security claim of this whole project rests on what is granted here.
# The platform can enumerate secrets and read their metadata. It cannot
# read a value. That is not enforced by careful coding, it is enforced by
# the role: Key Vault Reader carries
# Microsoft.KeyVault/vaults/secrets/readMetadata/action and does not carry
# .../secrets/getSecret/action.
#
# Azure has no equivalent of an IAM explicit deny outside deny assignments,
# which are only creatable through managed applications or Blueprints. The
# honest Azure answer is a role that never granted the permission in the
# first place, plus an Azure Policy audit for drift, plus the redaction
# layer in the application. All three are here.

resource "azurerm_user_assigned_identity" "platform" {
  name                = "${var.prefix}-platform-id"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags
}

# Stand-in workloads. These do hold Key Vault Secrets User, because their
# entire job is to read secrets and produce the audit events the consumer
# map is built from.
resource "azurerm_user_assigned_identity" "consumer" {
  for_each = toset(["app", "batch"])

  name                = "${var.prefix}-consumer-${each.key}-id"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags
}

# Reading the Log Analytics workspace for the consumer map.
resource "azurerm_role_assignment" "log_reader" {
  scope                = "/subscriptions/${var.subscription_id}"
  role_definition_name = "Log Analytics Reader"
  principal_id         = azurerm_user_assigned_identity.platform.principal_id
}

# Enumerating vaults, App Configuration stores, and their control plane
# properties. Reader is control plane only and grants no data actions.
resource "azurerm_role_assignment" "reader" {
  scope                = "/subscriptions/${var.subscription_id}"
  role_definition_name = "Reader"
  principal_id         = azurerm_user_assigned_identity.platform.principal_id
}

# Graph app roles for the Entra credential sweep and for resolving
# consumer object ids to display names. Application.Read.All returns
# credential descriptors (start, end, hint) and never credential material.
data "azuread_service_principal" "msgraph" {
  count     = var.grant_graph ? 1 : 0
  client_id = "00000003-0000-0000-c000-000000000000"
}

resource "azuread_app_role_assignment" "graph" {
  for_each = var.grant_graph ? toset(["Application.Read.All", "Directory.Read.All"]) : toset([])

  app_role_id         = data.azuread_service_principal.msgraph[0].app_role_ids[each.value]
  principal_object_id = azurerm_user_assigned_identity.platform.principal_id
  resource_object_id  = data.azuread_service_principal.msgraph[0].object_id
}

# Drift detection for the one thing that would invalidate the security
# claim: someone granting this identity a role that can read secret
# values. Audit rather than deny, because a deny policy at subscription
# scope would block legitimate grants to the consumer identities too.
resource "azurerm_subscription_policy_assignment" "no_secret_read" {
  name                 = "${var.prefix}-platform-no-secret-read"
  display_name         = "Audit data plane secret read grants to the secops platform identity"
  subscription_id      = "/subscriptions/${var.subscription_id}"
  policy_definition_id = azurerm_policy_definition.no_secret_read.id
  description          = <<-EOT
    The secrets lifecycle platform is designed to read metadata only. This
    assignment flags any role assignment that would give its identity data
    plane read access to Key Vault secrets, keys, or certificates.
  EOT

  parameters = jsonencode({
    platformPrincipalId = { value = azurerm_user_assigned_identity.platform.principal_id }
  })
}

resource "azurerm_policy_definition" "no_secret_read" {
  name         = "${var.prefix}-audit-platform-secret-read"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Audit secret read role assignments to the secops platform identity"

  metadata = jsonencode({ category = "Key Vault" })

  parameters = jsonencode({
    platformPrincipalId = {
      type     = "String"
      metadata = { displayName = "Platform identity principal id" }
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        { field = "type", equals = "Microsoft.Authorization/roleAssignments" },
        {
          field  = "Microsoft.Authorization/roleAssignments/principalId",
          equals = "[parameters('platformPrincipalId')]"
        },
        {
          field = "Microsoft.Authorization/roleAssignments/roleDefinitionId",
          in = [
            # Key Vault Secrets User
            "/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6",
            # Key Vault Secrets Officer
            "/providers/Microsoft.Authorization/roleDefinitions/b86a8fe4-44ce-4948-aee5-eccb2c155cd7",
            # Key Vault Certificates Officer
            "/providers/Microsoft.Authorization/roleDefinitions/a4417e6f-fecd-4de8-b567-7b0420556985",
            # Key Vault Crypto User
            "/providers/Microsoft.Authorization/roleDefinitions/12338af0-0e69-4776-bea7-57ae8d297424",
            # Key Vault Administrator
            "/providers/Microsoft.Authorization/roleDefinitions/00482a5a-887f-4fb3-b363-3b7fe8e74483"
          ]
        }
      ]
    }
    then = { effect = "audit" }
  })
}
