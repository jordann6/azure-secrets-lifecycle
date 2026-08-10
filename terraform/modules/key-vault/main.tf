# The demo vault, its diagnostic settings, and the role assignments that
# make the metadata-only claim true.
#
# Diagnostic settings are the load bearing piece. Without the AuditEvent
# category flowing to the workspace there is no consumer map, and the
# whole platform degrades to what Azure Policy already tells you.

resource "azurerm_key_vault" "main" {
  name                = "${var.prefix}-kv-${var.suffix}"
  resource_group_name = var.resource_group_name
  location            = var.location
  tenant_id           = var.tenant_id
  sku_name            = "standard"

  # RBAC rather than access policies, on purpose. It is the model Azure
  # recommends, and it is the harder case for this platform: an RBAC vault
  # does not name its readers on the resource, so the observed consumer
  # map is the only evidence of who actually reads a secret. The scoring
  # model accounts for that explicitly.
  rbac_authorization_enabled = true

  purge_protection_enabled   = true
  soft_delete_retention_days = 7

  public_network_access_enabled = true

  network_acls {
    bypass         = "AzureServices"
    default_action = var.operator_ip == "" ? "Allow" : "Deny"
    ip_rules       = var.operator_ip == "" ? [] : [var.operator_ip]
  }

  tags = var.tags
}

resource "azurerm_monitor_diagnostic_setting" "vault" {
  name                       = "${var.prefix}-kv-audit"
  target_resource_id         = azurerm_key_vault.main.id
  log_analytics_workspace_id = var.workspace_id
  # Resource specific mode puts events in AZKVAuditLogs with typed
  # columns instead of the shared AzureDiagnostics table. Cheaper to
  # query and the only mode new deployments should use.
  log_analytics_destination_type = "Dedicated"

  enabled_log {
    category = "AuditEvent"
  }

  enabled_log {
    category = "AzurePolicyEvaluationDetails"
  }
}

# The platform identity. Key Vault Reader reads metadata for secrets,
# keys, and certificates and cannot read a value. This single line is the
# security posture of the project.
resource "azurerm_role_assignment" "platform_metadata" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Reader"
  principal_id         = var.platform_principal_id
}

# The stand-in workloads, which do read values. Their reads are the audit
# events the consumer map is built from.
resource "azurerm_role_assignment" "consumer_secrets" {
  for_each = var.consumer_principal_ids

  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = each.value
}

# The operator, so the seed can create the test estate. Scoped to this
# vault and nothing else.
resource "azurerm_role_assignment" "operator_officer" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Administrator"
  principal_id         = var.operator_object_id
}
