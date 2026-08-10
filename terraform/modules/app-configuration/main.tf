# App Configuration store, the SSM Parameter Store analogue.
#
# This is the honest weak spot in the metadata-only story and it is worth
# stating plainly. App Configuration Data Reader is the narrowest built in
# role and it does return values. There is no Key Vault Reader equivalent
# here, so the guarantee downgrades from "the role makes it impossible" to
# "the request never asks for it and the redactor scrubs the response".
# The scanner uses $select to request metadata fields only.
#
# The structural fix is the Key Vault reference pattern: keep the material
# in Key Vault, keep only the reference in App Configuration, and the
# metadata-only guarantee comes back from the vault side. The seed creates
# one of those so the difference is visible on the dashboard.

resource "azurerm_app_configuration" "main" {
  name                = "${var.prefix}-appcs-${var.suffix}"
  resource_group_name = var.resource_group_name
  location            = var.location
  # Free tier: one store per subscription, 10 MB, no SLA. Enough for a
  # demo estate and it costs nothing.
  sku = "free"

  local_auth_enabled    = false
  public_network_access = "Enabled"

  # The free SKU does not implement soft delete, and sending any retention
  # window with it fails the create with SkuFeatureNotSupported. The
  # provider validates the field to 1 to 7, so there is no value that
  # works: the attribute has to be absent entirely. The standard SKU
  # supports it and costs about $36 a month, which is more than the rest
  # of this deployment combined for a demo store holding five keys.
  purge_protection_enabled = false

  tags = var.tags
}

resource "azurerm_monitor_diagnostic_setting" "store" {
  name                       = "${var.prefix}-appcs-audit"
  target_resource_id         = azurerm_app_configuration.main.id
  log_analytics_workspace_id = var.workspace_id

  enabled_log {
    category = "Audit"
  }

  enabled_log {
    category = "HttpRequest"
  }
}

resource "azurerm_role_assignment" "platform_reader" {
  scope                = azurerm_app_configuration.main.id
  role_definition_name = "App Configuration Data Reader"
  principal_id         = var.platform_principal_id
}

resource "azurerm_role_assignment" "operator_owner" {
  scope                = azurerm_app_configuration.main.id
  role_definition_name = "App Configuration Data Owner"
  principal_id         = var.operator_object_id
}
