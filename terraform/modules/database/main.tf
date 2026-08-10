# Postgres Flexible Server, B1ms burstable.
#
# Password authentication is disabled. The application connects with an
# Entra ID access token as its password, minted per connection from the
# same managed identity that reads Key Vault metadata, so this deployment
# contains no stored database credential at all. See
# config/initializers/entra_postgres_auth.rb for the client side.
#
# Cost note: this is the only resource here that does not scale to zero.
# B_Standard_B1ms with 32 GB runs about $13 a month if it is left on,
# which is roughly $0.43 a day for a deploy, demo, destroy cycle. It can
# be stopped between demos with
#   az postgres flexible-server stop -g <rg> -n <server>
# which drops the bill to storage only.

resource "azurerm_postgresql_flexible_server" "main" {
  name                = "${var.prefix}-pg-${var.suffix}"
  resource_group_name = var.resource_group_name
  location            = var.location

  version    = "16"
  sku_name   = var.sku_name
  storage_mb = var.storage_mb

  # Burstable tiers do not support high availability or zone redundant
  # backups, and this workload does not need them: a lost scan is
  # re-runnable and the evidence of record lives in immutable blob
  # storage, not here.
  backup_retention_days        = 7
  geo_redundant_backup_enabled = false
  zone                         = "1"

  public_network_access_enabled = true

  authentication {
    active_directory_auth_enabled = true
    password_auth_enabled         = false
    tenant_id                     = var.tenant_id
  }

  tags = var.tags

  lifecycle {
    # Azure picks an availability zone if one is not pinned, and a later
    # plan that sees a different zone would force replacement of the
    # database.
    ignore_changes = [zone, high_availability]
  }
}

resource "azurerm_postgresql_flexible_server_database" "main" {
  name      = "secops"
  server_id = azurerm_postgresql_flexible_server.main.id
  charset   = "UTF8"
  collation = "en_US.utf8"

  lifecycle {
    prevent_destroy = false
  }
}

# The platform identity is an Entra administrator on the server, which is
# what lets it connect by token with no in-database bootstrap step. Making
# it a plain role instead would need a session as an existing Entra admin
# running pgaadauth_create_principal, which Terraform cannot express and
# which would put a manual step in the middle of `make deploy`.
resource "azurerm_postgresql_flexible_server_active_directory_administrator" "platform" {
  server_name         = azurerm_postgresql_flexible_server.main.name
  resource_group_name = var.resource_group_name
  tenant_id           = var.tenant_id
  object_id           = var.platform_identity.principal_id
  principal_name      = var.platform_identity.name
  principal_type      = "ServicePrincipal"
}

# The operator, so migrations and psql sessions work from a workstation.
resource "azurerm_postgresql_flexible_server_active_directory_administrator" "operator" {
  server_name         = azurerm_postgresql_flexible_server.main.name
  resource_group_name = var.resource_group_name
  tenant_id           = var.tenant_id
  object_id           = var.admin_object_id
  principal_name      = "operator"
  principal_type      = "User"
}

# Container Apps consumption workloads have no stable outbound address, so
# the alternative to this rule is VNet integration with a NAT gateway,
# which costs more per month than everything else in this project put
# together. The exposure is bounded: password auth is off, so reaching the
# listener without an Entra token in the tenant gets you nothing.
resource "azurerm_postgresql_flexible_server_firewall_rule" "azure_services" {
  name             = "allow-azure-services"
  server_id        = azurerm_postgresql_flexible_server.main.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

resource "azurerm_postgresql_flexible_server_firewall_rule" "operator" {
  count = var.operator_ip == "" ? 0 : 1

  name             = "allow-operator"
  server_id        = azurerm_postgresql_flexible_server.main.id
  start_ip_address = split("/", var.operator_ip)[0]
  end_ip_address   = split("/", var.operator_ip)[0]
}
