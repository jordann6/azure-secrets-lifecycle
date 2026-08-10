data "azurerm_client_config" "current" {}

resource "random_string" "suffix" {
  length  = 6
  upper   = false
  special = false
}

locals {
  suffix = random_string.suffix.result
  name   = var.prefix

  tags = {
    Project     = "azure-secrets-lifecycle"
    Environment = var.environment
    Owner       = var.owner
    ManagedBy   = "terraform"
  }
}

resource "azurerm_resource_group" "main" {
  name     = "${local.name}-rg"
  location = var.location
  tags     = local.tags
}

# Observability first: the workspace is both where Key Vault audit events
# land for the consumer map and where the Container Apps environment sends
# its own logs, so everything downstream depends on it.
module "observability" {
  source = "./modules/observability"

  prefix                = local.name
  suffix                = local.suffix
  resource_group_name   = azurerm_resource_group.main.name
  location              = var.location
  retention_days        = var.log_retention_days
  enable_findings_table = var.enable_sentinel_export
  tags                  = local.tags
}

module "identity" {
  source = "./modules/identity"

  prefix              = local.name
  resource_group_name = azurerm_resource_group.main.name
  location            = var.location
  subscription_id     = var.subscription_id
  grant_graph         = var.grant_graph_permissions
  tags                = local.tags
}

module "key_vault" {
  source = "./modules/key-vault"

  prefix                 = local.name
  suffix                 = local.suffix
  resource_group_name    = azurerm_resource_group.main.name
  location               = var.location
  tenant_id              = data.azurerm_client_config.current.tenant_id
  operator_object_id     = data.azurerm_client_config.current.object_id
  operator_ip            = var.operator_ip
  platform_principal_id  = module.identity.principal_id
  consumer_principal_ids = module.identity.consumer_principal_ids
  workspace_id           = module.observability.workspace_resource_id
  tags                   = local.tags
}

module "app_configuration" {
  source = "./modules/app-configuration"

  prefix                = local.name
  suffix                = local.suffix
  resource_group_name   = azurerm_resource_group.main.name
  location              = var.location
  operator_object_id    = data.azurerm_client_config.current.object_id
  platform_principal_id = module.identity.principal_id
  workspace_id          = module.observability.workspace_resource_id
  tags                  = local.tags
}

module "evidence" {
  source = "./modules/evidence"

  prefix                = local.name
  suffix                = local.suffix
  resource_group_name   = azurerm_resource_group.main.name
  location              = var.location
  retention_days        = var.evidence_retention_days
  platform_principal_id = module.identity.principal_id
  operator_object_id    = data.azurerm_client_config.current.object_id
  tags                  = local.tags
}

module "database" {
  source = "./modules/database"

  prefix              = local.name
  suffix              = local.suffix
  resource_group_name = azurerm_resource_group.main.name
  location            = var.location
  sku_name            = var.postgres_sku
  storage_mb          = var.postgres_storage_mb
  operator_ip         = var.operator_ip
  admin_object_id     = data.azurerm_client_config.current.object_id
  tenant_id           = data.azurerm_client_config.current.tenant_id
  platform_identity   = module.identity.identity
  tags                = local.tags
}

module "openai" {
  source = "./modules/openai"
  count  = var.enable_openai ? 1 : 0

  prefix                = local.name
  suffix                = local.suffix
  resource_group_name   = azurerm_resource_group.main.name
  location              = var.location
  model                 = var.openai_model
  model_version         = var.openai_model_version
  capacity              = var.openai_capacity
  platform_principal_id = module.identity.principal_id
  tags                  = local.tags
}

module "compute" {
  source = "./modules/compute"

  prefix              = local.name
  suffix              = local.suffix
  resource_group_name = azurerm_resource_group.main.name
  location            = var.location
  image_tag           = var.image_tag
  scan_cron           = var.scan_cron

  identity_id           = module.identity.identity_id
  identity_client       = module.identity.client_id
  consumer_identity_ids = module.identity.consumer_identity_ids

  workspace_resource_id  = module.observability.workspace_resource_id
  workspace_customer_id  = module.observability.workspace_customer_id
  dce_endpoint           = module.observability.dce_endpoint
  dcr_immutable_id       = module.observability.dcr_immutable_id
  enable_sentinel_export = var.enable_sentinel_export

  postgres_fqdn     = module.database.fqdn
  postgres_database = module.database.database_name
  postgres_user     = module.database.admin_login

  evidence_account   = module.evidence.account_name
  evidence_container = module.evidence.container_name

  key_vault_name      = module.key_vault.vault_name
  app_config_endpoint = module.app_configuration.endpoint

  openai_endpoint   = var.enable_openai ? module.openai[0].endpoint : ""
  openai_deployment = var.enable_openai ? module.openai[0].deployment_name : ""

  subscription_id = var.subscription_id
  lookback_days   = var.lookback_days
  max_runbooks    = var.max_runbooks
  graph_enabled   = var.grant_graph_permissions

  tags = local.tags
}
