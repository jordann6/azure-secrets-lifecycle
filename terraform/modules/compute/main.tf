# Container Registry, Container Apps environment, the dashboard app, and
# the jobs that drive the pipeline.
#
# One image, four roles. The web app serves the dashboard; the scan job
# runs the pipeline on a schedule; the migrate job prepares the schema;
# the two consumer jobs read secrets so the audit log has real access
# patterns to build a consumer map from.
#
# Everything except Postgres scales to zero. A day with no traffic and one
# scheduled scan costs cents.

resource "azurerm_container_registry" "main" {
  name                = "${var.prefix}acr${var.suffix}"
  resource_group_name = var.resource_group_name
  location            = var.location
  sku                 = "Basic"

  # The admin account is a static username and password pair. Pulls
  # authenticate with the managed identity instead.
  admin_enabled = false

  tags = var.tags
}

resource "azurerm_role_assignment" "acr_pull" {
  scope                = azurerm_container_registry.main.id
  role_definition_name = "AcrPull"
  principal_id         = data.azurerm_user_assigned_identity.platform.principal_id
}

data "azurerm_user_assigned_identity" "platform" {
  name                = reverse(split("/", var.identity_id))[0]
  resource_group_name = var.resource_group_name
}

resource "azurerm_container_app_environment" "main" {
  name                       = "${var.prefix}-env"
  resource_group_name        = var.resource_group_name
  location                   = var.location
  log_analytics_workspace_id = var.workspace_resource_id
  tags                       = var.tags
}

# Rails will not boot without this. It is the one stored secret in the
# deployment, and it is inert here: sessions and cookies are disabled, the
# dashboard is read only, and nothing is signed or encrypted with it. It
# lives as a Container Apps secret rather than in Key Vault so that
# fetching it does not require giving the platform identity the data plane
# read permission the rest of this project spends its effort avoiding.
resource "random_password" "secret_key_base" {
  length  = 64
  special = false
}

locals {
  image = "${azurerm_container_registry.main.login_server}/secops:${var.image_tag}"

  # Shared by the web app and every job, so the dashboard renders from the
  # same configuration the pipeline ran under.
  env = {
    RAILS_ENV                  = "production"
    RAILS_LOG_TO_STDOUT        = "1"
    PGAUTH                     = "entra"
    PGHOST                     = var.postgres_fqdn
    PGUSER                     = var.postgres_user
    PGDATABASE                 = var.postgres_database
    PGSSLMODE                  = "require"
    AZURE_CLIENT_ID            = var.identity_client
    AZURE_SUBSCRIPTION_ID      = var.subscription_id
    AZURE_RESOURCE_GROUP       = var.resource_group_name
    LOG_ANALYTICS_WORKSPACE_ID = var.workspace_customer_id
    LOOKBACK_DAYS              = tostring(var.lookback_days)
    MAX_RUNBOOKS               = tostring(var.max_runbooks)
    GRAPH_ENABLED              = tostring(var.graph_enabled)
    EVIDENCE_STORAGE_ACCOUNT   = var.evidence_account
    EVIDENCE_CONTAINER         = var.evidence_container
    APP_CONFIG_ENDPOINT        = var.app_config_endpoint
    KEY_VAULT_NAME             = var.key_vault_name
    AZURE_OPENAI_ENDPOINT      = var.openai_endpoint
    AZURE_OPENAI_DEPLOYMENT    = var.openai_deployment
    SENTINEL_ENABLED           = tostring(var.enable_sentinel_export)
    DCE_ENDPOINT               = var.dce_endpoint
    DCR_IMMUTABLE_ID           = var.dcr_immutable_id
  }
}

resource "azurerm_container_app" "web" {
  name                         = "${var.prefix}-dashboard"
  resource_group_name          = var.resource_group_name
  container_app_environment_id = azurerm_container_app_environment.main.id
  revision_mode                = "Single"
  tags                         = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [var.identity_id]
  }

  registry {
    server   = azurerm_container_registry.main.login_server
    identity = var.identity_id
  }

  secret {
    name  = "secret-key-base"
    value = random_password.secret_key_base.result
  }

  ingress {
    external_enabled = true
    target_port      = 3000
    transport        = "auto"

    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }

  template {
    # Scale to zero. A dashboard nobody is looking at should not bill, and
    # a cold start on a page that is read a few times a day is a fair
    # trade for that.
    min_replicas = 0
    max_replicas = 1

    container {
      name   = "dashboard"
      image  = local.image
      cpu    = 0.5
      memory = "1Gi"

      dynamic "env" {
        for_each = local.env
        content {
          name  = env.key
          value = env.value
        }
      }

      env {
        name        = "SECRET_KEY_BASE"
        secret_name = "secret-key-base"
      }

      liveness_probe {
        transport = "HTTP"
        path      = "/healthz"
        port      = 3000
      }

      readiness_probe {
        transport = "HTTP"
        path      = "/healthz"
        port      = 3000
      }
    }
  }

  depends_on = [azurerm_role_assignment.acr_pull]
}

# Schema management. Kept as its own manual job rather than folded into
# the web container's start command, so that a scaled-to-zero dashboard
# waking up cannot run a migration on a cold start.
resource "azurerm_container_app_job" "migrate" {
  name                         = "${var.prefix}-migrate"
  resource_group_name          = var.resource_group_name
  location                     = var.location
  container_app_environment_id = azurerm_container_app_environment.main.id
  replica_timeout_in_seconds   = 600
  replica_retry_limit          = 1
  tags                         = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [var.identity_id]
  }

  registry {
    server   = azurerm_container_registry.main.login_server
    identity = var.identity_id
  }

  secret {
    name  = "secret-key-base"
    value = random_password.secret_key_base.result
  }

  manual_trigger_config {
    parallelism              = 1
    replica_completion_count = 1
  }

  template {
    container {
      name    = "migrate"
      image   = local.image
      cpu     = 0.5
      memory  = "1Gi"
      command = ["bundle", "exec", "rails", "db:prepare"]

      dynamic "env" {
        for_each = local.env
        content {
          name  = env.key
          value = env.value
        }
      }

      env {
        name        = "SECRET_KEY_BASE"
        secret_name = "secret-key-base"
      }
    }
  }

  depends_on = [azurerm_role_assignment.acr_pull]
}

# The pipeline. EventBridge in the AWS version; a cron trigger here.
resource "azurerm_container_app_job" "scan" {
  name                         = "${var.prefix}-scan"
  resource_group_name          = var.resource_group_name
  location                     = var.location
  container_app_environment_id = azurerm_container_app_environment.main.id
  # A full sweep of a demo estate takes seconds. The ceiling is here for
  # a tenant with hundreds of vaults, where Graph throttling dominates.
  replica_timeout_in_seconds = 1800
  replica_retry_limit        = 1
  tags                       = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [var.identity_id]
  }

  registry {
    server   = azurerm_container_registry.main.login_server
    identity = var.identity_id
  }

  secret {
    name  = "secret-key-base"
    value = random_password.secret_key_base.result
  }

  schedule_trigger_config {
    cron_expression          = var.scan_cron
    parallelism              = 1
    replica_completion_count = 1
  }

  template {
    container {
      name    = "scan"
      image   = local.image
      cpu     = 1.0
      memory  = "2Gi"
      command = ["rake", "secops:scan"]

      dynamic "env" {
        for_each = local.env
        content {
          name  = env.key
          value = env.value
        }
      }

      env {
        name        = "SECRET_KEY_BASE"
        secret_name = "secret-key-base"
      }
    }
  }

  depends_on = [azurerm_role_assignment.acr_pull]
}

# Stand-in workloads. Each runs as its own user assigned identity holding
# Key Vault Secrets User, reads the secrets it owns, and leaves an audit
# trail with a distinct caller object id. That is what turns the consumer
# map from a schema into a demo.
resource "azurerm_container_app_job" "consumer" {
  for_each = local.consumers

  name                         = "${var.prefix}-test-consumer-${each.key}"
  resource_group_name          = var.resource_group_name
  location                     = var.location
  container_app_environment_id = azurerm_container_app_environment.main.id
  replica_timeout_in_seconds   = 300
  replica_retry_limit          = 0
  tags                         = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [var.consumer_identity_ids[each.key]]
  }

  manual_trigger_config {
    parallelism              = 1
    replica_completion_count = 1
  }

  template {
    container {
      name   = "consumer"
      image  = "mcr.microsoft.com/azure-cli:2.67.0"
      cpu    = 0.25
      memory = "0.5Gi"

      command = ["/bin/bash", "-c"]
      args = [
        join(" && ", concat(
          ["az login --identity --client-id $AZ_CLIENT_ID --output none"],
          [for name in each.value.secrets :
            "for i in 1 2 3; do az keyvault secret show --vault-name $KEY_VAULT_NAME --name ${name} --query id --output tsv; done"
          ],
          ["echo consumer ${each.key} finished"]
        ))
      ]

      env {
        name  = "AZ_CLIENT_ID"
        value = data.azurerm_user_assigned_identity.consumer[each.key].client_id
      }

      env {
        name  = "KEY_VAULT_NAME"
        value = var.key_vault_name
      }
    }
  }
}

data "azurerm_user_assigned_identity" "consumer" {
  for_each = var.consumer_identity_ids

  name                = reverse(split("/", each.value))[0]
  resource_group_name = var.resource_group_name
}

locals {
  # Mirrors the consumer column in Seed::Estate. Keeping the two in step
  # is what makes the seeded estate produce a consumer map that matches
  # the story the dashboard tells.
  consumers = {
    app = {
      secrets = [
        "secops-test-db-primary",
        "secops-test-app-jwt-signing",
        "secops-test-redis-auth",
        "secops-test-webhook-hmac"
      ]
    }
    batch = {
      secrets = [
        "secops-test-db-replica"
      ]
    }
  }
}
