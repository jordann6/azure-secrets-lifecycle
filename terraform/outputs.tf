output "dashboard_url" {
  description = "Public URL of the Rails dashboard."
  value       = module.compute.dashboard_url
}

output "resource_group" {
  value = azurerm_resource_group.main.name
}

output "registry_login_server" {
  value = module.compute.registry_login_server
}

output "registry_name" {
  value = module.compute.registry_name
}

output "key_vault_name" {
  value = module.key_vault.vault_name
}

output "app_config_name" {
  value = module.app_configuration.name
}

output "app_config_endpoint" {
  value = module.app_configuration.endpoint
}

output "evidence_storage_account" {
  value = module.evidence.account_name
}

output "evidence_container" {
  value = module.evidence.container_name
}

output "log_analytics_workspace_id" {
  description = "Workspace GUID used by the Log Analytics query API."
  value       = module.observability.workspace_customer_id
}

output "log_analytics_workspace_name" {
  value = module.observability.workspace_name
}

output "postgres_fqdn" {
  value = module.database.fqdn
}

output "postgres_server_name" {
  value = module.database.server_name
}

output "scan_job_name" {
  value = module.compute.scan_job_name
}

output "migrate_job_name" {
  value = module.compute.migrate_job_name
}

output "consumer_app_job_name" {
  value = module.compute.consumer_job_names["app"]
}

output "consumer_batch_job_name" {
  value = module.compute.consumer_job_names["batch"]
}

output "openai_endpoint" {
  value = var.enable_openai ? module.openai[0].endpoint : ""
}

# Sourced by `make env` so the seed and local rake tasks talk to the
# deployment that terraform just created.
output "shell_env" {
  description = "Shell exports for the operator tasks."
  value       = <<-EOT
    export AZURE_SUBSCRIPTION_ID=${var.subscription_id}
    export AZURE_RESOURCE_GROUP=${azurerm_resource_group.main.name}
    export KEY_VAULT_NAME=${module.key_vault.vault_name}
    export APP_CONFIG_NAME=${module.app_configuration.name}
    export APP_CONFIG_ENDPOINT=${module.app_configuration.endpoint}
    export EVIDENCE_STORAGE_ACCOUNT=${module.evidence.account_name}
    export EVIDENCE_CONTAINER=${module.evidence.container_name}
    export LOG_ANALYTICS_WORKSPACE_ID=${module.observability.workspace_customer_id}
  EOT
}
