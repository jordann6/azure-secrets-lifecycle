output "dashboard_url" {
  value = "https://${azurerm_container_app.web.ingress[0].fqdn}"
}

output "registry_login_server" {
  value = azurerm_container_registry.main.login_server
}

output "registry_name" {
  value = azurerm_container_registry.main.name
}

output "image" {
  value = local.image
}

output "scan_job_name" {
  value = azurerm_container_app_job.scan.name
}

output "migrate_job_name" {
  value = azurerm_container_app_job.migrate.name
}

output "verify_job_name" {
  value = azurerm_container_app_job.verify.name
}

output "consumer_job_names" {
  value = { for k, v in azurerm_container_app_job.consumer : k => v.name }
}
