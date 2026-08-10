output "workspace_resource_id" {
  value = azurerm_log_analytics_workspace.main.id
}

# The GUID the Log Analytics query API addresses a workspace by. Distinct
# from the ARM resource id, and the one the application needs.
output "workspace_customer_id" {
  value = azurerm_log_analytics_workspace.main.workspace_id
}

output "workspace_name" {
  value = azurerm_log_analytics_workspace.main.name
}

output "dce_endpoint" {
  value = try(azurerm_monitor_data_collection_endpoint.main[0].logs_ingestion_endpoint, "")
}

output "dcr_immutable_id" {
  value = try(azurerm_monitor_data_collection_rule.findings[0].immutable_id, "")
}

output "dcr_id" {
  value = try(azurerm_monitor_data_collection_rule.findings[0].id, "")
}
