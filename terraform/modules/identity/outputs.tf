output "identity" {
  description = "The platform user assigned identity."
  value       = azurerm_user_assigned_identity.platform
}

output "identity_id" {
  value = azurerm_user_assigned_identity.platform.id
}

output "principal_id" {
  value = azurerm_user_assigned_identity.platform.principal_id
}

output "client_id" {
  value = azurerm_user_assigned_identity.platform.client_id
}

output "consumer_identity_ids" {
  description = "Consumer identity resource ids, keyed by consumer name."
  value       = { for k, v in azurerm_user_assigned_identity.consumer : k => v.id }
}

output "consumer_client_ids" {
  value = { for k, v in azurerm_user_assigned_identity.consumer : k => v.client_id }
}

output "consumer_principal_ids" {
  value = { for k, v in azurerm_user_assigned_identity.consumer : k => v.principal_id }
}
