output "account_name" {
  value = azurerm_storage_account.evidence.name
}

output "container_name" {
  value = azurerm_storage_container.evidence.name
}

output "account_id" {
  value = azurerm_storage_account.evidence.id
}
