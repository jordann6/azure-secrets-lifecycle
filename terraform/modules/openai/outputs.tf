output "endpoint" {
  value = azurerm_cognitive_account.openai.endpoint
}

output "deployment_name" {
  value = azurerm_cognitive_deployment.runbooks.name
}

output "account_id" {
  value = azurerm_cognitive_account.openai.id
}
