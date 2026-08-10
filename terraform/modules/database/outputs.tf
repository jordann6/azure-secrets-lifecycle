output "fqdn" {
  value = azurerm_postgresql_flexible_server.main.fqdn
}

output "server_name" {
  value = azurerm_postgresql_flexible_server.main.name
}

output "database_name" {
  value = azurerm_postgresql_flexible_server_database.main.name
}

# The Entra principal name the application connects as. There is no
# password output because there is no password: authentication is a token
# minted per connection from the managed identity.
output "admin_login" {
  value = var.platform_identity.name
}

output "admin_password" {
  description = "Always empty. Present so the compute module has one shape to consume."
  value       = ""
  sensitive   = true
}
