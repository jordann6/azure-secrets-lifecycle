terraform {
  # Remote state in Azure Storage. Bootstrap the account and container out
  # of band, then `terraform init -backend-config=backend.hcl`.
  #
  # State is left local by default so the project clones and plans without
  # a pre-existing storage account. Uncomment for anything shared.
  #
  # backend "azurerm" {
  #   resource_group_name  = "tfstate-rg"
  #   storage_account_name = "tfstateXXXXXX"
  #   container_name       = "tfstate"
  #   key                  = "azure-secrets-lifecycle.tfstate"
  #   use_azuread_auth     = true
  # }
}
