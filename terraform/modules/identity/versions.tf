terraform {
  required_version = ">= 1.10"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.14"
    }
    # Microsoft Graph app role assignments are an Entra concern, not an
    # ARM one, so they come from the azuread provider.
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0"
    }
  }
}
