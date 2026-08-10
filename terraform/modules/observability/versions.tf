terraform {
  required_version = ">= 1.10"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.14"
    }
    # Log Analytics custom table schemas have no first class azurerm
    # resource, so the findings table is declared through the ARM API.
    azapi = {
      source  = "Azure/azapi"
      version = "~> 2.2"
    }
  }
}
