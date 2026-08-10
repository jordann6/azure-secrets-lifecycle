terraform {
  required_version = ">= 1.10"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.14"
    }
    azapi = {
      source  = "Azure/azapi"
      version = "~> 2.2"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "azurerm" {
  subscription_id = var.subscription_id

  # The evidence account has shared key access disabled, and without this
  # the provider still reaches for a key to poll the blob data plane and
  # fails the create with KeyBasedAuthenticationNotPermitted. Entra auth
  # for the data plane is what the application uses too.
  storage_use_azuread = true

  features {
    key_vault {
      # Purge protection is on for the demo vault, so a destroy leaves
      # soft deleted objects behind rather than failing. Recovering them
      # on the next apply is the correct behaviour for a vault; silently
      # purging them would not be.
      purge_soft_delete_on_destroy    = false
      recover_soft_deleted_key_vaults = true
    }
    resource_group {
      # Guards against a destroy that leaves orphans behind and bills
      # forever because something outside state landed in the group.
      prevent_deletion_if_contains_resources = false
    }
  }
}

provider "azapi" {}

provider "azuread" {}
