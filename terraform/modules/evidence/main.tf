# Evidence storage: versioned, immutable, write only from the platform
# identity, TLS enforced.
#
# This is the Azure equivalent of an S3 bucket with versioning and Object
# Lock in governance mode. The differences are worth knowing:
#
#   - Azure immutability is a container property, not a per object one.
#   - A time based retention policy blocks overwrite and delete for the
#     window. New blobs still write fine, which is all this platform does.
#   - The policy is created UNLOCKED. A locked policy cannot be shortened
#     or removed by anyone, including the subscription owner, and the
#     storage account cannot be deleted until every blob's window expires.
#     That is correct for a real compliance programme and fatal for a
#     project whose whole point is deploy, demo, and destroy in an
#     afternoon. Locking it is a one line change and a deliberate decision,
#     not a default.

resource "azurerm_storage_account" "evidence" {
  name                = "${var.prefix}ev${var.suffix}"
  resource_group_name = var.resource_group_name
  location            = var.location

  account_tier             = "Standard"
  account_replication_type = "LRS"
  account_kind             = "StorageV2"

  https_traffic_only_enabled      = true
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  # Entra only. A shared key is a static credential, which is precisely
  # what this project exists to complain about.
  shared_access_key_enabled = false

  blob_properties {
    versioning_enabled = true

    delete_retention_policy {
      days = var.retention_days
    }

    container_delete_retention_policy {
      days = var.retention_days
    }
  }

  tags = var.tags
}

resource "azurerm_storage_container" "evidence" {
  name                  = "evidence"
  storage_account_id    = azurerm_storage_account.evidence.id
  container_access_type = "private"
}

resource "azurerm_storage_container_immutability_policy" "evidence" {
  storage_container_resource_manager_id = azurerm_storage_container.evidence.id
  immutability_period_in_days           = var.retention_days

  # See the module header. Unlocked so `make destroy` can complete.
  locked = false

  # Lets the writer append to an existing evidence artifact within the
  # window without being able to overwrite what is already there.
  protected_append_writes_all_enabled = true
}

# Write only. The platform can put an evidence artifact and cannot delete
# one, which is the same shape as the S3 bucket policy in the AWS version.
resource "azurerm_role_assignment" "platform_writer" {
  scope                = azurerm_storage_account.evidence.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = var.platform_principal_id
}

# The operator needs delete rights for `make destroy` to purge the
# container before terraform removes it.
resource "azurerm_role_assignment" "operator_owner" {
  scope                = azurerm_storage_account.evidence.id
  role_definition_name = "Storage Blob Data Owner"
  principal_id         = var.operator_object_id
}
