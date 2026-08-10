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
  # LRS, public endpoint, and platform managed keys are all cost and
  # complexity decisions for a demo estate, not oversights. The controls
  # that carry the compliance claim here are immutability, versioning,
  # Entra only auth with no shared key, and the read logging below.
  #checkov:skip=CKV_AZURE_206:LRS is deliberate; GRS doubles storage cost for evidence that is reproducible by re-running a scan.
  #checkov:skip=CKV_AZURE_59:Public network access is required because Container Apps consumption egress has no stable IP to allow-list. Anonymous access is off and shared keys are disabled.
  #checkov:skip=CKV2_AZURE_33:Private endpoint needs VNet integration plus a NAT gateway, which costs more than the rest of the deployment.
  #checkov:skip=CKV2_AZURE_1:CMK needs a second vault and a key rotation story; evidence integrity here comes from the immutability policy, not from key custody.
  #checkov:skip=CKV_AZURE_33:Queue logging is not applicable; this account serves blob only and has no queue service in use.
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
  # This control is implemented, not waived: StorageRead, StorageWrite and
  # StorageDelete all flow to the workspace via the diagnostic setting
  # below. Checkov's graph check looks for the legacy `log` block on a
  # setting attached to the account and does not follow `enabled_log` on
  # one scoped to /blobServices/default, so it reports a false negative.
  #checkov:skip=CKV2_AZURE_21:Implemented by azurerm_monitor_diagnostic_setting.blob in this file; the graph check does not follow enabled_log on a blobServices-scoped setting.
  name                  = "evidence"
  storage_account_id    = azurerm_storage_account.evidence.id
  container_access_type = "private"
}

# Who read the evidence, and when. An immutable artifact proves the
# findings were not altered after the fact; it says nothing about who
# looked at them. For a container whose whole purpose is to satisfy an
# auditor, the access trail is part of the product rather than an extra.
resource "azurerm_monitor_diagnostic_setting" "blob" {
  name               = "${var.prefix}-evidence-access"
  target_resource_id = "${azurerm_storage_account.evidence.id}/blobServices/default"

  log_analytics_workspace_id = var.workspace_id

  enabled_log {
    category = "StorageRead"
  }

  enabled_log {
    category = "StorageWrite"
  }

  enabled_log {
    category = "StorageDelete"
  }

  # Transaction metrics are deliberately not collected: this setting
  # exists for the access trail, and metric ingestion is the line item
  # that would actually cost something here.
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
