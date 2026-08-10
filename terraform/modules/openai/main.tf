# Azure OpenAI for runbook synthesis, the Bedrock analogue.
#
# No API key is created and local authentication is disabled outright, so
# the only way to call this account is an Entra token from a principal
# holding Cognitive Services OpenAI User. The platform identity has that
# role and nothing else here.
#
# If the subscription has no model quota, set enable_openai = false. The
# analyzer detects the missing endpoint and produces rule based runbooks
# instead, labelled generator=fallback everywhere they surface.

resource "azurerm_cognitive_account" "openai" {
  # Public network access, customer managed keys, and data loss prevention
  # all need either a private endpoint or a Key Vault CMK plus the network
  # isolation to go with it. Both cost more per month than everything else
  # in this deployment combined, and neither changes the security property
  # this project is actually demonstrating: the account has no API key at
  # all (local_auth_enabled = false), so the only way in is an Entra token
  # from a principal holding Cognitive Services OpenAI User.
  #checkov:skip=CKV_AZURE_134:Public access is deliberate; local auth is disabled so Entra is the only path. Private endpoint needs VNet + NAT, out of budget for a demo.
  #checkov:skip=CKV2_AZURE_22:CMK needs a second Key Vault and rotation story for a resource holding no persisted data.
  #checkov:skip=CKV_AZURE_247:DLP allowlisting is a data-exfiltration control for prompts carrying regulated data; this sends redacted secret metadata only.
  name                = "${var.prefix}-openai-${var.suffix}"
  resource_group_name = var.resource_group_name
  location            = var.location
  kind                = "OpenAI"
  sku_name            = "S0"

  # Not used to authenticate anything today: the platform calls in with
  # its own user assigned identity. Present because an account with no
  # identity cannot later be granted access to a CMK or a private storage
  # account without being recreated, and it costs nothing to carry.
  identity {
    type = "SystemAssigned"
  }

  custom_subdomain_name = "${var.prefix}-openai-${var.suffix}"

  # Kills key based auth. This is the Azure OpenAI equivalent of turning
  # off shared key access on a storage account.
  local_auth_enabled            = false
  public_network_access_enabled = true

  tags = var.tags
}

resource "azurerm_cognitive_deployment" "runbooks" {
  name                 = var.model
  cognitive_account_id = azurerm_cognitive_account.openai.id

  model {
    format  = "OpenAI"
    name    = var.model
    version = var.model_version
  }

  sku {
    # Pay per token with no reserved throughput. Runbook synthesis is a
    # handful of calls a day, bounded by MAX_RUNBOOKS.
    name     = "GlobalStandard"
    capacity = var.capacity
  }
}

resource "azurerm_role_assignment" "platform_openai_user" {
  scope                = azurerm_cognitive_account.openai.id
  role_definition_name = "Cognitive Services OpenAI User"
  principal_id         = var.platform_principal_id
}
