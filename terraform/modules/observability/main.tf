# Log Analytics workspace, the custom findings table, and the ingestion
# path into it.
#
# The workspace does double duty: it receives Key Vault and App
# Configuration audit events (the consumer map's only source of truth) and
# it holds the custom table Sentinel reads findings from. On AWS the same
# two jobs took CloudTrail plus an S3 bucket plus a Glue table plus an
# Athena workgroup for the first, and Security Hub for the second.

resource "azurerm_log_analytics_workspace" "main" {
  name                = "${var.prefix}-logs-${var.suffix}"
  resource_group_name = var.resource_group_name
  location            = var.location
  sku                 = "PerGB2018"
  retention_in_days   = var.retention_days

  # Ingestion is the cost driver here, not storage. A demo estate produces
  # a few MB a day, but a cap turns a misconfigured diagnostic setting from
  # a surprise invoice into a dropped log line.
  daily_quota_gb = 1

  tags = var.tags
}

# Custom table for findings. There is no first class azurerm resource for
# a custom table schema, so this goes through azapi. The schema is the
# contract between the analyzer's Sentinel exporter and every hunting
# query written against it, which is why it lives in code rather than
# being inferred from the first row that arrives.
resource "azapi_resource" "findings_table" {
  count = var.enable_findings_table ? 1 : 0

  type      = "Microsoft.OperationalInsights/workspaces/tables@2022-10-01"
  name      = "SecOpsFindings_CL"
  parent_id = azurerm_log_analytics_workspace.main.id

  body = {
    properties = {
      schema = {
        name = "SecOpsFindings_CL"
        columns = [
          { name = "TimeGenerated", type = "datetime" },
          { name = "ScanId", type = "string" },
          { name = "FindingId", type = "string" },
          { name = "FindingType", type = "string" },
          { name = "Title", type = "string" },
          { name = "Severity", type = "string" },
          { name = "ControlIds", type = "dynamic" },
          { name = "ResourceId", type = "string" },
          { name = "SubscriptionId", type = "string" },
          { name = "OwnerTag", type = "string" },
          { name = "ReadinessScore", type = "int" },
          { name = "RemediationStatus", type = "string" }
        ]
      }
      retentionInDays      = var.retention_days
      totalRetentionInDays = var.retention_days
    }
  }
}

resource "azurerm_monitor_data_collection_endpoint" "main" {
  count = var.enable_findings_table ? 1 : 0

  name                = "${var.prefix}-dce-${var.suffix}"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags
}

resource "azurerm_monitor_data_collection_rule" "findings" {
  count = var.enable_findings_table ? 1 : 0

  name                        = "${var.prefix}-dcr-findings"
  resource_group_name         = var.resource_group_name
  location                    = var.location
  data_collection_endpoint_id = azurerm_monitor_data_collection_endpoint.main[0].id
  tags                        = var.tags

  destinations {
    log_analytics {
      workspace_resource_id = azurerm_log_analytics_workspace.main.id
      name                  = "findings-workspace"
    }
  }

  data_flow {
    streams       = ["Custom-SecOpsFindings_CL"]
    destinations  = ["findings-workspace"]
    output_stream = "Custom-SecOpsFindings_CL"
    # Identity transform. The application already emits the table's shape,
    # so reshaping here would only add a second place for the schema to
    # drift out of sync.
    transform_kql = "source"
  }

  stream_declaration {
    stream_name = "Custom-SecOpsFindings_CL"

    column {
      name = "TimeGenerated"
      type = "datetime"
    }
    column {
      name = "ScanId"
      type = "string"
    }
    column {
      name = "FindingId"
      type = "string"
    }
    column {
      name = "FindingType"
      type = "string"
    }
    column {
      name = "Title"
      type = "string"
    }
    column {
      name = "Severity"
      type = "string"
    }
    column {
      name = "ControlIds"
      type = "dynamic"
    }
    column {
      name = "ResourceId"
      type = "string"
    }
    column {
      name = "SubscriptionId"
      type = "string"
    }
    column {
      name = "OwnerTag"
      type = "string"
    }
    column {
      name = "ReadinessScore"
      type = "int"
    }
    column {
      name = "RemediationStatus"
      type = "string"
    }
  }

  depends_on = [azapi_resource.findings_table]
}

# Without this the analyzer's Logs Ingestion POST returns 403. The
# Logs Ingestion API authorizes against the data collection rule, not the
# workspace, and Log Analytics Reader on the subscription does not carry
# the ingestion action. Monitoring Metrics Publisher is the role that
# does, despite the name reading like it is metrics only.
resource "azurerm_role_assignment" "findings_publisher" {
  count = var.enable_findings_table ? 1 : 0

  scope                = azurerm_monitor_data_collection_rule.findings[0].id
  role_definition_name = "Monitoring Metrics Publisher"
  principal_id         = var.platform_principal_id
}
