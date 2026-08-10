variable "subscription_id" {
  description = "Target Azure subscription id."
  type        = string
}

variable "location" {
  description = "Azure region. Azure OpenAI and Container Apps must both be available here."
  type        = string
  default     = "eastus2"
}

variable "prefix" {
  description = "Name prefix for every resource in the deployment."
  type        = string
  default     = "secops"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,12}$", var.prefix))
    error_message = "prefix must be 3 to 13 lowercase alphanumeric or hyphen characters starting with a letter."
  }
}

variable "environment" {
  description = "Environment tag value."
  type        = string
  default     = "demo"
}

variable "owner" {
  description = "Owner tag value. Findings inherit it when a resource carries no owner tag of its own."
  type        = string
  default     = "platform-team"
}

variable "operator_ip" {
  description = <<-EOT
    Public IP allowed to reach Postgres and the Key Vault data plane, in CIDR
    form. Needed to run migrations and the seed from a workstation. Leave empty
    to skip the rule, which means seeding has to run from inside Azure.
  EOT
  type        = string
  default     = ""
}

variable "lookback_days" {
  description = "Audit log lookback window for the consumer map."
  type        = number
  default     = 90

  validation {
    condition     = var.lookback_days >= 1 && var.lookback_days <= 365
    error_message = "lookback_days must be between 1 and 365."
  }
}

variable "log_retention_days" {
  description = "Log Analytics workspace retention. Drives the largest recurring line item after Postgres."
  type        = number
  default     = 30
}

variable "evidence_retention_days" {
  description = "Immutability window on evidence blobs, in days."
  type        = number
  default     = 7
}

variable "max_runbooks" {
  description = "Model synthesized runbooks per scan. Bounds the Azure OpenAI spend."
  type        = number
  default     = 5
}

variable "scan_cron" {
  description = "Cron schedule for the scan job, in UTC."
  type        = string
  default     = "0 6 * * *"
}

variable "enable_openai" {
  description = <<-EOT
    Deploy Azure OpenAI for runbook synthesis. Set false in a subscription
    without model quota; the analyzer falls back to rule based runbooks and
    every other part of the pipeline is unaffected.
  EOT
  type        = bool
  default     = true
}

variable "openai_model" {
  description = "Azure OpenAI model to deploy for runbook synthesis."
  type        = string
  default     = "gpt-4o-mini"
}

variable "openai_model_version" {
  description = "Model version for the deployment."
  type        = string
  default     = "2024-07-18"
}

variable "openai_capacity" {
  description = "Deployment capacity in thousands of tokens per minute."
  type        = number
  default     = 10
}

variable "grant_graph_permissions" {
  description = <<-EOT
    Grant the platform identity Application.Read.All and Directory.Read.All on
    Microsoft Graph, which the Entra credential sweep and consumer name
    resolution need. Requires the operator to hold Privileged Role
    Administrator or Global Administrator. Set false to deploy without it: the
    Entra sweep is skipped and consumers stay unresolved GUIDs.
  EOT
  type        = bool
  default     = true
}

variable "enable_sentinel_export" {
  description = "Ship findings into a custom Log Analytics table for Microsoft Sentinel."
  type        = bool
  default     = true
}

variable "postgres_sku" {
  description = "Postgres Flexible Server SKU. B_Standard_B1ms is the cheapest that runs this workload."
  type        = string
  default     = "B_Standard_B1ms"
}

variable "postgres_storage_mb" {
  description = "Postgres storage in MB. 32768 is the floor."
  type        = number
  default     = 32768
}

variable "image_tag" {
  description = "Container image tag to run."
  type        = string
  default     = "latest"
}
