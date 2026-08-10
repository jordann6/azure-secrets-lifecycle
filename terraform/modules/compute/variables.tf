variable "prefix" {
  type = string
}

variable "suffix" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "location" {
  type = string
}

variable "image_tag" {
  type = string
}

variable "scan_cron" {
  type = string
}

variable "identity_id" {
  type = string
}

variable "identity_client" {
  type = string
}

variable "consumer_identity_ids" {
  type = map(string)
}

variable "workspace_resource_id" {
  type = string
}

variable "workspace_customer_id" {
  type = string
}

variable "dce_endpoint" {
  type    = string
  default = ""
}

variable "dcr_immutable_id" {
  type    = string
  default = ""
}

variable "enable_sentinel_export" {
  type = bool
}

variable "postgres_fqdn" {
  type = string
}

variable "postgres_database" {
  type = string
}

variable "postgres_user" {
  type = string
}

variable "evidence_account" {
  type = string
}

variable "evidence_container" {
  type = string
}

variable "key_vault_name" {
  type = string
}

variable "app_config_endpoint" {
  type = string
}

variable "openai_endpoint" {
  type    = string
  default = ""
}

variable "openai_deployment" {
  type    = string
  default = ""
}

variable "subscription_id" {
  type = string
}

variable "lookback_days" {
  type = number
}

variable "max_runbooks" {
  type = number
}

variable "graph_enabled" {
  type = bool
}

variable "tags" {
  type = map(string)
}
