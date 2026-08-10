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

variable "retention_days" {
  description = "Immutability and soft delete window in days."
  type        = number
}

variable "platform_principal_id" {
  type = string
}

variable "operator_object_id" {
  type = string
}

variable "tags" {
  type = map(string)
}

variable "workspace_id" {
  description = "Log Analytics workspace for evidence container access logging."
  type        = string
}
