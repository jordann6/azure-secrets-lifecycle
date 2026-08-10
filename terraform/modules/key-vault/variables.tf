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

variable "tenant_id" {
  type = string
}

variable "operator_object_id" {
  type = string
}

variable "operator_ip" {
  description = "Operator CIDR allowed through the vault firewall. Empty means no firewall."
  type        = string
  default     = ""
}

variable "platform_principal_id" {
  type = string
}

variable "consumer_principal_ids" {
  type = map(string)
}

variable "workspace_id" {
  type = string
}

variable "tags" {
  type = map(string)
}
