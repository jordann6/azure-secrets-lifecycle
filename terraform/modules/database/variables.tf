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

variable "sku_name" {
  type = string
}

variable "storage_mb" {
  type = number
}

variable "operator_ip" {
  type    = string
  default = ""
}

variable "admin_object_id" {
  description = "Operator object id, added as an Entra administrator."
  type        = string
}

variable "tenant_id" {
  type = string
}

variable "platform_identity" {
  description = "The platform user assigned identity object."
  type = object({
    name         = string
    principal_id = string
    client_id    = string
  })
}

variable "tags" {
  type = map(string)
}
