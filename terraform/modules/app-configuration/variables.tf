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

variable "operator_object_id" {
  type = string
}

variable "platform_principal_id" {
  type = string
}

variable "workspace_id" {
  type = string
}

variable "tags" {
  type = map(string)
}
