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

variable "model" {
  type = string
}

variable "model_version" {
  type = string
}

variable "capacity" {
  type = number
}

variable "platform_principal_id" {
  type = string
}

variable "tags" {
  type = map(string)
}
