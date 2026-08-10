variable "prefix" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "location" {
  type = string
}

variable "subscription_id" {
  type = string
}

variable "grant_graph" {
  description = "Assign Microsoft Graph app roles to the platform identity."
  type        = bool
  default     = true
}

variable "tags" {
  type = map(string)
}
