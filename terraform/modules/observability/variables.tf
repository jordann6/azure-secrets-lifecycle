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
  type = number
}

variable "enable_findings_table" {
  description = "Create the custom findings table and its ingestion path."
  type        = bool
  default     = true
}

variable "tags" {
  type = map(string)
}
