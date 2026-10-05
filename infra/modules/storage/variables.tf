variable "name" {
  description = "Name prefix for buckets. The AWS account ID is appended for global uniqueness."
  type        = string
}

variable "force_destroy" {
  description = "Allow terraform destroy to delete non-empty buckets. Keep false outside short-lived environments."
  type        = bool
  default     = false
}

variable "noncurrent_version_expiration_days" {
  description = "Days to keep previous object versions."
  type        = number
  default     = 30
}

variable "access_log_retention_days" {
  description = "Days to keep S3 server access logs."
  type        = number
  default     = 365
}
