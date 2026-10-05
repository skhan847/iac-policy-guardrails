variable "aws_region" {
  description = "Region for the state bucket and IAM resources."
  type        = string
  default     = "us-east-2"
}

variable "project_name" {
  description = "Short name used as a prefix for resources."
  type        = string
  default     = "iac-guardrails"

  validation {
    condition     = can(regex("^[a-z0-9-]{3,24}$", var.project_name))
    error_message = "Use 3-24 lowercase letters, digits or hyphens."
  }
}

variable "owner" {
  description = "Value for the required owner tag (your name or GitHub handle)."
  type        = string
}

variable "github_repository" {
  description = "GitHub repository allowed to assume the CI roles, as owner/name."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "Use the form owner/repository."
  }
}

variable "github_environment" {
  description = "GitHub Environment whose jobs may assume the apply role."
  type        = string
  default     = "dev"
}

variable "create_oidc_provider" {
  description = "Set to false if the account already has the GitHub OIDC provider (only one is allowed per account)."
  type        = bool
  default     = true
}
