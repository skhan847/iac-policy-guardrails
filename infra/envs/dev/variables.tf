variable "aws_region" {
  description = "AWS region. Policy GOV-001 restricts which regions are allowed."
  type        = string
  default     = "us-east-2"
}

variable "project_name" {
  description = "Short project name used in resource names."
  type        = string
  default     = "iac-guardrails"
}

variable "environment" {
  description = "Environment name."
  type        = string
  default     = "dev"
}

variable "owner" {
  description = "Owner tag value (your name or GitHub handle)."
  type        = string
}

variable "data_classification" {
  description = "Data classification tag applied to every resource."
  type        = string
  default     = "internal"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.20.0.0/16"
}

variable "enable_database" {
  description = "Create the RDS database. Set false to save cost while iterating on other parts."
  type        = bool
  default     = true
}
