variable "name" {
  description = "Name prefix for database resources."
  type        = string
}

variable "vpc_id" {
  description = "VPC for the database security group."
  type        = string
}

variable "subnet_ids" {
  description = "Private subnets for the DB subnet group (at least two AZs)."
  type        = list(string)
}

variable "allowed_security_groups" {
  description = "Security groups allowed to reach PostgreSQL, keyed by a static label (for example { web = sg-123 })."
  type        = map(string)
  default     = {}
}

variable "instance_class" {
  description = "RDS instance class. Must be on the allow-list in policies/terraform/config.rego."
  type        = string
  default     = "db.t4g.micro"
}

variable "engine_version" {
  description = "PostgreSQL major version."
  type        = string
  default     = "17"
}

variable "allocated_storage" {
  description = "Initial storage in GiB."
  type        = number
  default     = 20
}

variable "backup_retention_period" {
  description = "Days of automated backups."
  type        = number
  default     = 7
}

variable "deletion_protection" {
  description = "Block deletion of the instance. Leave true outside throwaway environments."
  type        = bool
  default     = true
}

variable "skip_final_snapshot" {
  description = "Skip the final snapshot on delete."
  type        = bool
  default     = false
}
