variable "name" {
  description = "Name prefix for compute resources."
  type        = string
}

variable "vpc_id" {
  description = "VPC to launch into."
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR; HTTPS ingress and database egress are limited to it."
  type        = string
}

variable "subnet_id" {
  description = "Private subnet for the instance."
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type. Must be on the allow-list in policies/terraform/config.rego."
  type        = string
  default     = "t3.micro"
}

variable "assets_bucket_arn" {
  description = "Bucket the application may read from."
  type        = string
}
