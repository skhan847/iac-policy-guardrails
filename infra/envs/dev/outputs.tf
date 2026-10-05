output "vpc_id" {
  description = "VPC ID."
  value       = module.network.vpc_id
}

output "bucket_names" {
  description = "S3 bucket names."
  value       = module.storage.bucket_names
}

output "instance_id" {
  description = "Application instance ID."
  value       = module.compute.instance_id
}

output "database_endpoint" {
  description = "Database endpoint, if the database is enabled."
  value       = one(module.database[*].endpoint)
}

output "database_secret_arn" {
  description = "Secrets Manager ARN for the database master password."
  value       = one(module.database[*].master_user_secret_arn)
}
