output "instance_id" {
  description = "EC2 instance ID."
  value       = aws_instance.this.id
}

output "security_group_id" {
  description = "Security group attached to the instance."
  value       = aws_security_group.this.id
}

output "role_name" {
  description = "IAM role used by the instance."
  value       = aws_iam_role.this.name
}
