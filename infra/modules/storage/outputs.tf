output "bucket_names" {
  description = "Bucket names keyed by purpose."
  value       = { for k, b in aws_s3_bucket.this : k => b.id }
}

output "assets_bucket_arn" {
  description = "ARN of the application assets bucket."
  value       = aws_s3_bucket.this["assets"].arn
}
