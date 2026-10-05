# Two private buckets: "assets" for application data and "logs" for S3 server
# access logs. Every bucket gets the same hardening companions, all named
# "this" and keyed like the bucket, which is the convention the S3 policies in
# policies/terraform/storage.rego rely on.

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id

  buckets = {
    assets = {
      name = "${var.name}-assets-${local.account_id}"
      # SSE-KMS with the AWS managed aws/s3 key.
      sse_algorithm = "aws:kms"
    }
    logs = {
      name = "${var.name}-logs-${local.account_id}"
      # S3 server access logging only delivers to SSE-S3 (AES256) buckets.
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket" "this" {
  for_each = local.buckets

  bucket        = each.value.name
  force_destroy = var.force_destroy

  tags = {
    Name    = each.value.name
    purpose = each.key
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  for_each = aws_s3_bucket.this

  bucket                  = each.value.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "this" {
  for_each = aws_s3_bucket.this

  bucket = each.value.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "this" {
  for_each = aws_s3_bucket.this

  bucket = each.value.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  for_each = aws_s3_bucket.this

  bucket = each.value.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = local.buckets[each.key].sse_algorithm
    }
    bucket_key_enabled = local.buckets[each.key].sse_algorithm == "aws:kms"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  for_each = aws_s3_bucket.this

  bucket = each.value.id

  rule {
    id     = "noncurrent-versions"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_version_expiration_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  dynamic "rule" {
    for_each = each.key == "logs" ? [1] : []

    content {
      id     = "expire-access-logs"
      status = "Enabled"

      filter {}

      expiration {
        days = var.access_log_retention_days
      }
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

data "aws_iam_policy_document" "bucket" {
  for_each = aws_s3_bucket.this

  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      each.value.arn,
      "${each.value.arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # Only the logs bucket accepts deliveries from the S3 logging service, and
  # only for the assets bucket in this account.
  dynamic "statement" {
    for_each = each.key == "logs" ? [1] : []

    content {
      sid       = "AllowS3ServerAccessLogs"
      actions   = ["s3:PutObject"]
      resources = ["${each.value.arn}/s3-access/*"]

      principals {
        type        = "Service"
        identifiers = ["logging.s3.amazonaws.com"]
      }

      condition {
        test     = "ArnLike"
        variable = "aws:SourceArn"
        values   = [aws_s3_bucket.this["assets"].arn]
      }

      condition {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [local.account_id]
      }
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  for_each = aws_s3_bucket.this

  bucket = each.value.id
  policy = data.aws_iam_policy_document.bucket[each.key].json

  depends_on = [aws_s3_bucket_public_access_block.this]
}

resource "aws_s3_bucket_logging" "assets" {
  bucket        = aws_s3_bucket.this["assets"].id
  target_bucket = aws_s3_bucket.this["logs"].id
  target_prefix = "s3-access/assets/"
}
