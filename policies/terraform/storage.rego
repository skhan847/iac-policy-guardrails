# S3 data protection rules.
#
#   S3-001 (deny) Bucket without a public access block that sets all four flags
#   S3-002 (deny) Bucket without explicit server-side encryption configuration
#   S3-003 (warn) Bucket without versioning enabled
#   S3-004 (deny) Public canned ACLs
#
# S3 settings are separate resources in AWS provider v4+, so these rules look
# for companion resources with the same module, name and index as the bucket
# (see `companions` in lib.rego).
package main

import rego.v1

public_access_flags := [
	"block_public_acls",
	"block_public_policy",
	"ignore_public_acls",
	"restrict_public_buckets",
]

public_acls := {"public-read", "public-read-write", "authenticated-read"}

buckets contains rc if {
	some rc in changed_resources
	rc.type == "aws_s3_bucket"
}

fully_blocked(bucket) if {
	some pab in companions(bucket, "aws_s3_bucket_public_access_block")
	every flag in public_access_flags {
		pab.change.after[flag] == true
	}
}

encrypted(bucket) if {
	some sse in companions(bucket, "aws_s3_bucket_server_side_encryption_configuration")
	some rule in sse.change.after.rule
	some by_default in rule.apply_server_side_encryption_by_default
	by_default.sse_algorithm in {"AES256", "aws:kms", "aws:kms:dsse"}
}

versioned(bucket) if {
	some v in companions(bucket, "aws_s3_bucket_versioning")
	some cfg in v.change.after.versioning_configuration
	cfg.status == "Enabled"
}

deny contains msg if {
	some bucket in buckets
	not fully_blocked(bucket)
	not exempt("S3-001", bucket.address)
	msg := fmt_msg("S3-001", bucket.address, "needs an aws_s3_bucket_public_access_block with all four flags set to true.")
}

deny contains msg if {
	some bucket in buckets
	not encrypted(bucket)
	not exempt("S3-002", bucket.address)
	msg := fmt_msg("S3-002", bucket.address, "needs an explicit aws_s3_bucket_server_side_encryption_configuration (AES256 or aws:kms).")
}

warn contains msg if {
	some bucket in buckets
	not versioned(bucket)
	not exempt("S3-003", bucket.address)
	msg := fmt_msg("S3-003", bucket.address, "does not have versioning enabled, so overwritten or deleted objects cannot be recovered.")
}

deny contains msg if {
	some rc in changed_resources
	rc.type == "aws_s3_bucket_acl"
	rc.change.after.acl in public_acls
	not exempt("S3-004", rc.address)
	msg := fmt_msg("S3-004", rc.address, sprintf("uses the public canned ACL %q.", [rc.change.after.acl]))
}
