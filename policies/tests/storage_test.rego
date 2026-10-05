package main

import rego.v1

storage_mod := "module.storage"

secure_bucket_set(key) := [
	mod_res(storage_mod, "aws_s3_bucket", "this", key, {"bucket": key}),
	mod_res(storage_mod, "aws_s3_bucket_public_access_block", "this", key, {
		"block_public_acls": true, "block_public_policy": true,
		"ignore_public_acls": true, "restrict_public_buckets": true,
	}),
	mod_res(storage_mod, "aws_s3_bucket_server_side_encryption_configuration", "this", key, {
		"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}],
	}),
	mod_res(storage_mod, "aws_s3_bucket_versioning", "this", key, {
		"versioning_configuration": [{"status": "Enabled"}],
	}),
]

# Drop resources of one type from a bucket set.
without(resources, type) := [rc | some rc in resources; rc.type != type]

test_s3_secure_bucket_passes if {
	plan := mock_plan(secure_bucket_set("assets"))
	count(deny) == 0 with input as plan
	count(warn) == 0 with input as plan
}

test_s3001_missing_public_access_block_denied if {
	plan := mock_plan(without(secure_bucket_set("assets"), "aws_s3_bucket_public_access_block"))
	results := deny with input as plan
	has_rule(results, "S3-001")
}

test_s3001_partial_public_access_block_denied if {
	bucket_set := secure_bucket_set("assets")
	weak := mod_res(storage_mod, "aws_s3_bucket_public_access_block", "this", "assets", {
		"block_public_acls": true, "block_public_policy": false,
		"ignore_public_acls": true, "restrict_public_buckets": true,
	})
	plan := mock_plan(array.concat(without(bucket_set, "aws_s3_bucket_public_access_block"), [weak]))
	results := deny with input as plan
	has_rule(results, "S3-001")
}

test_s3001_companion_must_match_bucket_key if {
	# The "logs" access block must not satisfy the check for "assets".
	assets := without(secure_bucket_set("assets"), "aws_s3_bucket_public_access_block")
	plan := mock_plan(array.concat(assets, secure_bucket_set("logs")))
	results := deny with input as plan
	has_rule(results, "S3-001")
}

test_s3002_missing_encryption_denied if {
	plan := mock_plan(without(secure_bucket_set("assets"), "aws_s3_bucket_server_side_encryption_configuration"))
	results := deny with input as plan
	has_rule(results, "S3-002")
}

test_s3003_missing_versioning_warns if {
	plan := mock_plan(without(secure_bucket_set("assets"), "aws_s3_bucket_versioning"))
	results := warn with input as plan
	has_rule(results, "S3-003")
}

test_s3004_public_acl_denied if {
	results := deny with input as mock_plan([res("aws_s3_bucket_acl", "site", {"acl": "public-read"})])
	has_rule(results, "S3-004")
}
