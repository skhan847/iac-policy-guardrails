package main

import rego.v1

secure_instance := {
	"instance_type": "t3.micro",
	"associate_public_ip_address": false,
	"metadata_options": [{"http_endpoint": "enabled", "http_tokens": "required"}],
	"root_block_device": [{"encrypted": true, "volume_type": "gp3"}],
}

instance(overrides) := res("aws_instance", "web", object.union(secure_instance, overrides))

test_cmp_secure_instance_passes if {
	plan := mock_plan([instance({})])
	count(deny) == 0 with input as plan
	count(warn) == 0 with input as plan
}

test_cmp001_unapproved_type_denied if {
	results := deny with input as mock_plan([instance({"instance_type": "m5.4xlarge"})])
	has_rule(results, "CMP-001")
}

test_cmp002_imdsv1_allowed_denied if {
	results := deny with input as mock_plan([instance({"metadata_options": [{"http_tokens": "optional"}]})])
	has_rule(results, "CMP-002")
}

test_cmp002_metadata_options_omitted_denied if {
	after := object.remove(secure_instance, ["metadata_options"])
	results := deny with input as mock_plan([res("aws_instance", "web", after)])
	has_rule(results, "CMP-002")
}

test_cmp003_unencrypted_root_denied if {
	results := deny with input as mock_plan([instance({"root_block_device": [{"encrypted": false}]})])
	has_rule(results, "CMP-003")
}

test_cmp004_public_ip_warns if {
	results := warn with input as mock_plan([instance({"associate_public_ip_address": true})])
	has_rule(results, "CMP-004")
}
