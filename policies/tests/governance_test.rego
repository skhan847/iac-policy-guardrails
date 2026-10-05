package main

import rego.v1

good_tags := {"owner": "sk", "environment": "dev", "data-classification": "internal"}

tagged(tags) := res("aws_vpc", "main", {"tags_all": tags})

test_tag001_complete_tags_pass if {
	results := deny with input as mock_plan([tagged(good_tags)])
	not has_rule(results, "TAG-001")
	not has_rule(results, "TAG-002")
}

test_tag001_missing_tag_denied if {
	results := deny with input as mock_plan([tagged(object.remove(good_tags, ["owner"]))])
	has_rule(results, "TAG-001")
}

test_tag001_empty_value_counts_as_missing if {
	results := deny with input as mock_plan([tagged(object.union(good_tags, {"owner": ""}))])
	has_rule(results, "TAG-001")
}

test_tag001_unknown_tags_skipped if {
	results := deny with input as mock_plan([res("aws_vpc", "main", {"cidr_block": "10.0.0.0/16"})])
	not has_rule(results, "TAG-001")
}

test_tag002_bad_classification_denied if {
	results := deny with input as mock_plan([tagged(object.union(good_tags, {"data-classification": "top-secret"}))])
	has_rule(results, "TAG-002")
}

test_gov001_unapproved_region_variable_denied if {
	plan := {"resource_changes": [], "variables": {"aws_region": {"value": "eu-west-1"}}}
	results := deny with input as plan
	has_rule(results, "GOV-001")
}

test_gov001_unapproved_provider_constant_denied if {
	plan := {"resource_changes": [], "configuration": {"provider_config": {"aws": {
		"name": "aws",
		"expressions": {"region": {"constant_value": "ap-south-1"}},
	}}}}
	results := deny with input as plan
	has_rule(results, "GOV-001")
}

test_gov001_approved_region_passes if {
	plan := {"resource_changes": [], "variables": {"aws_region": {"value": "us-east-2"}}}
	results := deny with input as plan
	not has_rule(results, "GOV-001")
}

test_gov002_database_delete_denied if {
	rc := with_actions(res("aws_db_instance", "app", null), ["delete"])
	results := deny with input as mock_plan([rc])
	has_rule(results, "GOV-002")
}

test_gov002_bucket_replacement_denied if {
	rc := with_actions(res("aws_s3_bucket", "assets", {"bucket": "x"}), ["delete", "create"])
	results := deny with input as mock_plan([rc])
	some msg in results
	contains(msg, "would be replaced")
}

test_gov002_exception_allows_delete if {
	rc := with_actions(res("aws_db_instance", "app", null), ["delete"])
	results := deny with input as mock_plan([rc])
		with data.exceptions as [future_exception("GOV-002", "aws_db_instance.app")]
	not has_rule(results, "GOV-002")
}

test_gov002_unprotected_delete_allowed if {
	rc := with_actions(res("aws_security_group", "old", null), ["delete"])
	results := deny with input as mock_plan([rc])
	not has_rule(results, "GOV-002")
}

test_exc001_expired_exception_warns if {
	results := warn with input as mock_plan([])
		with data.exceptions as [expired_exception("NET-001", "aws_security_group.web")]
	has_rule(results, "EXC-001")
}

test_exc002_incomplete_exception_denied if {
	results := deny with input as mock_plan([])
		with data.exceptions as [{"rule": "NET-001", "address": "x", "expires": "2099-01-01T00:00:00Z"}]
	has_rule(results, "EXC-002")
}

test_exc002_complete_exception_passes if {
	results := deny with input as mock_plan([])
		with data.exceptions as [future_exception("NET-001", "x")]
	not has_rule(results, "EXC-002")
}
