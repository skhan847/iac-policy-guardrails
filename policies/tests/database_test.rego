package main

import rego.v1

secure_db := {
	"instance_class": "db.t4g.micro",
	"publicly_accessible": false,
	"storage_encrypted": true,
	"deletion_protection": true,
	"backup_retention_period": 7,
}

db(overrides) := res("aws_db_instance", "app", object.union(secure_db, overrides))

test_db_secure_instance_passes if {
	plan := mock_plan([db({})])
	count(deny) == 0 with input as plan
	count(warn) == 0 with input as plan
}

test_db001_public_instance_denied if {
	results := deny with input as mock_plan([db({"publicly_accessible": true})])
	has_rule(results, "DB-001")
}

test_db002_unencrypted_denied if {
	results := deny with input as mock_plan([db({"storage_encrypted": false})])
	has_rule(results, "DB-002")
}

test_db003_large_instance_class_denied if {
	results := deny with input as mock_plan([db({"instance_class": "db.r6g.4xlarge"})])
	has_rule(results, "DB-003")
}

test_db004_deletion_protection_off_warns if {
	results := warn with input as mock_plan([db({"deletion_protection": false})])
	has_rule(results, "DB-004")
}

test_db005_short_backup_retention_warns if {
	results := warn with input as mock_plan([db({"backup_retention_period": 1})])
	has_rule(results, "DB-005")
}
