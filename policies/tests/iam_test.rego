package main

import rego.v1

policy_doc(statements) := json.marshal({"Version": "2012-10-17", "Statement": statements})

role_policy(statements) := res("aws_iam_role_policy", "app", {"policy": policy_doc(statements)})

test_iam001_full_wildcard_denied if {
	results := deny with input as mock_plan([role_policy([{"Effect": "Allow", "Action": "*", "Resource": "*"}])])
	has_rule(results, "IAM-001")
}

test_iam001_service_wildcard_denied if {
	stmt := {"Effect": "Allow", "Action": ["s3:GetObject", "s3:*"], "Resource": "arn:aws:s3:::b/*"}
	results := deny with input as mock_plan([role_policy([stmt])])
	has_rule(results, "IAM-001")
}

test_iam001_single_statement_object_handled if {
	doc := json.marshal({"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}})
	results := deny with input as mock_plan([res("aws_iam_policy", "p", {"policy": doc})])
	has_rule(results, "IAM-001")
}

test_iam001_deny_statement_ignored if {
	stmt := {"Effect": "Deny", "Action": "s3:*", "Resource": "*"}
	results := deny with input as mock_plan([role_policy([stmt])])
	not has_rule(results, "IAM-001")
}

test_iam_least_privilege_passes if {
	stmt := {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::assets/*"]}
	plan := mock_plan([role_policy([stmt])])
	count(deny) == 0 with input as plan
	count(warn) == 0 with input as plan
}

test_iam002_resource_wildcard_warns if {
	stmt := {"Sid": "Describe", "Effect": "Allow", "Action": "ec2:DescribeInstances", "Resource": "*"}
	results := warn with input as mock_plan([role_policy([stmt])])
	has_rule(results, "IAM-002")
}

test_iam_unknown_policy_skipped if {
	# Policy not known until apply: no "policy" key in `after`.
	plan := mock_plan([res("aws_iam_role_policy", "app", {"name": "x"})])
	count(deny) == 0 with input as plan
}

test_iam003_admin_attachment_denied if {
	results := deny with input as mock_plan([res("aws_iam_role_policy_attachment", "admin", {
		"role": "app", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
	})])
	has_rule(results, "IAM-003")
}

test_iam003_scoped_managed_policy_allowed if {
	results := deny with input as mock_plan([res("aws_iam_role_policy_attachment", "ssm", {
		"role": "app", "policy_arn": "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
	})])
	not has_rule(results, "IAM-003")
}

test_iam004_access_key_denied if {
	results := deny with input as mock_plan([res("aws_iam_access_key", "ci", {"user": "ci-bot"})])
	has_rule(results, "IAM-004")
}

test_iam005_open_trust_policy_denied if {
	trust := policy_doc([{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": "*"}}])
	results := deny with input as mock_plan([res("aws_iam_role", "r", {"assume_role_policy": trust})])
	has_rule(results, "IAM-005")
}

test_iam005_service_trust_allowed if {
	trust := policy_doc([{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"Service": "ec2.amazonaws.com"}}])
	results := deny with input as mock_plan([res("aws_iam_role", "r", {"assume_role_policy": trust})])
	not has_rule(results, "IAM-005")
}
