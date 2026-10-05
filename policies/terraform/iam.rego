# IAM least-privilege rules.
#
#   IAM-001 (deny) Allow statements with Action "*" or a service-wide wildcard ("s3:*")
#   IAM-002 (warn) Allow statements with Resource "*"
#   IAM-003 (deny) Attaching overly broad AWS managed policies (AdministratorAccess, ...)
#   IAM-004 (deny) Long-lived IAM user access keys
#   IAM-005 (deny) Role trust policies that let any AWS principal assume them
#
# Policy JSON is only checked when its value is known at plan time. If a policy
# references an attribute that does not exist yet (e.g. a new bucket ARN), the
# check runs on the next plan once that value is known.
package main

import rego.v1

inline_policy_types := {
	"aws_iam_policy",
	"aws_iam_role_policy",
	"aws_iam_user_policy",
	"aws_iam_group_policy",
	"aws_s3_bucket_policy",
}

attachment_types := {
	"aws_iam_role_policy_attachment",
	"aws_iam_user_policy_attachment",
	"aws_iam_group_policy_attachment",
	"aws_iam_policy_attachment",
}

# Every Allow statement in a known policy document, tagged with its resource.
allow_statements contains {"address": rc.address, "statement": stmt} if {
	some rc in changed_resources
	rc.type in inline_policy_types
	is_string(rc.change.after.policy)
	doc := json.unmarshal(rc.change.after.policy)
	some stmt in as_array(doc.Statement)
	stmt.Effect == "Allow"
}

wildcard_action(action) if action == "*"

wildcard_action(action) if endswith(action, ":*")

deny contains msg if {
	some entry in allow_statements
	some action in as_array(object.get(entry.statement, "Action", []))
	wildcard_action(action)
	not exempt("IAM-001", entry.address)
	msg := fmt_msg("IAM-001", entry.address, sprintf("grants wildcard action %q. List the specific actions needed.", [action]))
}

warn contains msg if {
	some entry in allow_statements
	"*" in as_array(object.get(entry.statement, "Resource", []))
	not exempt("IAM-002", entry.address)
	sid := object.get(entry.statement, "Sid", "(no Sid)")
	msg := fmt_msg("IAM-002", entry.address, sprintf("statement %s applies to Resource \"*\". Scope it to specific ARNs where the service supports it.", [sid]))
}

deny contains msg if {
	some rc in changed_resources
	rc.type in attachment_types
	some name in forbidden_managed_policies
	endswith(rc.change.after.policy_arn, sprintf(":policy/%s", [name]))
	not exempt("IAM-003", rc.address)
	msg := fmt_msg("IAM-003", rc.address, sprintf("attaches the AWS managed policy %s. Write a least-privilege policy instead.", [name]))
}

deny contains msg if {
	some rc in changed_resources
	rc.type == "aws_iam_access_key"
	not exempt("IAM-004", rc.address)
	msg := fmt_msg("IAM-004", rc.address, "creates a long-lived access key. Use IAM roles with OIDC or instance profiles.")
}

deny contains msg if {
	some rc in changed_resources
	rc.type == "aws_iam_role"
	is_string(rc.change.after.assume_role_policy)
	doc := json.unmarshal(rc.change.after.assume_role_policy)
	some stmt in as_array(doc.Statement)
	stmt.Effect == "Allow"
	open_principal(stmt.Principal)
	not exempt("IAM-005", rc.address)
	msg := fmt_msg("IAM-005", rc.address, "trust policy allows any AWS principal to assume this role.")
}

open_principal(p) if p == "*"

open_principal(p) if {
	is_object(p)
	"*" in as_array(object.get(p, "AWS", []))
}
