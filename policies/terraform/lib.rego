# Shared helpers used by every policy in package main.
#
# Input is the JSON produced by `terraform show -json tfplan`.
# Reference: https://developer.hashicorp.com/terraform/internals/json-format
package main

import rego.v1

# Managed resources that this plan will create or update.
# Deletes and no-ops are ignored; replacements ("delete" + "create") are included.
changed_resources contains rc if {
	some rc in input.resource_changes
	rc.mode == "managed"
	some action in rc.change.actions
	action in {"create", "update"}
}

# Managed resources that this plan will delete (including replacements).
deleted_resources contains rc if {
	some rc in input.resource_changes
	rc.mode == "managed"
	"delete" in rc.change.actions
}

# True when an approved, unexpired exception exists for this rule and address.
# Exceptions live in policies/data/exceptions.json (see docs/exceptions.md).
exempt(rule_id, address) if {
	some e in data.exceptions
	e.rule == rule_id
	e.address == address
	time.now_ns() < time.parse_rfc3339_ns(e.expires)
}

# Companion resources declared next to a parent: same module, same resource
# name, same count/for_each index. Example: aws_s3_bucket.this["logs"] and
# aws_s3_bucket_versioning.this["logs"]. Modules in this repo follow that
# naming convention so policies can correlate resources at plan time, when
# IDs that would normally link them are still unknown.
companions(parent, type) := {c |
	some c in input.resource_changes
	c.type == type
	c.mode == "managed"
	object.get(c, "module_address", "") == object.get(parent, "module_address", "")
	c.name == parent.name
	object.get(c, "index", null) == object.get(parent, "index", null)
}

# Normalise "x" / ["x"] / null into an array.
as_array(x) := x if is_array(x)

as_array(x) := [x] if {
	not is_array(x)
	x != null
}

as_array(null) := []

# Consistent message format: [RULE-ID] address: explanation
fmt_msg(rule_id, address, text) := sprintf("[%s] %s: %s", [rule_id, address, text])
