# Tagging and governance rules.
#
#   TAG-001 (deny) Taggable resource missing a required tag
#   TAG-002 (deny) data-classification tag has a value outside the approved set
#   GOV-001 (deny) Deployment to a region outside the approved list
#   GOV-002 (deny) Plan deletes or replaces a stateful resource
#   EXC-001 (warn) An exception in policies/data/exceptions.json has expired
#   EXC-002 (deny) An exception is missing required fields
package main

import rego.v1

# tags_all includes provider default_tags, so tags set once in the provider
# block satisfy this rule. Resources whose tags are unknown at plan time are
# skipped rather than failed.
resource_tags(rc) := tags if {
	tags := rc.change.after.tags_all
	is_object(tags)
}

deny contains msg if {
	some rc in changed_resources
	tags := resource_tags(rc)
	present := {k | some k, v in tags; v != ""}
	missing := required_tags - present
	count(missing) > 0
	not exempt("TAG-001", rc.address)
	msg := fmt_msg("TAG-001", rc.address, sprintf("is missing required tags %v.", [sort(missing)]))
}

deny contains msg if {
	some rc in changed_resources
	tags := resource_tags(rc)
	value := tags["data-classification"]
	not value in allowed_data_classifications
	not exempt("TAG-002", rc.address)
	msg := fmt_msg("TAG-002", rc.address, sprintf("has data-classification %q; allowed: %v.", [value, sort(allowed_data_classifications)]))
}

# Region from the aws_region variable, or a hard-coded provider region.
plan_regions contains region if region := input.variables.aws_region.value

plan_regions contains region if {
	some provider in input.configuration.provider_config
	provider.name == "aws"
	region := provider.expressions.region.constant_value
}

deny contains msg if {
	some region in plan_regions
	not region in allowed_regions
	msg := fmt_msg("GOV-001", "provider.aws", sprintf("region %q is not approved; allowed: %v.", [region, sort(allowed_regions)]))
}

deny contains msg if {
	some rc in deleted_resources
	rc.type in protected_types
	not exempt("GOV-002", rc.address)
	verb := replace_or_delete(rc.change.actions)
	msg := fmt_msg("GOV-002", rc.address, sprintf("would be %s, which destroys its data. Add a time-boxed exception if this is intended.", [verb]))
}

replace_or_delete(actions) := "replaced" if "create" in actions

replace_or_delete(actions) := "deleted" if not "create" in actions

required_exception_fields := {"rule", "address", "reason", "approved_by", "expires", "ticket"}

warn contains msg if {
	some e in data.exceptions
	time.now_ns() >= time.parse_rfc3339_ns(e.expires)
	msg := fmt_msg("EXC-001", e.address, sprintf("exception for %s expired on %s and is no longer applied. Remove it or renew it.", [e.rule, e.expires]))
}

deny contains msg if {
	some i, e in data.exceptions
	missing := {f | some f in required_exception_fields; not e[f]}
	count(missing) > 0
	msg := fmt_msg("EXC-002", sprintf("exceptions[%d]", [i]), sprintf("is missing required fields %v.", [sort(missing)]))
}
