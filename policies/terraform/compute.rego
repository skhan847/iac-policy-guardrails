# EC2 rules.
#
#   CMP-001 (deny) Instance type outside the approved list (cost control)
#   CMP-002 (deny) IMDSv1 allowed (metadata_options.http_tokens must be "required")
#   CMP-003 (deny) Root volume not explicitly encrypted
#   CMP-004 (warn) Instance gets a public IP address
package main

import rego.v1

instances contains rc if {
	some rc in changed_resources
	rc.type == "aws_instance"
}

imdsv2_required(rc) if {
	some opts in rc.change.after.metadata_options
	opts.http_tokens == "required"
}

root_encrypted(rc) if {
	some root in rc.change.after.root_block_device
	root.encrypted == true
}

deny contains msg if {
	some rc in instances
	not rc.change.after.instance_type in allowed_instance_types
	not exempt("CMP-001", rc.address)
	msg := fmt_msg("CMP-001", rc.address, sprintf("uses instance type %q; allowed: %v.", [rc.change.after.instance_type, sort(allowed_instance_types)]))
}

deny contains msg if {
	some rc in instances
	not imdsv2_required(rc)
	not exempt("CMP-002", rc.address)
	msg := fmt_msg("CMP-002", rc.address, "must require IMDSv2 (metadata_options { http_tokens = \"required\" }).")
}

deny contains msg if {
	some rc in instances
	not root_encrypted(rc)
	not exempt("CMP-003", rc.address)
	msg := fmt_msg("CMP-003", rc.address, "root volume must set encrypted = true.")
}

warn contains msg if {
	some rc in instances
	rc.change.after.associate_public_ip_address == true
	not exempt("CMP-004", rc.address)
	msg := fmt_msg("CMP-004", rc.address, "will receive a public IP address. Prefer private subnets behind a load balancer.")
}
