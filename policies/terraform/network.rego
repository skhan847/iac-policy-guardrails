# Network exposure rules.
#
#   NET-001 (deny) Admin ports (SSH/RDP/WinRM) open to 0.0.0.0/0 or ::/0
#   NET-002 (warn) Any other internet-facing ingress except 80/443
#   NET-003 (warn) Subnets that auto-assign public IPs
#
# Security group rules can be written three ways in the AWS provider; all
# three are normalised into `ingress_rules` so each check is written once.
package main

import rego.v1

world_cidrs := {"0.0.0.0/0", "::/0"}

all_protocols := {"-1", "all"}

tcp_protocols := {"tcp", "6"}

# 1) Inline ingress blocks on aws_security_group
ingress_rules contains rule if {
	some rc in changed_resources
	rc.type == "aws_security_group"
	some block in as_array(object.get(rc.change.after, "ingress", []))
	cidrs := array.concat(as_array(object.get(block, "cidr_blocks", [])), as_array(object.get(block, "ipv6_cidr_blocks", [])))
	some cidr in cidrs
	rule := {
		"address": rc.address,
		"cidr": cidr,
		"protocol": lower(sprintf("%v", [block.protocol])),
		"from": block.from_port,
		"to": block.to_port,
	}
}

# 2) aws_security_group_rule with type = "ingress"
ingress_rules contains rule if {
	some rc in changed_resources
	rc.type == "aws_security_group_rule"
	rc.change.after.type == "ingress"
	cidrs := array.concat(as_array(object.get(rc.change.after, "cidr_blocks", [])), as_array(object.get(rc.change.after, "ipv6_cidr_blocks", [])))
	some cidr in cidrs
	rule := {
		"address": rc.address,
		"cidr": cidr,
		"protocol": lower(sprintf("%v", [rc.change.after.protocol])),
		"from": rc.change.after.from_port,
		"to": rc.change.after.to_port,
	}
}

# 3) aws_vpc_security_group_ingress_rule (current recommended resource)
ingress_rules contains rule if {
	some rc in changed_resources
	rc.type == "aws_vpc_security_group_ingress_rule"
	after := rc.change.after
	some cidr in [c | some c in [object.get(after, "cidr_ipv4", null), object.get(after, "cidr_ipv6", null)]; c != null]
	rule := {
		"address": rc.address,
		"cidr": cidr,
		"protocol": lower(sprintf("%v", [after.ip_protocol])),
		"from": object.get(after, "from_port", null),
		"to": object.get(after, "to_port", null),
	}
}

covers_port(rule, _) if rule.protocol in all_protocols

covers_port(rule, port) if {
	rule.protocol in tcp_protocols
	rule.from <= port
	port <= rule.to
}

admin_exposed(rule) if {
	rule.cidr in world_cidrs
	some port in admin_ports
	covers_port(rule, port)
}

only_public_ports(rule) if {
	rule.protocol in tcp_protocols
	rule.from == rule.to
	rule.from in public_ports
}

deny contains msg if {
	some rule in ingress_rules
	admin_exposed(rule)
	not exempt("NET-001", rule.address)
	msg := fmt_msg("NET-001", rule.address, sprintf("allows remote administration ports from the internet (%s). Use SSM Session Manager or restrict the CIDR.", [rule.cidr]))
}

warn contains msg if {
	some rule in ingress_rules
	rule.cidr in world_cidrs
	not admin_exposed(rule)
	not only_public_ports(rule)
	not exempt("NET-002", rule.address)
	msg := fmt_msg("NET-002", rule.address, sprintf("exposes protocol %s ports %v-%v to %s. Only 80/443 are expected to be public.", [rule.protocol, rule.from, rule.to, rule.cidr]))
}

warn contains msg if {
	some rc in changed_resources
	rc.type == "aws_subnet"
	rc.change.after.map_public_ip_on_launch == true
	not exempt("NET-003", rc.address)
	msg := fmt_msg("NET-003", rc.address, "auto-assigns public IPs to every instance launched in it. Assign public IPs explicitly instead.")
}
