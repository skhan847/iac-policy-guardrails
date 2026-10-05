package main

import rego.v1

ssh_world := {"cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": [], "protocol": "tcp", "from_port": 22, "to_port": 22}

test_net001_inline_ssh_from_internet_denied if {
	results := deny with input as mock_plan([res("aws_security_group", "web", {"ingress": [ssh_world]})])
	has_rule(results, "NET-001")
}

test_net001_ipv6_world_denied if {
	rule := object.union(ssh_world, {"cidr_blocks": [], "ipv6_cidr_blocks": ["::/0"]})
	results := deny with input as mock_plan([res("aws_security_group", "web", {"ingress": [rule]})])
	has_rule(results, "NET-001")
}

test_net001_port_range_covering_rdp_denied if {
	results := deny with input as mock_plan([res("aws_security_group_rule", "wide", {
		"type": "ingress", "cidr_blocks": ["0.0.0.0/0"], "protocol": "tcp", "from_port": 3000, "to_port": 4000,
	})])
	has_rule(results, "NET-001")
}

test_net001_all_protocols_rule_denied if {
	results := deny with input as mock_plan([res("aws_vpc_security_group_ingress_rule", "all", {
		"cidr_ipv4": "0.0.0.0/0", "ip_protocol": "-1", "from_port": null, "to_port": null,
	})])
	has_rule(results, "NET-001")
}

test_net001_private_cidr_allowed if {
	rule := object.union(ssh_world, {"cidr_blocks": ["10.20.0.0/16"]})
	results := deny with input as mock_plan([res("aws_security_group", "web", {"ingress": [rule]})])
	not has_rule(results, "NET-001")
}

test_net001_exception_applies if {
	results := deny with input as mock_plan([res("aws_security_group", "web", {"ingress": [ssh_world]})])
		with data.exceptions as [future_exception("NET-001", "aws_security_group.web")]
	not has_rule(results, "NET-001")
}

test_net001_expired_exception_ignored if {
	results := deny with input as mock_plan([res("aws_security_group", "web", {"ingress": [ssh_world]})])
		with data.exceptions as [expired_exception("NET-001", "aws_security_group.web")]
	has_rule(results, "NET-001")
}

test_net001_deleted_group_ignored if {
	rc := with_actions(res("aws_security_group", "web", {"ingress": [ssh_world]}), ["delete"])
	results := deny with input as mock_plan([rc])
	not has_rule(results, "NET-001")
}

test_net002_nonstandard_public_port_warns if {
	results := warn with input as mock_plan([res("aws_vpc_security_group_ingress_rule", "app", {
		"cidr_ipv4": "0.0.0.0/0", "ip_protocol": "tcp", "from_port": 8080, "to_port": 8080,
	})])
	has_rule(results, "NET-002")
}

test_net002_https_does_not_warn if {
	results := warn with input as mock_plan([res("aws_vpc_security_group_ingress_rule", "https", {
		"cidr_ipv4": "0.0.0.0/0", "ip_protocol": "tcp", "from_port": 443, "to_port": 443,
	})])
	not has_rule(results, "NET-002")
}

test_net003_public_ip_subnet_warns if {
	results := warn with input as mock_plan([res("aws_subnet", "public", {"map_public_ip_on_launch": true})])
	has_rule(results, "NET-003")
}
