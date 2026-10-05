package main

import rego.v1

# ---- Test helpers (shared by every *_test.rego file) ----

mock_plan(resources) := {"resource_changes": resources}

# A managed resource change at the root module.
res(type, name, after) := {
	"address": sprintf("%s.%s", [type, name]),
	"mode": "managed",
	"type": type,
	"name": name,
	"change": {"actions": ["create"], "after": after},
}

# Same, inside a module with a for_each key, e.g. module.storage.aws_s3_bucket.this["assets"]
mod_res(module, type, name, key, after) := {
	"address": sprintf("%s.%s.%s[%q]", [module, type, name, key]),
	"module_address": module,
	"mode": "managed",
	"type": type,
	"name": name,
	"index": key,
	"change": {"actions": ["create"], "after": after},
}

with_actions(rc, actions) := object.union(rc, {"change": object.union(rc.change, {"actions": actions})})

has_rule(results, rule_id) if {
	some msg in results
	startswith(msg, sprintf("[%s]", [rule_id]))
}

future_exception(rule_id, address) := {
	"rule": rule_id,
	"address": address,
	"reason": "test",
	"approved_by": "test",
	"ticket": "TEST-1",
	"expires": "2099-01-01T00:00:00Z",
}

expired_exception(rule_id, address) := object.union(
	future_exception(rule_id, address),
	{"expires": "2000-01-01T00:00:00Z"},
)
