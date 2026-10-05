# Organisation-wide settings the policies enforce. Change values here,
# not inside individual rules, so a policy change is a one-line, reviewable diff.
package main

import rego.v1

allowed_regions := {"us-east-1", "us-east-2"}

allowed_instance_types := {"t3.micro", "t3.small", "t4g.micro", "t4g.small"}

allowed_db_instance_classes := {"db.t3.micro", "db.t4g.micro", "db.t4g.small"}

required_tags := {"owner", "environment", "data-classification"}

allowed_data_classifications := {"public", "internal", "confidential", "restricted"}

# Remote administration ports that must never be reachable from the internet.
admin_ports := {22, 3389, 5985, 5986}

# Ports that may be exposed to the internet without a warning.
public_ports := {80, 443}

minimum_backup_retention_days := 7

# Stateful resource types whose deletion or replacement needs an exception.
protected_types := {
	"aws_db_instance",
	"aws_rds_cluster",
	"aws_s3_bucket",
	"aws_dynamodb_table",
	"aws_kms_key",
}

# AWS managed policies too broad to attach to any principal.
forbidden_managed_policies := {
	"AdministratorAccess",
	"IAMFullAccess",
	"PowerUserAccess",
}
