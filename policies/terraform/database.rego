# Database rules.
#
#   DB-001 (deny) RDS instance reachable from the internet
#   DB-002 (deny) RDS storage not encrypted at rest
#   DB-003 (deny) Instance class outside the approved list
#   DB-004 (warn) Deletion protection disabled
#   DB-005 (warn) Backup retention below the minimum
package main

import rego.v1

db_instances contains rc if {
	some rc in changed_resources
	rc.type == "aws_db_instance"
}

deny contains msg if {
	some rc in changed_resources
	rc.type in {"aws_db_instance", "aws_rds_cluster_instance"}
	rc.change.after.publicly_accessible == true
	not exempt("DB-001", rc.address)
	msg := fmt_msg("DB-001", rc.address, "is publicly accessible. Databases belong in private subnets.")
}

deny contains msg if {
	some rc in db_instances
	not rc.change.after.storage_encrypted == true
	not exempt("DB-002", rc.address)
	msg := fmt_msg("DB-002", rc.address, "must set storage_encrypted = true.")
}

deny contains msg if {
	some rc in db_instances
	not rc.change.after.instance_class in allowed_db_instance_classes
	not exempt("DB-003", rc.address)
	msg := fmt_msg("DB-003", rc.address, sprintf("uses instance class %q; allowed: %v.", [rc.change.after.instance_class, sort(allowed_db_instance_classes)]))
}

warn contains msg if {
	some rc in db_instances
	not rc.change.after.deletion_protection == true
	not exempt("DB-004", rc.address)
	msg := fmt_msg("DB-004", rc.address, "has deletion protection disabled.")
}

warn contains msg if {
	some rc in db_instances
	rc.change.after.backup_retention_period < minimum_backup_retention_days
	not exempt("DB-005", rc.address)
	msg := fmt_msg("DB-005", rc.address, sprintf("keeps backups for %v days; minimum is %v.", [rc.change.after.backup_retention_period, minimum_backup_retention_days]))
}
