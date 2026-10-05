locals {
  name = "${var.project_name}-${var.environment}"
}

module "network" {
  source = "../../modules/network"

  name       = local.name
  cidr_block = var.vpc_cidr
}

module "storage" {
  source = "../../modules/storage"

  name = local.name
  # Dev is torn down regularly; production would keep the default (false).
  force_destroy = true
}

module "compute" {
  source = "../../modules/compute"

  name              = local.name
  vpc_id            = module.network.vpc_id
  vpc_cidr          = module.network.vpc_cidr
  subnet_id         = module.network.private_subnet_ids[0]
  assets_bucket_arn = module.storage.assets_bucket_arn
}

module "database" {
  source = "../../modules/database"
  count  = var.enable_database ? 1 : 0

  name       = local.name
  vpc_id     = module.network.vpc_id
  subnet_ids = module.network.private_subnet_ids

  allowed_security_groups = {
    web = module.compute.security_group_id
  }

  # Dev only, covered by an approved exception for DB-004 in
  # policies/data/exceptions.json. Production keeps the module defaults.
  deletion_protection = false
  skip_final_snapshot = true
}
