provider "aws" {
  region = var.aws_region

  # Applied to every taggable resource; satisfies policy TAG-001.
  default_tags {
    tags = {
      owner                 = var.owner
      environment           = var.environment
      "data-classification" = var.data_classification
      project               = var.project_name
      "managed-by"          = "terraform"
    }
  }
}
