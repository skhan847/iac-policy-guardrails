terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # Bootstrap starts with local state because the state bucket does not exist
  # yet. After the first apply, see README "Step 1" to migrate this state into
  # the bucket it just created.
}
