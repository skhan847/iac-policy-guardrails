# Bucket and region are passed at init time so no account-specific values are
# committed:
#   terraform init -backend-config=backend.hcl            (locally)
#   terraform init -backend-config="bucket=..." ...       (CI, from repo variables)
terraform {
  backend "s3" {
    key          = "envs/dev/terraform.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}
