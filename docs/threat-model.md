# Threat model

Method: STRIDE, applied to the delivery pipeline (the main attack surface for IaC) and to the deployed infrastructure. Treat this as a living document: update it when you add a component, and link each new control back to a row here.

## Scope and trust boundaries

| Component | Trust boundary |
|---|---|
| Developer workstation | Untrusted until code passes review |
| GitHub repository and pull requests | Code is untrusted until merged to `main` through branch protection |
| GitHub Actions runners | Ephemeral; trusted only with the permissions each job declares |
| AWS IAM plan role | Read-only; assumable from pull requests and `main` |
| AWS IAM apply role | Write; assumable only from the `dev` GitHub Environment |
| Terraform state (S3) | Contains resource attributes and possibly sensitive values |
| Deployed workload (VPC, EC2, RDS, S3) | Production-like data |

## Assets

1. AWS account integrity (who can create, change or delete resources)
2. Terraform state (source of truth; can contain sensitive values)
3. Application data in S3 and RDS
4. The guardrails themselves (policies, exceptions, workflows, bootstrap IAM)

## Pipeline threats

| STRIDE | Threat | Control in this repo | Residual risk / next step |
|---|---|---|---|
| Spoofing | Attacker obtains long-lived AWS keys from CI secrets | No keys exist: GitHub OIDC federation with short-lived STS credentials; IAM-004 denies creating IAM user keys | Compromise of a maintainer's GitHub account |
| Spoofing | A fork or other repo assumes the AWS roles | Trust policies pin `aud` and exact `sub` values for this repository; plan job skips forks | None significant |
| Tampering | A PR weakens a policy or adds an exception to slip a change through | CODEOWNERS on `policies/` and `.github/`; required code-owner review; EXC-002 enforces exception metadata; exceptions expire | Collusion between author and reviewer |
| Tampering | A PR modifies the workflow to skip checks or exfiltrate credentials | Workflow changes need code-owner review; PR jobs only get the read-only plan role | A malicious `terraform plan` can run code via external data sources or providers. Mitigate with a provider allow-list (`.terraform.lock.hcl` review) |
| Tampering | Compromised third-party action or tool | Pinned major versions, Dependabot updates, checksum-verified Conftest and Gitleaks downloads | Pin actions to commit SHAs (stretch goal) |
| Tampering | State file altered or deleted | Versioned, encrypted bucket; TLS-only policy; public access blocked; apply role explicitly denied bucket-policy and versioning changes | Enable MFA delete or Object Lock for production |
| Repudiation | No record of who changed infrastructure | Every change is a merged PR plus an environment approval; CloudTrail records role sessions named with the workflow run ID | Ship CloudTrail to a separate log-archive account |
| Information disclosure | Secrets committed to the repo | Gitleaks in pre-commit and CI; `detect-private-key`; RDS password generated and held by Secrets Manager | Historical secrets require rotation, not just removal |
| Information disclosure | Plan artifact leaks sensitive values | One-day artifact retention; PR comment includes policy results and plan summary only | Encrypt the plan artifact |
| Denial of service | Concurrent applies corrupt state | S3-native state locking; workflow concurrency groups | None significant |
| Elevation of privilege | Pipeline grants itself or the app admin rights | Apply role can only manage `app-*` roles; explicit deny on attaching admin policies; IAM-001/003/005 policies; bootstrap applied out-of-band | Replace PowerUserAccess with a scoped policy and permissions boundary |

## Infrastructure threats

| STRIDE | Threat | Control | Policy / check |
|---|---|---|---|
| Spoofing | SSRF steals EC2 instance credentials via IMDSv1 | IMDSv2 required, hop limit 1 | CMP-002, Checkov CKV_AWS_79 |
| Tampering | Unauthorized changes made in the console | Nightly refresh-only drift detection opens an issue | `drift.yml` |
| Information disclosure | Public S3 bucket | Public access block, BucketOwnerEnforced, TLS-only policy | S3-001, S3-004 |
| Information disclosure | Unencrypted data at rest | SSE on buckets, encrypted RDS and EBS | S3-002, DB-002, CMP-003 |
| Information disclosure | Database reachable from the internet | Private subnets, security group references only the app, `publicly_accessible = false`, `rds.force_ssl` | DB-001 |
| Elevation of privilege | Internet-exposed admin ports | No SSH at all; SSM Session Manager | NET-001 |
| Elevation of privilege | Over-broad application role | Role limited to reading one bucket | IAM-001, IAM-002 |
| Denial of service / data loss | Accidental database or bucket replacement | Plans that destroy stateful resources are denied without an exception | GOV-002, DB-004, DB-005 |
| Repudiation | No network audit trail | VPC flow logs to CloudWatch (1 year); S3 server access logs | Checkov CKV2_AWS_11 |
