# Policy exceptions

Sometimes a policy is right in general but wrong for one resource. Weakening or deleting the rule would remove protection everywhere, so instead this repo allows **narrow, time-boxed, reviewed exceptions**.

## How exceptions work

Exceptions live in [`policies/data/exceptions.json`](../policies/data/exceptions.json) and are passed to Conftest with `--data`. Every rule calls `exempt(rule_id, address)` before reporting a finding. An exception applies only when:

- `rule` matches the rule ID exactly (for example `NET-001`), and
- `address` matches the full Terraform resource address exactly, and
- `expires` is in the future.

```json
{
  "rule": "DB-004",
  "address": "module.database[0].aws_db_instance.this",
  "reason": "Dev database is torn down after every demo; deletion protection would block terraform destroy.",
  "approved_by": "course-instructor",
  "ticket": "DEVSECOPS-12",
  "expires": "2026-12-31T23:59:59Z"
}
```

All six fields are required; EXC-002 denies the plan if any are missing. When an exception expires it stops applying automatically, and EXC-001 warns so someone removes or renews it.

## Requesting one

1. Find the exact address in the PR comment or the plan output.
2. Add an entry to `exceptions.json` in the same PR as the change that needs it. Keep `expires` as short as practical (90 days at most).
3. Explain in `reason` why the risk is acceptable and what compensating control exists, if any.
4. A code owner of `policies/data/` must approve the PR (enforced by CODEOWNERS and branch protection).

## What exceptions cannot do

- They cannot cover a whole rule, a whole module or a wildcard address.
- GOV-001 (region) has no exception path.
- They do not touch Checkov. Checkov skips go in `.checkov.yaml` with a written justification and get the same review.

## Why this design

Every exception is in version control, linked to a ticket, tied to an approver, and expires on its own. An auditor can answer "what risks have we accepted, who accepted them, and until when?" with `git log policies/data/exceptions.json`.
