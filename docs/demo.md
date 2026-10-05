# Five-minute demo script

Prerequisites: setup in the README is done and the dev stack is deployed from `main`.

## 1. A risky change is blocked (≈2 min)

```bash
git switch -c demo/open-ssh
cp docs/demo/open-ssh.tf.example infra/envs/dev/demo.tf
git add infra/envs/dev/demo.tf
git commit -m "Open SSH for debugging"
git push -u origin demo/open-ssh
```

Open the pull request. Point out, in order:

- **Checkov** fails in *Format, lint, scan* on its generic open-SSH check (CKV_AWS_24).
- **Plan and policy check** still runs and posts a comment: `[NET-001] aws_vpc_security_group_ingress_rule.debug_ssh: allows remote administration ports from the internet`. Explain that this rule ran against the *plan*, after modules and variables were resolved, which a source scanner cannot always do.
- The **Merge** button is blocked by branch protection.
- The workflow file contains no AWS keys: the job got 1-hour credentials through OIDC, and only for the read-only plan role.

## 2. Fix it (≈1 min)

Change `cidr_ipv4` to `module.network.vpc_cidr` (or delete the file), push, and show the comment update to ✅ in place.

## 3. Deploy through the gate (≈1 min)

Merge. In **Actions → Apply**, show that the plan job re-ran the policies on `main`, the plan summary is attached, and the apply job is **waiting for approval** in the `dev` environment. Approve it. The apply uses the *saved* plan, so exactly what was reviewed is what runs.

## 4. Catch a change made outside the pipeline (≈1 min)

In the AWS console, open the `…-assets-…` bucket → **Properties → Bucket Versioning → Suspend**. Then run **Actions → Drift detection → Run workflow**. A GitHub issue labeled `drift` appears listing the changed resource. Re-run **Apply** (workflow_dispatch) to restore the declared state, and run drift detection again to show the issue closing itself.

## Offline backup

If AWS or GitHub misbehave during the presentation:

```bash
make policy-demo
```

Same policies, run locally against `policies/fixtures/*.json`: the secure plan passes and the insecure one returns 13 denials and 5 warnings.
