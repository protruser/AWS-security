# Terraform AI patch workflow

## Existing capabilities reused

The dashboard already provides FAIL multi-selection, encrypted patch history,
integrated per-file AI proposals, first and final human approval, second AI review,
GitHub PR checks, saved-plan deployment, rediagnosis, and `.patch`/PDF downloads.
The MySQL `terraform_patches` and `terraform_patch_deploy_lock` tables are reused.
No new migration is required for this update.

## Source and guardrails

The sole Terraform source is `protruser/AWS-Security-Infra`, branch `gyu`, with
Terraform root `.` and managed declarations under `modules/`. The dashboard's
`wonny-sec-terraform/` is never used as operational input. The source adapter
rejects any other repository or ref. Reads are pinned to a commit, and Git blob
hashes are checked. A changed `gyu` head requires a new patch and approvals.
Branches use `ai-patch/<patch UUID>`; PRs target `gyu`. No code directly pushes
to `gyu`. Patch PRs start as drafts and can only be marked ready by the signed
deployment workflow after final approval and revalidation.

`POST /api/ai-actions/mapping-preview` reads the live file tree and resource
declarations. When `TF_STATE_BUCKET` and `TF_STATE_KEY` are configured, it also
reads Terraform State to confirm AWS resource identity. State values are never
returned or stored by mapping. A file-type match without State ownership is
marked `MANUAL_REVIEW`; the operator must confirm or change the file. The
preview commit SHA is required when creating a patch, so stale mappings fail.
IAM rules 1.1–1.4 and 1.9 can be mapped to their specific Terraform
resource types (1.2 targets IAM access keys and login profiles). When the live `gyu` tree has no such declarations, preview
returns `NO_CANDIDATE` and permits an operator to choose a file manually;
it never claims that an existing IAM resource is owned by Terraform.

The sequence is source snapshot → integrated proposal and first report → admin
first approval → second AI review (a `NEEDS_HUMAN_REVIEW` result requires an
admin decision with a recorded reason) → patch branch and PR → GitHub checks and saved Plan
→ final AI report → separate approver final decision → deployment worker → merge → apply
→ rediagnosis. A rejection or failure stops that patch. Earlier versions remain
downloadable from encrypted DB history, regardless of GitHub branch retention.
First approval starts the second AI review automatically. An `APPROVE` verdict
starts draft branch and PR creation immediately when GitHub writes are enabled.
The patch worker retries a `READY_FOR_PR` patch if that creation was interrupted
or GitHub was temporarily unavailable. Rejected and unresolved reviews never
create a PR.

The final report explains the planned change, user impact, interruption and
replacement risk in plain Korean, with unverified conditions clearly marked.
After the second AI review, all GitHub checks pass, and the final report is ready,
the approver sees the patch in the dashboard bell. Final approval immediately
dispatches the signed deployment when apply is enabled. Run
`backend/run_patch_deploy_worker.py` as a separate managed process. It polls
GitHub checks, retries pending PR creation and approved deployments after transient failures,
and records completed deployment runs even when no browser is open. Optimistic
patch status transitions and a global
deploy lock prevent duplicate dispatch. The worker rechecks the signed approval,
PR head/base, successful CI run, exact Plan manifest and commit before dispatch.
The GitHub runner checks signature, PR, saved Plan SHA/version, and State
lineage/serial again before merge and apply. If a prerequisite changes, a new
patch with new checks and approvals is required. A merge that succeeds before
an apply failure remains a recorded partial deployment and is never retried.

## API

| Method | Path suffix under `/api/ai-actions` | Purpose |
| --- | --- | --- |
| POST | `/mapping-preview` | Suggest files for selected FAIL rule IDs |
| GET/POST | `/patches` | History / create patch from confirmed mapping |
| GET | `/patches/<id>` | Full encrypted-history detail |
| GET | `/patches/approval-inbox` | Approver-only ready patch notifications |
| POST | `/terraform-fix` | First AI integrated proposal |
| POST | `/patches/<id>/first-approval` | Admin first approval or rejection |
| POST | `/patches/<id>/ai-review` | Second AI after first approval |
| POST | `/patches/<id>/human-review` | Admin decision on a bound `NEEDS_HUMAN_REVIEW` result |
| POST | `/patches/<id>/publish` | Isolated branch and PR |
| POST | `/patches/<id>/checks/refresh` | Record actual CI results |
| POST | `/patches/<id>/final-approval` | Separate approver final approval or rejection |
| POST | `/patches/<id>/deployment/refresh` | Record deployment and rediagnose |
| POST | `/patches/<id>/rediagnosis/use-latest` | Reconcile a failed rediagnosis with a completed AI diagnosis started after the verified apply; never redeploy |
| GET | `/patches/<id>/download/{patch,first,final,results}` | Historical artifacts |

There is no public deploy button or deploy API.

## Infra repository setup (installed)

The workflows live in `protruser/AWS-Security-Infra` itself (the former
`integrations/` drafts were adapted to the S3 backend in `versions.tf`, Terraform
1.16.4, deterministic Lambda builds and `TERRAFORM_TFVARS`, then removed here):

- `.github/workflows/terraform-patch.yml`: runs only for `ai-patch/<UUID>` PRs to
  `gyu`. fmt / validate / TFLint (error level) / Checkov (only findings that the
  patch adds compared with `gyu`) / plan. The saved Plan is KMS-encrypted under
  `terraform-patches/` in the State bucket; only `manifest.json` is uploaded.
- `.github/workflows/terraform-patch-deploy.yml`: dispatched by the worker. Verifies
  the signed approval, PR/branch/base/check run, Plan SHA/version and State
  lineage/serial, merges the PR with `GITHUB_TOKEN`, then applies the saved Plan.
- `scripts/terraform_patch_ci.py`, `scripts/verify_patch_authorization.py`.
- Human PRs keep using `terraform-pr.yml` / `terraform-apply.yml` (GitHub
  `production` approval). Both deploy paths share the `terraform-production`
  concurrency group.

Infra repository settings:

- Default branch: `gyu` (`workflow_dispatch` requires the workflow on the default branch).
- Environment `terraform-production`: no reviewers (the dashboard's signed final
  approval is the approval), deployment branches `gyu` only.
- Variables: `AWS_REGION`, `TF_PLAN_ROLE_ARN`, `TF_APPLY_ROLE_ARN`,
  `TF_PLAN_BUCKET` (the State bucket), `TF_PLAN_KMS_KEY_ARN`
  (`terraform output terraform_plan_kms_key_arn`).
- Secrets: `TERRAFORM_TFVARS`, `PATCH_APPROVAL_SIGNING_KEY` (same value as the dashboard).
- Branch protection on `gyu` must not require an approving review, or the deploy
  workflow's `GITHUB_TOKEN` merge fails.

## Dashboard setup

`deploy/dashboard/deploy.sh` applies the `terraform_patches` migration and runs
`run_patch_deploy_worker.py` as the `dashboard-patch-worker` container (same image
and `/opt/dashboard/app.env`).

`/opt/dashboard/app.env`:

- `GITHUB_TOKEN`: fine-grained PAT for `protruser/AWS-Security-Infra` only, with
  Contents read/write, Pull requests read/write and Actions read/write. The default
  Actions `GITHUB_TOKEN` cannot be used: PRs it creates do not trigger workflows.
- `PATCH_ENCRYPTION_KEY`: Fernet key shared by the dashboard and the worker.
- `PATCH_APPROVAL_SIGNING_KEY`: at least 32 bytes, same as the infra repository secret.
- `PATCH_GITHUB_REPOSITORY` / `PATCH_GITHUB_REF`: default to
  `protruser/AWS-Security-Infra` / `gyu`; other values are rejected.
- `TF_STATE_BUCKET`, `TF_STATE_KEY`, `TF_STATE_REGION`: optional read-only State
  access for confident resource mapping. With these unset, mapping is manual.
- `PATCH_ENABLE_GITHUB_WRITES=true` and `PATCH_ENABLE_TERRAFORM_APPLY=true` only
  after the settings above are ready. Both remain disabled by default.

Dashboard Actions variable `TRIVY_BLOCK_DEPLOY` defaults to false/unset. Setting
it to `true` makes HIGH or CRITICAL image findings block the ECR push. Existing
Amazon Inspector remains unchanged.
