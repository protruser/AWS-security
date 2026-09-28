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

The sequence is source snapshot → integrated proposal and first report → first
approval → second AI review → patch branch and PR → GitHub checks and saved Plan
→ final AI report → final approval → separate deployment worker → merge → apply
→ rediagnosis. A rejection or failure stops that patch. Earlier versions remain
downloadable from encrypted DB history, regardless of GitHub branch retention.

Final approval records the decision only. Run `backend/run_patch_deploy_worker.py`
as a separate managed process. It polls GitHub checks, dispatches approved
deployments when apply is enabled, and records completed deployment runs even
when no browser is open. Optimistic patch status transitions and a global
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
| POST | `/terraform-fix` | First AI integrated proposal |
| POST | `/patches/<id>/first-approval` | First approval or rejection |
| POST | `/patches/<id>/ai-review` | Second AI after first approval |
| POST | `/patches/<id>/publish` | Isolated branch and PR |
| POST | `/patches/<id>/checks/refresh` | Record actual CI results |
| POST | `/patches/<id>/final-approval` | Final approval or rejection |
| POST | `/patches/<id>/deployment/refresh` | Record deployment and rediagnose |
| GET | `/patches/<id>/download/{patch,first,final,results}` | Historical artifacts |

There is no public deploy button or deploy API.

## Installation required before enabling writes

The files under `integrations/AWS-Security-Infra/` are prepared artifacts only.
They have **not** been pushed to the operational repository. After separate
authorization, install validation workflow and its CI script on `gyu` through
a reviewed PR. Install the deployment workflow and authorization verifier on
both `gyu` and the repository default branch (`main`): GitHub requires a
`workflow_dispatch` workflow on the default branch, while dispatch targets
`gyu`. Keep branch protection preventing merges without required checks. The
validation workflow has no `terraform apply` command. The dashboard Docker
pipeline has Trivy before ECR push; the Terraform PR uses Checkov.

Dashboard environment:

- `PATCH_GITHUB_REPOSITORY=protruser/AWS-Security-Infra`
- `PATCH_GITHUB_REF=gyu`
- `GITHUB_TOKEN`: scoped GitHub App/PAT with Contents and Pull requests write,
  Actions read/write for run inspection and dispatch. A token other than the default `GITHUB_TOKEN` may be
  needed to trigger PR Actions from API-created branches.
- `PATCH_ENCRYPTION_KEY`: shared Fernet key for all backend workers.
- `PATCH_APPROVAL_SIGNING_KEY`: at least 32 bytes, same value in the infra
  repository's protected Actions secret.
- `OPENAI_API_KEY`, existing DB/session/role configuration.
- `TF_STATE_BUCKET`, `TF_STATE_KEY`, `TF_STATE_REGION`: optional read-only State
  access for confident resource mapping. With these unset, mapping is manual.
- `PATCH_ENABLE_GITHUB_WRITES=true` and `PATCH_ENABLE_TERRAFORM_APPLY=true` only
  after workflows, credentials, protected environment, and worker are ready.
  Both remain disabled by default.

Infra repository Actions variables:

- `TF_STATE_REGION`, `TF_STATE_BUCKET`, `TF_STATE_KEY` for existing remote State.
- `TF_PLAN_BUCKET` with versioning and `TF_PLAN_KMS_KEY_ARN` for encrypted Plans.
- `TF_PLAN_ROLE_ARN`: OIDC role with provider read/list/describe, State read and
  lock permissions, and Plan object write/KMS encryption. No AWS mutation rights.
- `TF_APPLY_ROLE_ARN`: separate protected OIDC role for approved deployment.
- `PATCH_APPROVAL_SIGNING_KEY`: protected Actions secret.

Dashboard Actions variable `TRIVY_BLOCK_DEPLOY` defaults to false/unset. Setting
it to `true` makes HIGH or CRITICAL image findings block the ECR push. Existing
Amazon Inspector remains unchanged.

No GitHub write, PR, merge, migration execution, or Terraform apply is part of
this local code update.
