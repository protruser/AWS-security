"""Phase 2/3 state transitions around the existing phase-1 patch service."""
import hashlib
import json
import os
import re
from datetime import datetime, timezone

from services.patch_authorization import issue
from services.aws_collector import collect_aws_state
from services.ai_diagnosis_service import diagnose_aws_state
from services.github_terraform_source import GitHubSource
from services.patch_reports import final_report
from services.patch_security import PatchError, check_sensitive
from services.terraform_patch_service import TerraformPatches, audit, digest
from services.terraform_remediation_service import review_terraform_fix

CHECK_NAMES = ("fmt", "validate", "plan", "tflint", "checkov")


def approval_digest(patch):
    payload = patch["payload"]
    relevant = {"patch_id": patch["id"], "first_hash": patch["content_hash"],
                "head_sha": payload["github_pr"]["head_sha"],
                "base_sha": payload["github_pr"]["base_sha"],
                "run_id": payload["checks"]["run_id"],
                "plan_sha256": payload["checks"]["plan_sha256"],
                "plan_key": payload["checks"]["plan_key"],
                "plan_version_id": payload["checks"]["plan_version_id"],
                "state": payload["checks"]["state"],
                "final_report": payload["final_report"]}
    return hashlib.sha256(json.dumps(relevant, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


class PatchWorkflow(TerraformPatches):
    def __init__(self, *args, github_factory=GitHubSource, reviewer=review_terraform_fix,
                 report_final=final_report, **kwargs):
        super().__init__(*args, **kwargs)
        self.github_factory, self.reviewer, self.report_final = github_factory, reviewer, report_final

    def _source_guard(self, patch):
        if digest(patch["payload"]) != patch["content_hash"]:
            raise PatchError("CODE_CHANGED", "승인된 코드·보고서가 변경되었습니다.", 409)
        if patch["payload"].get("first_approval", {}).get("content_hash") != patch["content_hash"]:
            raise PatchError("FIRST_APPROVAL_REQUIRED", "해당 코드의 1차 승인이 필요합니다.", 409)

    def start_review(self, patch_id, actor):
        patch = self.repo.get(patch_id)
        if patch["status"] != "FIRST_APPROVED":
            raise PatchError("FIRST_APPROVAL_REQUIRED", "1차 승인된 패치만 검증할 수 있습니다.", 409)
        self._source_guard(patch)
        patch["status"] = "AI_REVIEWING"
        audit(patch["payload"], "AI_REVIEWING", actor)
        self.repo.save(patch, "FIRST_APPROVED")
        self.submit(lambda: self._review_and_publish(patch, actor))
        return self.repo.get(patch_id)

    def _review_and_publish(self, patch, actor):
        payload = patch["payload"]
        try:
            diff = "\n".join(f["diff"] for f in payload["files"] if f["diff"])
            review = self.reviewer(
                finding={"findings": payload["findings"]},
                diff_text=diff,
                files=[{key: file.get(key) for key in
                        ("file_path", "original_content", "proposed_content", "diff")}
                       for file in payload["files"]],
                mapping=payload.get("mapping"),
                change_report=payload.get("report"),
            )
            if review.get("verdict") not in ("APPROVE", "REJECT", "NEEDS_HUMAN_REVIEW"):
                raise ValueError("invalid verdict")
            check_sensitive(json.dumps(review, ensure_ascii=False))
            payload["ai_review"] = review
            patch["status"] = {
                "APPROVE": "READY_FOR_PR",
                "REJECT": "AI_REJECTED",
                "NEEDS_HUMAN_REVIEW": "AI_NEEDS_HUMAN_REVIEW",
            }[review["verdict"]]
            audit(payload, {
                "APPROVE": "AI_APPROVED",
                "REJECT": "AI_REJECTED",
                "NEEDS_HUMAN_REVIEW": "AI_NEEDS_HUMAN_REVIEW",
            }[review["verdict"]], actor)
        except Exception:
            patch["status"] = "AI_REVIEW_FAILED"
            payload["error"] = {"code": "AI_REVIEW_FAILED", "message": "2차 AI 검증에 실패했습니다. 새 패치로 다시 요청하세요."}
            audit(payload, "AI_REVIEW_FAILED", actor)
        self.repo.save(patch, "AI_REVIEWING")
        if patch["status"] == "READY_FOR_PR" and os.getenv("PATCH_ENABLE_GITHUB_WRITES") == "true":
            self.publish(patch["id"], actor)

    def publish(self, patch_id, actor):
        patch = self.repo.get(patch_id)
        if patch["status"] != "READY_FOR_PR" or patch["payload"].get("ai_review", {}).get("verdict") != "APPROVE":
            raise PatchError("AI_APPROVAL_REQUIRED", "2차 AI 검증 통과 후에만 PR을 만들 수 있습니다.", 409)
        self._source_guard(patch)
        github = self.github_factory()
        if not patch["payload"].get("github_pr"):
            info = github.commit_patch(patch)
            patch["payload"]["github_pr"] = info
            audit(patch["payload"], "BRANCH_CREATED", actor, head_sha=info["head_sha"])
            self.repo.save(patch, "READY_FOR_PR")
        result = github.create_pr(patch)
        patch["payload"]["github_pr"].update(result)
        patch["payload"]["checks"] = {"results": {k: {"status": "NOT_RUN"} for k in CHECK_NAMES}}
        patch["status"] = "CHECKS_RUNNING"
        audit(patch["payload"], "PR_CREATED", actor, url=result["url"])
        self.repo.save(patch, "READY_FOR_PR")
        return self.repo.get(patch_id)

    def refresh_checks(self, patch_id, actor):
        patch = self.repo.get(patch_id)
        if patch["status"] != "CHECKS_RUNNING":
            raise PatchError("INVALID_STATE", "자동 검사 중인 패치만 조회할 수 있습니다.", 409)
        self._source_guard(patch)
        info = patch["payload"]["github_pr"]
        github = self.github_factory()
        pr = github.pr_state(info["number"])
        if (pr.get("draft") is not True or pr.get("head", {}).get("sha") != info["head_sha"]
                or pr.get("base", {}).get("ref") != info["base_ref"]
                or github.ref_sha(info["branch"]) != info["head_sha"]
                or github.base_sha() != info["base_sha"]):
            patch["status"] = "REVALIDATION_REQUIRED"
            audit(patch["payload"], "REVALIDATION_REQUIRED", actor, code="CODE_CHANGED")
            self.repo.save(patch, "CHECKS_RUNNING")
            raise PatchError("CODE_CHANGED", "PR 또는 운영 브랜치가 변경되었습니다. 새 패치와 재승인이 필요합니다.", 409)
        run = github.workflow_run(info["branch"], info["head_sha"])
        if not run:
            return patch
        checks = patch["payload"]["checks"]
        checks.update({"run_id": run["id"], "url": run["html_url"], "started_at": run.get("created_at")})
        if run.get("status") != "completed":
            for value in checks["results"].values():
                value["status"] = "RUNNING"
            patch["status"] = "CHECKS_RUNNING"
            self.repo.save(patch, patch["status"])
            return self.repo.get(patch_id)
        try:
            manifest = github.artifact_manifest(run["id"], patch_id)
            if (manifest.get("patch_id") != patch_id or manifest.get("head_sha") != info["head_sha"]
                    or manifest.get("base_sha") != info["base_sha"] or manifest.get("run_id") != run["id"]):
                raise ValueError("manifest does not bind to reviewed commit")
            results = manifest["results"]
            if set(results) != set(CHECK_NAMES) or not all(results[k]["status"] in
                    ("PASS", "FAIL", "ERROR", "NOT_RUN") for k in CHECK_NAMES):
                raise ValueError("invalid checks")
            summary = manifest.get("plan_summary")
            kinds = {"create", "update", "delete", "replace", "read", "no-op"}
            if summary is not None and (not isinstance(summary, dict)
                    or not isinstance(summary.get("counts"), dict)
                    or not isinstance(summary.get("resources"), dict)
                    or set(summary["counts"]) != kinds or set(summary["resources"]) != kinds
                    or any(type(summary["counts"][kind]) is not int or summary["counts"][kind] < 0
                           or not isinstance(summary["resources"][kind], list)
                           or len(summary["resources"][kind]) != summary["counts"][kind]
                           or not all(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_]{1,100}", value)
                                      for value in summary["resources"][kind]) for kind in kinds)):
                raise ValueError("invalid plan summary")
            labels = summary.get("labels") if isinstance(summary, dict) else None
            if labels is not None and (not isinstance(labels, dict) or set(labels) != kinds
                    or any(not isinstance(labels[kind], list)
                           or len(labels[kind]) != summary["counts"][kind]
                           or not all(isinstance(label, str) and re.fullmatch(
                               r"[A-Za-z0-9_]{1,100}(?:\.[A-Za-z0-9_]{1,100})?", label)
                                      for label in labels[kind]) for kind in kinds)):
                raise ValueError("invalid plan resource labels")
            checks["results"] = results
            checks["finished_at"] = run.get("updated_at")
            checks["plan_summary"] = manifest.get("plan_summary")
            checks["plan_sha256"] = manifest.get("plan_sha256")
            checks["plan_key"] = manifest.get("plan_key")
            checks["plan_version_id"] = manifest.get("plan_version_id")
            checks["state"] = manifest.get("state")
            check_sensitive(json.dumps(checks, ensure_ascii=False))
            if (run.get("conclusion") != "success" or any(v["status"] != "PASS" for v in results.values())
                    or not isinstance(checks["plan_summary"], dict)
                    or not isinstance(checks["plan_sha256"], str) or len(checks["plan_sha256"]) != 64
                    or not isinstance(checks["plan_key"], str) or not checks["plan_key"].startswith(f"terraform-patches/{patch_id}/{info['head_sha']}/")
                    or not isinstance(checks["plan_version_id"], str) or not checks["plan_version_id"]
                    or not isinstance(checks["state"], dict)
                    or not isinstance(checks["state"].get("lineage"), str)
                    or type(checks["state"].get("serial")) is not int):
                patch["status"] = "CHECKS_FAILED"
            else:
                patch["status"] = "FINAL_REPORTING"
        except Exception:
            patch["status"] = "CHECKS_FAILED"
            checks["error"] = "GitHub 검증 결과를 신뢰할 수 없습니다."
            for value in checks["results"].values():
                if value.get("status") == "RUNNING":
                    value["status"] = "ERROR"
        audit(patch["payload"], patch["status"], actor, run_id=run["id"])
        self.repo.save(patch, "CHECKS_RUNNING")
        if patch["status"] == "FINAL_REPORTING":
            self.submit(lambda: self._build_final_report(patch, actor))
        return self.repo.get(patch_id)

    def _build_final_report(self, patch, actor):
        try:
            patch["payload"]["final_report"] = self.report_final(patch)
            patch["status"] = "AWAITING_FINAL_APPROVAL"
            audit(patch["payload"], patch["status"], actor)
        except Exception:
            patch["status"] = "FINAL_REPORT_FAILED"
            patch["payload"]["error"] = {"code": "FINAL_REPORT_FAILED", "message": "최종 보고서 생성에 실패했습니다."}
        self.repo.save(patch, "FINAL_REPORTING")

    def decide_final(self, patch_id, body, actor):
        patch = self.repo.get(patch_id)
        if patch["requested_by"] == actor:
            raise PatchError("SELF_APPROVAL", "요청자는 최종 승인할 수 없습니다.", 403)
        if patch["status"] != "AWAITING_FINAL_APPROVAL":
            raise PatchError("INVALID_STATE", "최종 보고서가 준비된 패치만 승인할 수 있습니다.", 409)
        self._source_guard(patch)
        if any(patch["payload"]["checks"]["results"].get(name, {}).get("status") != "PASS"
               for name in CHECK_NAMES):
            raise PatchError("CHECKS_NOT_PASSED", "Every required GitHub check must pass.", 409)
        binding = approval_digest(patch)
        if body.get("approval_hash") != binding or body.get("reviewed") is not True:
            raise PatchError("STALE_APPROVAL", "최신 보고서·Plan·검증 결과 확인이 필요합니다.", 409)
        decision, note = body.get("decision"), body.get("note", "")
        if decision not in ("approve", "reject") or not isinstance(note, str) or len(note) > 2000 or (decision == "reject" and not note.strip()):
            raise PatchError("INVALID_DECISION", "승인/반려와 반려 사유를 확인하세요.")
        check_sensitive(note)
        info = patch["payload"]["github_pr"]
        github = self.github_factory()
        pr = github.pr_state(info["number"])
        if (pr.get("state") != "open" or pr.get("draft") is not True
                or pr.get("head", {}).get("sha") != info["head_sha"]
                or pr.get("base", {}).get("ref") != info["base_ref"]
                or github.ref_sha(info["branch"]) != info["head_sha"]
                or github.base_sha() != info["base_sha"]):
            patch["status"] = "REVALIDATION_REQUIRED"
            audit(patch["payload"], "REVALIDATION_REQUIRED", actor, code="CODE_CHANGED")
            self.repo.save(patch, "AWAITING_FINAL_APPROVAL")
            raise PatchError("CODE_CHANGED", "코드가 변경되었습니다. 검증과 승인을 다시 받아야 합니다.", 409)
        patch["status"] = "FINAL_APPROVED" if decision == "approve" else "FINAL_REJECTED"
        audit(patch["payload"], patch["status"], actor, approval_hash=binding, note=note)
        patch["payload"]["final_approval"] = patch["payload"]["audit"][-1]
        self.repo.save(patch, "AWAITING_FINAL_APPROVAL")
        return self.repo.get(patch_id)

    def start_deploy(self, patch_id, actor):
        patch = self.repo.get(patch_id)
        if patch["status"] != "FINAL_APPROVED":
            raise PatchError("FINAL_APPROVAL_REQUIRED", "최종 승인된 패치만 배포할 수 있습니다.", 409)
        if os.getenv("PATCH_ENABLE_TERRAFORM_APPLY") != "true":
            raise PatchError("APPLY_DISABLED", "Terraform 배포 기능이 비활성화되어 있습니다.", 503)
        if os.getenv("PATCH_ENABLE_GITHUB_WRITES") != "true":
            raise PatchError("GITHUB_WRITES_DISABLED", "GitHub 쓰기 기능이 비활성화되어 있습니다.", 503)
        self._source_guard(patch)
        if any(patch["payload"]["checks"]["results"].get(name, {}).get("status") != "PASS"
               for name in CHECK_NAMES):
            raise PatchError("CHECKS_NOT_PASSED", "Every required GitHub check must pass.", 409)
        binding = approval_digest(patch)
        if patch["payload"].get("final_approval", {}).get("approval_hash") != binding:
            raise PatchError("STALE_APPROVAL", "승인 이후 코드·Plan·보고서가 달라졌습니다.", 409)
        info, checks = patch["payload"]["github_pr"], patch["payload"]["checks"]
        github = self.github_factory()
        pr = github.pr_state(info["number"])
        if (pr.get("state") != "open" or pr.get("draft") is not True
                or pr.get("head", {}).get("sha") != info["head_sha"]
                or pr.get("base", {}).get("ref") != info["base_ref"]
                or github.ref_sha(info["branch"]) != info["head_sha"]
                or github.base_sha() != info["base_sha"]):
            raise PatchError("CODE_CHANGED", "PR 또는 운영 브랜치가 변경되었습니다. 재검증·재승인이 필요합니다.", 409)
        run = github.workflow_run(info["branch"], info["head_sha"])
        if not run or run.get("id") != checks["run_id"] or run.get("conclusion") != "success":
            raise PatchError("CHECKS_CHANGED", "승인된 검사 실행 결과가 더 이상 유효하지 않습니다.", 409)
        manifest = github.artifact_manifest(run["id"], patch_id)
        if (manifest.get("plan_sha256") != checks["plan_sha256"]
                or manifest.get("plan_key") != checks["plan_key"]
                or manifest.get("plan_version_id") != checks["plan_version_id"]
                or manifest.get("state") != checks["state"]
                or manifest.get("results") != checks["results"]):
            raise PatchError("CHECKS_CHANGED", "Plan 또는 검사 기록이 승인 당시와 다릅니다.", 409)
        token = issue(patch, binding)
        self.repo.acquire_deploy_lock(patch_id)
        patch["status"] = "DEPLOYING"
        started = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        patch["payload"]["deployment"] = {"status": "RUNNING", "started_at": started,
            "head_sha": info["head_sha"], "plan_sha256": checks["plan_sha256"]}
        audit(patch["payload"], "DEPLOYING", actor, approval_hash=binding)
        try:
            self.repo.save(patch, "FINAL_APPROVED")
        except Exception:
            self.repo.release_deploy_lock(patch_id)
            raise
        try:
            github.dispatch_deploy(patch_id, token)
        except Exception:
            # Dispatch may be ambiguous; keep the lock if GitHub accepted but the
            # response failed. A human must inspect the run before any retry.
            patch["status"] = "DEPLOY_DISPATCH_UNKNOWN"
            patch["payload"]["deployment"]["status"] = "UNKNOWN"
            audit(patch["payload"], "DEPLOY_DISPATCH_UNKNOWN", actor)
            self.repo.save(patch, "DEPLOYING")
            raise PatchError("DEPLOY_DISPATCH_UNKNOWN", "배포 요청 상태를 확인할 수 없습니다. GitHub 실행 기록을 확인하세요.", 409) from None
        return self.repo.get(patch_id)

    def block_stale_deploy(self, patch_id, code):
        """Stop automatic retries when approval no longer binds to source/checks."""
        patch = self.repo.get(patch_id)
        if patch["status"] != "FINAL_APPROVED":
            return
        patch["status"] = "REVALIDATION_REQUIRED"
        patch["payload"]["error"] = {"code": code, "message": "Code or validation changed; create and approve a new patch."}
        audit(patch["payload"], "REVALIDATION_REQUIRED", "deploy-worker", code=code)
        self.repo.save(patch, "FINAL_APPROVED")

    def refresh_deploy(self, patch_id, actor):
        patch = self.repo.get(patch_id)
        if patch["status"] != "DEPLOYING":
            raise PatchError("INVALID_STATE", "진행 중인 배포가 아닙니다.", 409)
        github = self.github_factory()
        run = github.deployment_run(patch_id, patch["payload"]["deployment"]["started_at"])
        if not run or run.get("status") != "completed":
            return patch
        deployment = patch["payload"]["deployment"]
        deployment.update({"run_id": run["id"], "url": run["html_url"],
                           "completed_at": run.get("updated_at")})
        try:
            result = github.artifact_manifest(run["id"], patch_id, name=f"terraform-deploy-{patch_id}")
            if (result.get("patch_id") != patch_id or result.get("run_id") != run["id"]
                    or result.get("head_sha") != deployment["head_sha"]):
                raise ValueError("wrong deployment artifact")
            deployment["merge_sha"] = result.get("merge_sha")
            deployment["stages"] = {name: result.get(f"{name}_status", "NOT_RUN")
                                    for name in ("plan", "merge", "apply")}
            if result.get("plan_status") == "failure":
                deployment["error"] = "Saved Plan or Terraform State verification failed. Investigate and revalidate before a new patch."
            success = (run.get("conclusion") == "success"
                       and all(result.get(f"{name}_status") == "success"
                               for name in ("plan", "merge", "apply")))
        except Exception:
            success = False
            deployment["error"] = "배포 증거를 확인할 수 없습니다. GitHub 실행 기록을 확인하세요."
        deployment["status"] = "SUCCESS" if success else "FAILED"
        patch["status"] = "REDIAGNOSING" if success else "DEPLOY_FAILED"
        audit(patch["payload"], patch["status"], actor, run_id=run["id"])
        self.repo.save(patch, "DEPLOYING")
        self.repo.release_deploy_lock(patch_id)
        if success:
            self.submit(lambda: self._rediagnose(patch, actor))
        return self.repo.get(patch_id)

    def _rediagnose(self, patch, actor):
        try:
            result = diagnose_aws_state(collect_aws_state())
            check_sensitive(json.dumps(result, ensure_ascii=False, default=str))
            run_id = self.repo.store_rediagnosis(result, patch["id"])
            after = {r["rule_id"]: r for r in result["results"]}
            comparisons = []
            for finding in patch["payload"]["findings"]:
                current = after.get(finding["rule_id"], {})
                comparisons.append({"rule_id": finding["rule_id"], "before": finding["status"],
                    "after": current.get("status", "REVIEW"),
                    "current_value": current.get("current_value"),
                    "expected_value": current.get("expected_value"),
                    "verified": current.get("status") == "PASS"})
            patch["payload"]["rediagnosis"] = {"run_id": run_id, "results": comparisons}
            patch["status"] = "REMEDIATED" if all(r["verified"] for r in comparisons) else "NOT_REMEDIATED"
        except Exception:
            patch["status"] = "REDIAGNOSIS_FAILED"
            patch["payload"]["rediagnosis"] = {"error": "재진단에 실패했습니다. 배포 성공과 진단 통과는 별개입니다."}
        audit(patch["payload"], patch["status"], actor)
        self.repo.save(patch, "REDIAGNOSING")
