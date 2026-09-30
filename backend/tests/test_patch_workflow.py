"""End-to-end state tests with in-memory patches and fake GitHub/AWS."""
import os
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

from cryptography.fernet import Fernet

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app
from services.patch_authorization import verify
from services.patch_security import PatchError
from services.patch_workflow import PatchWorkflow, approval_digest, human_review_digest, CHECK_NAMES
from services.patch_repository import PatchRepository
from run_patch_deploy_worker import run_once
from services.terraform_patch_service import digest
from test_ai_action import MemoryRepository, ORIGINAL, PROPOSED, report_for


class Repository(MemoryRepository):
    def __init__(self):
        super().__init__()
        self.lock = None

    def acquire_deploy_lock(self, patch_id):
        if self.lock is not None:
            raise PatchError("DEPLOY_BUSY", "locked", 409)
        self.lock = patch_id

    def release_deploy_lock(self, patch_id):
        if self.lock == patch_id:
            self.lock = None

    def store_rediagnosis(self, result, patch_id):
        return 8

    def pending_deploy_ids(self, limit=10):
        return [row["id"] for row in self.rows.values() if row["status"] == "FINAL_APPROVED"][:limit]

    def active_check_ids(self, limit=10):
        return [row["id"] for row in self.rows.values() if row["status"] == "CHECKS_RUNNING"][:limit]

    def ready_pr_ids(self, limit=10):
        return [row["id"] for row in self.rows.values() if row["status"] == "READY_FOR_PR"][:limit]

    def active_deploy_ids(self, limit=10):
        return [row["id"] for row in self.rows.values() if row["status"] == "DEPLOYING"][:limit]


class GitHub:
    def __init__(self):
        self.base, self.head = "a" * 40, "b" * 40
        self.writes, self.dispatches, self.deploy_run = 0, [], None
        self.check_run = {"id": 501, "html_url": "https://github.com/org/repo/actions/runs/501",
                          "status": "completed", "conclusion": "success", "created_at": "2026-01-01T00:00:00Z",
                          "updated_at": "2026-01-01T00:01:00Z"}

    def commit_patch(self, row):
        self.writes += 1
        return {"branch": f'ai-patch/{row["id"]}', "base_sha": self.base, "head_sha": self.head,
                "repository": "org/repo", "base_ref": "wonny"}

    def create_pr(self, row):
        self.writes += 1
        return {"number": 42, "url": "https://github.com/org/repo/pull/42"}

    def pr_state(self, number):
        return {"state": "open", "draft": True, "head": {"sha": self.head}, "base": {"ref": "wonny"}}

    def ref_sha(self, branch):
        return self.head

    def base_sha(self):
        return self.base

    def workflow_run(self, branch, head_sha):
        return self.check_run

    def artifact_manifest(self, run_id, patch_id, name=None):
        if name:
            return {"patch_id": patch_id, "run_id": run_id, "head_sha": self.head,
                    "merge_sha": "c" * 40, "plan_status": "success",
                    "merge_status": "success", "apply_status": "success"}
        return {"patch_id": patch_id, "head_sha": self.head, "base_sha": self.base,
                "run_id": 501, "results": {k: {"status": "PASS", "url": "https://github.com/check",
                    "at": "2026-01-01T00:01:00Z"} for k in CHECK_NAMES},
                "plan_summary": {"counts": {"create": 0, "update": 1, "delete": 0, "replace": 0,
                                            "read": 0, "no-op": 0},
                                 "resources": {"create": [], "update": ["aws_s3_bucket"], "delete": [],
                                               "replace": [], "read": [], "no-op": []}},
                "plan_sha256": "d" * 64, "plan_key": f"terraform-patches/{patch_id}/{self.head}/501.tfplan",
                "plan_version_id": "version-1", "state": {"lineage": "state-1", "serial": 7}}

    def dispatch_deploy(self, patch_id, authorization):
        self.dispatches.append((patch_id, authorization))

    def deployment_run(self, patch_id, dispatched_at):
        return self.deploy_run


class PatchWorkflowTest(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"PATCH_ENCRYPTION_KEY": Fernet.generate_key().decode(),
            "PATCH_APPROVAL_SIGNING_KEY": "a" * 48, "OPENAI_API_KEY": "test-key",
            "PATCH_ENABLE_GITHUB_WRITES": "true", "PATCH_ENABLE_TERRAFORM_APPLY": "true"})
        env.start(); self.addCleanup(env.stop)
        self.repo, self.github = Repository(), GitHub()
        self.reviewer = Mock(return_value={"verdict": "APPROVE", "summary": "검증 통과", "concerns": [], "model": "claude"})
        self.report_final = Mock(return_value={"version": "final-v1", "ai_assessment": {
            "assessment": "plan 검토", "risks": [], "post_deploy_checks": ["재진단"]}})
        self.flow = PatchWorkflow(repository=self.repo, github_factory=lambda: self.github,
            reviewer=self.reviewer, report_final=self.report_final, submit=lambda work: work())
        self.patch_id = "11111111-1111-1111-1111-111111111111"
        files = [{"file_path": "modules/security/kms_secrets_storage.tf", "original_content": ORIGINAL,
                  "proposed_content": PROPOSED, "diff": "--- a/x\n+++ b/x\n-true\n+false\n"}]
        payload = {"findings": [{"rule_id": "3.7", "status": "FAIL"}],
            "mapping": {"3.7": [files[0]["file_path"]]},
            "source": {"repository": "org/repo", "ref": "wonny", "commit_sha": "a" * 40},
            "files": files, "report": report_for(files=files), "audit": [],
            "first_approval": None, "ai_review": None, "github_pr": None, "checks": None,
            "final_report": None, "final_approval": None, "deployment": None, "rediagnosis": None}
        row = {"id": self.patch_id, "diagnosis_run_id": 7, "status": "FIRST_APPROVED",
               "requested_by": "operator", "payload": payload, "revision": 1}
        row["content_hash"] = digest(payload)
        payload["first_approval"] = {"actor": "reviewer", "content_hash": row["content_hash"]}
        self.repo.insert(row)

    def stage_checks(self):
        self.flow.start_review(self.patch_id, "operator")
        self.assertEqual(self.repo.get(self.patch_id)["status"], "CHECKS_RUNNING")

    def await_first_approval(self):
        row = self.repo.get(self.patch_id)
        row["status"] = "AWAITING_FIRST_APPROVAL"
        row["payload"]["first_approval"] = None
        self.repo._store(row)
        return row

    def stage_final(self):
        self.stage_checks()
        return self.flow.refresh_checks(self.patch_id, "operator")

    def approve_final(self):
        row = self.stage_final()
        self.assertEqual(row["status"], "AWAITING_FINAL_APPROVAL")
        return self.flow.decide_final(self.patch_id, {"decision": "approve",
            "approval_hash": approval_digest(row), "reviewed": True}, "reviewer")

    def test_review_then_isolated_pr(self):
        self.stage_checks()
        self.reviewer.assert_called_once()
        review_input = self.reviewer.call_args.kwargs
        self.assertEqual(review_input["files"][0]["original_content"], ORIGINAL)
        self.assertEqual(review_input["files"][0]["proposed_content"], PROPOSED)
        self.assertEqual(review_input["mapping"], {"3.7": [review_input["files"][0]["file_path"]]})
        row = self.repo.get(self.patch_id)
        self.assertEqual(row["payload"]["github_pr"]["branch"], f"ai-patch/{self.patch_id}")
        self.assertEqual(self.github.writes, 2)
        self.assertIsNone(row["payload"]["deployment"])

    def test_first_approval_starts_second_review_and_pr(self):
        row = self.await_first_approval()
        approved = self.flow.decide(self.patch_id, {
            "decision": "approve", "content_hash": row["content_hash"],
            "reviewed": True, "note": "변경 확인"}, "operator")
        self.assertEqual(approved["status"], "CHECKS_RUNNING")
        self.assertEqual(approved["payload"]["first_approval"]["event"], "FIRST_APPROVED")
        self.assertEqual([item["event"] for item in approved["payload"]["audit"][:2]],
                         ["FIRST_APPROVED", "AI_REVIEWING"])
        self.reviewer.assert_called_once()
        self.assertEqual(self.github.writes, 2)
        with self.assertRaises(PatchError):
            self.flow.decide(self.patch_id, {
                "decision": "approve", "content_hash": row["content_hash"],
                "reviewed": True, "note": ""}, "operator")

    def test_first_rejection_does_not_start_second_review(self):
        row = self.await_first_approval()
        rejected = self.flow.decide(self.patch_id, {
            "decision": "reject", "content_hash": row["content_hash"],
            "reviewed": True, "note": "수정 범위 재검토"}, "operator")
        self.assertEqual(rejected["status"], "REJECTED")
        self.reviewer.assert_not_called()
        self.assertEqual(self.github.writes, 0)

    def test_worker_retries_pr_creation_after_second_review(self):
        row = self.repo.get(self.patch_id)
        row["status"] = "READY_FOR_PR"
        row["payload"]["ai_review"] = {"verdict": "APPROVE", "summary": "검증 통과", "concerns": []}
        self.repo._store(row)
        self.github.check_run = None
        with patch.object(self.github, "create_pr", side_effect=[
            PatchError("GITHUB_API_FAILED", "temporary", 502),
            {"number": 42, "url": "https://github.com/org/repo/pull/42"},
        ]) as create_pr:
            run_once(self.flow)
            pending = self.repo.get(self.patch_id)
            self.assertEqual(pending["status"], "READY_FOR_PR")
            self.assertEqual(pending["payload"]["github_pr"]["branch"], f"ai-patch/{self.patch_id}")
            run_once(self.flow)
            self.assertEqual(create_pr.call_count, 2)
        published = self.repo.get(self.patch_id)
        self.assertEqual(published["status"], "CHECKS_RUNNING")
        self.assertEqual(published["payload"]["github_pr"]["number"], 42)
        self.assertEqual(self.github.writes, 1)

    def test_worker_respects_disabled_github_writes(self):
        row = self.repo.get(self.patch_id)
        row["status"] = "READY_FOR_PR"
        row["payload"]["ai_review"] = {"verdict": "APPROVE", "summary": "검증 통과", "concerns": []}
        self.repo._store(row)
        with patch.dict(os.environ, {"PATCH_ENABLE_GITHUB_WRITES": "false"}):
            run_once(self.flow)
        self.assertEqual(self.repo.get(self.patch_id)["status"], "READY_FOR_PR")
        self.assertEqual(self.github.writes, 0)

    def test_reject_and_unapproved_block_pr(self):
        self.reviewer.return_value = {"verdict": "REJECT", "summary": "위험", "concerns": ["과도한 변경"]}
        self.flow.start_review(self.patch_id, "operator")
        self.assertEqual(self.repo.get(self.patch_id)["status"], "AI_REJECTED")
        self.assertEqual(self.github.writes, 0)
        with self.assertRaises(PatchError): self.flow.publish(self.patch_id, "operator")
        row = self.repo.get(self.patch_id)
        row["status"] = "AWAITING_FIRST_APPROVAL"; self.repo._store(row)
        with self.assertRaises(PatchError): self.flow.start_review(self.patch_id, "operator")

    def test_uncertain_review_is_distinct_and_cannot_publish(self):
        self.reviewer.return_value = {"verdict": "NEEDS_HUMAN_REVIEW", "summary": "대상 연결 불명",
                                      "concerns": ["sg-one의 Terraform state 연결 확인 필요"]}
        self.flow.start_review(self.patch_id, "operator")
        row = self.repo.get(self.patch_id)
        self.assertEqual(row["status"], "AI_NEEDS_HUMAN_REVIEW")
        self.assertEqual(self.github.writes, 0)
        with self.assertRaises(PatchError):
            self.flow.publish(self.patch_id, "operator")

    def test_human_approval_of_uncertain_review_advances_to_checks(self):
        self.reviewer.return_value = {"verdict": "NEEDS_HUMAN_REVIEW", "summary": "HTTP 조건 미해결",
                                      "concerns": ["HTTPS 리스너 부재"], "model": "claude"}
        self.flow.start_review(self.patch_id, "operator")
        row = self.repo.get(self.patch_id)
        approved = self.flow.decide_human_review(self.patch_id, {
            "decision": "approve", "review_hash": human_review_digest(row), "reviewed": True,
            "note": "HTTP 조건은 남아 있으며 별도 HTTPS 조치가 필요함을 확인"}, "operator")
        self.assertEqual(approved["status"], "CHECKS_RUNNING")
        self.assertEqual(approved["payload"]["ai_review"]["verdict"], "NEEDS_HUMAN_REVIEW")
        human = approved["payload"]["human_review_approval"]
        self.assertEqual(human["event"], "HUMAN_REVIEW_APPROVED")
        self.assertEqual(human["actor"], "operator")
        self.assertEqual(self.github.writes, 2)
        self.assertIsNone(approved["payload"]["deployment"])
        self.assertEqual(self.flow.refresh_checks(self.patch_id, "operator")["status"],
                         "AWAITING_FINAL_APPROVAL")
        self.assertEqual(self.report_final.call_args.args[0]["payload"]["human_review_approval"], human)

    def test_human_review_requires_bound_decision(self):
        self.reviewer.return_value = {"verdict": "NEEDS_HUMAN_REVIEW", "summary": "추가 확인",
                                      "concerns": ["확인 필요"]}
        self.flow.start_review(self.patch_id, "operator")
        row = self.repo.get(self.patch_id)
        review_hash = human_review_digest(row)
        for actor, body in [
            ("operator", {"decision": "approve", "review_hash": "wrong",
                          "reviewed": True, "note": "확인"}),
            ("operator", {"decision": "approve", "review_hash": review_hash,
                          "reviewed": False, "note": "확인"}),
            ("operator", {"decision": "approve", "review_hash": review_hash,
                          "reviewed": True, "note": " "}),
        ]:
            with self.assertRaises(PatchError):
                self.flow.decide_human_review(self.patch_id, body, actor)
        self.assertEqual(self.github.writes, 0)
        self.assertEqual(self.repo.get(self.patch_id)["status"], "AI_NEEDS_HUMAN_REVIEW")
        changed = self.repo.get(self.patch_id)
        changed["payload"]["ai_review"]["concerns"].append("새 우려사항")
        self.repo._store(changed)
        with self.assertRaises(PatchError):
            self.flow.decide_human_review(self.patch_id, {
                "decision": "approve", "review_hash": review_hash,
                "reviewed": True, "note": "확인"}, "operator")
        self.assertEqual(self.github.writes, 0)

    def test_human_review_rejection_stops_patch(self):
        self.reviewer.return_value = {"verdict": "NEEDS_HUMAN_REVIEW", "summary": "추가 확인",
                                      "concerns": ["확인 필요"]}
        self.flow.start_review(self.patch_id, "operator")
        row = self.repo.get(self.patch_id)
        rejected = self.flow.decide_human_review(self.patch_id, {
            "decision": "reject", "review_hash": human_review_digest(row),
            "reviewed": True, "note": "현재 변경만으로는 불충분"}, "reviewer")
        self.assertEqual(rejected["status"], "AI_HUMAN_REJECTED")
        self.assertEqual(self.github.writes, 0)
        with self.assertRaises(PatchError):
            self.flow.publish(self.patch_id, "operator")

    def test_changed_code_invalidates_review(self):
        row = self.repo.get(self.patch_id)
        row["payload"]["files"][0]["proposed_content"] += "# altered"
        self.repo._store(row)
        with self.assertRaises(PatchError): self.flow.start_review(self.patch_id, "operator")
        self.reviewer.assert_not_called()

    def test_check_failure_or_missing_manifest_blocks_report(self):
        self.stage_checks()
        self.github.check_run["conclusion"] = "failure"
        self.assertEqual(self.flow.refresh_checks(self.patch_id, "operator")["status"], "CHECKS_FAILED")
        self.report_final.assert_not_called()
        with self.assertRaises(PatchError): self.flow.decide_final(self.patch_id, {}, "reviewer")

    def test_plan_manifest_rejects_resource_addresses(self):
        self.stage_checks()
        manifest = self.github.artifact_manifest(501, self.patch_id)
        manifest["plan_summary"]["resources"]["update"] = ["aws_s3_bucket.private_address"]
        self.github.artifact_manifest = Mock(return_value=manifest)
        self.assertEqual(self.flow.refresh_checks(self.patch_id, "operator")["status"], "CHECKS_FAILED")
        self.report_final.assert_not_called()

    def test_changed_pr_head_blocks_check_acceptance(self):
        self.stage_checks(); self.github.head = "f" * 40
        with self.assertRaises(PatchError): self.flow.refresh_checks(self.patch_id, "operator")

    def test_final_approval_bound_to_plan_and_report(self):
        row = self.stage_final()
        with self.assertRaises(PatchError): self.flow.decide_final(self.patch_id,
            {"decision": "approve", "approval_hash": "wrong", "reviewed": True}, "reviewer")
        approved = self.flow.decide_final(self.patch_id, {"decision": "approve",
            "approval_hash": approval_digest(row), "reviewed": True}, "reviewer")
        self.assertEqual(approved["status"], "DEPLOYING")
        self.assertEqual(len(self.github.dispatches), 1)

    def test_final_approval_still_requires_other_person(self):
        row = self.stage_final()
        with self.assertRaises(PatchError) as error:
            self.flow.decide_final(self.patch_id, {"decision": "approve",
                "approval_hash": approval_digest(row), "reviewed": True}, "operator")
        self.assertEqual(error.exception.code, "SELF_APPROVAL")
        self.assertEqual(self.repo.get(self.patch_id)["status"], "AWAITING_FINAL_APPROVAL")

    def test_ready_pr_before_approval_requires_new_validation(self):
        row = self.stage_final()
        self.github.pr_state = lambda number: {"state": "open", "draft": False,
            "head": {"sha": self.github.head}, "base": {"ref": "wonny"}}
        with self.assertRaises(PatchError):
            self.flow.decide_final(self.patch_id, {"decision": "approve",
                "approval_hash": approval_digest(row), "reviewed": True}, "reviewer")
        self.assertEqual(self.repo.get(self.patch_id)["status"], "REVALIDATION_REQUIRED")
        self.assertEqual(self.github.dispatches, [])

    def test_rejection_blocks_deployment(self):
        row = self.stage_final()
        rejected = self.flow.decide_final(self.patch_id, {"decision": "reject", "note": "영향 검토",
            "approval_hash": approval_digest(row), "reviewed": True}, "reviewer")
        self.assertEqual(rejected["status"], "FINAL_REJECTED")
        with self.assertRaises(PatchError): self.flow.start_deploy(self.patch_id, "operator")

    def test_disabled_apply_and_changed_base_never_dispatch(self):
        row = self.stage_final()
        with patch.dict(os.environ, {"PATCH_ENABLE_TERRAFORM_APPLY": "false"}):
            with self.assertRaises(PatchError):
                self.flow.decide_final(self.patch_id, {"decision": "approve",
                    "approval_hash": approval_digest(row), "reviewed": True}, "reviewer")
        self.assertEqual(self.repo.get(self.patch_id)["status"], "AWAITING_FINAL_APPROVAL")
        self.github.base = "f" * 40
        with self.assertRaises(PatchError):
            self.flow.decide_final(self.patch_id, {"decision": "approve",
                "approval_hash": approval_digest(row), "reviewed": True}, "reviewer")
        self.assertEqual(self.github.dispatches, [])

    def test_signed_exact_plan_and_duplicate_deploy_block(self):
        self.approve_final()
        row = self.repo.get(self.patch_id)
        self.assertEqual(row["status"], "DEPLOYING")
        self.assertEqual(self.repo.lock, self.patch_id)
        claims = verify(self.github.dispatches[0][1])
        self.assertEqual(claims["plan_sha256"], "d" * 64)
        with self.assertRaises(PatchError): self.flow.start_deploy(self.patch_id, "operator")
        with self.assertRaises(PatchError): verify(self.github.dispatches[0][1] + "x")
        with self.assertRaises(PatchError): verify(self.github.dispatches[0][1], now=int(time.time()) + 901)

    def test_separate_worker_dispatches_final_approval_once(self):
        self.approve_final()
        self.assertEqual(len(self.github.dispatches), 1)
        run_once(self.flow)
        run_once(self.flow)
        self.assertEqual(len(self.github.dispatches), 1)
        self.assertEqual(self.repo.get(self.patch_id)["status"], "DEPLOYING")

    def test_separate_worker_records_checks_without_open_browser(self):
        self.stage_checks()
        run_once(self.flow)
        self.assertEqual(self.repo.get(self.patch_id)["status"], "AWAITING_FINAL_APPROVAL")

    def test_failed_apply_is_retained_and_unlocks(self):
        self.approve_final()
        self.github.deploy_run = {"id": 601, "html_url": "https://github.com/org/repo/actions/runs/601",
                                  "status": "completed", "conclusion": "failure", "updated_at": "2026-01-01T00:00:00Z"}
        row = self.flow.refresh_deploy(self.patch_id, "operator")
        self.assertEqual(row["status"], "DEPLOY_FAILED")
        self.assertEqual(row["payload"]["deployment"]["status"], "FAILED")
        self.assertIsNone(self.repo.lock)

    def test_successful_apply_with_fail_rediagnosis_is_not_remediated(self):
        self.approve_final()
        self.github.deploy_run = {"id": 601, "html_url": "https://github.com/org/repo/actions/runs/601",
                                  "status": "completed", "conclusion": "success", "updated_at": "2026-01-01T00:00:00Z"}
        with patch("services.patch_workflow.collect_aws_state", return_value={}), patch(
                "services.patch_workflow.diagnose_aws_state", return_value={"results": [
                    {"rule_id": "3.7", "status": "FAIL", "current_value": "still public"}]}):
            row = self.flow.refresh_deploy(self.patch_id, "operator")
        self.assertEqual(row["status"], "NOT_REMEDIATED")
        self.assertEqual(row["payload"]["deployment"]["status"], "SUCCESS")
        self.assertFalse(row["payload"]["rediagnosis"]["results"][0]["verified"])

    def test_global_lock_separates_patches(self):
        row = self.stage_final()
        self.repo.acquire_deploy_lock("another")
        approved = self.flow.decide_final(self.patch_id, {"decision": "approve",
            "approval_hash": approval_digest(row), "reviewed": True}, "reviewer")
        self.assertEqual(approved["status"], "FINAL_APPROVED")
        self.assertIn("deployment_start_error", approved)
        self.assertEqual(self.github.dispatches, [])
        self.repo.release_deploy_lock("another")
        run_once(self.flow)
        self.assertEqual(len(self.github.dispatches), 1)


class PatchRoutesTest(unittest.TestCase):
    def test_approval_inbox_is_approver_only(self):
        app.app.config.update(TESTING=True, SECRET_KEY="route-inbox-test")
        client = app.app.test_client()
        service = app.app.extensions["terraform_patches"]
        with patch.object(service.repo, "approval_inbox", return_value=[{"id": "patch-1"}]) as inbox:
            with client.session_transaction() as session:
                session.update(authenticated=True, role="관리자", username="operator")
            self.assertEqual(client.get("/api/ai-actions/patches/approval-inbox").status_code, 403)
            inbox.assert_not_called()
            with client.session_transaction() as session:
                session.update(authenticated=True, role="승인자", username="reviewer")
            response = client.get("/api/ai-actions/patches/approval-inbox")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json["patches"], [{"id": "patch-1"}])

    def test_approval_inbox_requires_both_reviews_and_all_github_passes(self):
        checks = {name: {"status": "PASS"} for name in CHECK_NAMES}
        valid = {"ai_review": {"verdict": "APPROVE"}, "checks": {"results": checks},
                 "final_report": {"version": "final"}, "findings": [{"rule_id": "3.7"}]}
        failed = {**valid, "checks": {"results": {**checks, "plan": {"status": "FAIL"}}}}
        rejected = {**valid, "ai_review": {"verdict": "REJECT"}}
        connection = MagicMock()
        connection.__enter__.return_value = connection
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchall.return_value = [
            {"id": key, "requested_by": "operator", "updated_at": "now", "payload_encrypted": payload}
            for key, payload in (("valid", valid), ("failed", failed), ("rejected", rejected))]
        with patch("services.patch_repository.get_connection", return_value=connection), patch(
                "services.patch_repository.unseal", side_effect=lambda value: value):
            result = PatchRepository().approval_inbox()
        self.assertEqual([item["id"] for item in result], ["valid"])

    def test_human_review_route_exposes_binding_only_to_admin(self):
        app.app.config.update(TESTING=True, SECRET_KEY="route-review-test")
        client = app.app.test_client()
        patch_id = "11111111-1111-1111-1111-111111111111"
        row = {"id": patch_id, "status": "AI_NEEDS_HUMAN_REVIEW", "content_hash": "a" * 64,
               "payload": {"ai_review": {"verdict": "NEEDS_HUMAN_REVIEW",
                                         "summary": "확인 필요", "concerns": ["미해결 조건"]}}}
        service = app.app.extensions["terraform_patches"]
        with patch.object(service.repo, "get", return_value=row), patch.object(
                service, "decide_human_review", return_value=row) as decide:
            with client.session_transaction() as session:
                session.update(authenticated=True, role="관리자", username="operator")
            detail = client.get(f"/api/ai-actions/patches/{patch_id}").get_json()
            self.assertEqual(detail["review_hash"], human_review_digest(row))
            body = {"decision": "approve", "review_hash": detail["review_hash"],
                    "reviewed": True, "note": "우려사항 확인"}
            self.assertEqual(client.post(f"/api/ai-actions/patches/{patch_id}/human-review",
                                         json=body).status_code, 200)
            decide.assert_called_once_with(patch_id, body, "operator")
            with client.session_transaction() as session:
                session.update(authenticated=True, role="승인자", username="reviewer")
            self.assertEqual(client.post(f"/api/ai-actions/patches/{patch_id}/human-review",
                                         json=body).status_code, 403)

    def test_final_approval_route_remains_approver_only(self):
        app.app.config.update(TESTING=True, SECRET_KEY="route-final-test")
        client = app.app.test_client()
        patch_id = "11111111-1111-1111-1111-111111111111"
        service = app.app.extensions["terraform_patches"]
        with patch.object(service, "decide_final", return_value={"status": "FINAL_APPROVED"}) as decide:
            with client.session_transaction() as session:
                session.update(authenticated=True, role="관리자", username="operator")
            self.assertEqual(client.post(f"/api/ai-actions/patches/{patch_id}/final-approval",
                                         json={"decision": "approve"}).status_code, 403)
            with client.session_transaction() as session:
                session.update(authenticated=True, role="승인자", username="reviewer")
            self.assertEqual(client.post(f"/api/ai-actions/patches/{patch_id}/final-approval",
                                         json={"decision": "approve"}).status_code, 200)
            decide.assert_called_once()

    def test_download_uses_saved_diff_and_auth(self):
        env = patch.dict(os.environ, {"PATCH_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        app.app.config.update(TESTING=True, SECRET_KEY="route-test")
        client = app.app.test_client()
        with client.session_transaction() as session:
            session.update(authenticated=True, role="관리자", username="operator")
        patch_id = "11111111-1111-1111-1111-111111111111"
        row = {"id": patch_id, "status": "REJECTED",
               "payload": {"files": [{"diff": "--- a/x\n+++ b/x\n-old\n+new\n"}]}}
        service = app.app.extensions["terraform_patches"]
        with patch.object(service.repo, "get", return_value=row):
            response = client.get(f"/api/ai-actions/patches/{patch_id}/download/patch")
            self.assertEqual(response.status_code, 200)
            self.assertIn("+new", response.get_data(as_text=True))
            self.assertEqual(response.headers["Cache-Control"], "no-store")
        with client.session_transaction() as session: session.clear()
        self.assertEqual(client.get(f"/api/ai-actions/patches/{patch_id}/download/patch").status_code, 401)
