"""Phase-1 integration tests: real service/API, isolated GitHub/AI/DB adapters."""
import copy
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography.fernet import Fernet

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app
from services.patch_security import PatchError, check_sensitive, seal, unseal, safe_path
from services.terraform_patch_service import TerraformPatches, digest
from services.terraform_remediation_service import _unified_diff, validate_change_report

ORIGINAL = 'resource "aws_s3_bucket" "example" {\n  force_destroy = true\n}\n'
PROPOSED = ORIGINAL.replace("true", "false")


class MemoryRepository:
    def __init__(self):
        self.rows = {}
        self.results = {"results": [
            {"rule_id": "3.7", "status": "FAIL", "reason": "public", "resource_ids": ["bucket-example"]},
            {"rule_id": "4.3", "status": "FAIL", "reason": "encryption", "resource_ids": ["bucket-example"]},
            {"rule_id": "1.1", "status": "PASS"},
        ]}

    def diagnosis(self, run_id):
        if run_id != 7:
            raise PatchError("INVALID_DIAGNOSIS", "missing")
        return copy.deepcopy(self.results)

    def insert(self, value):
        self._store(value)

    def _store(self, value):
        row = copy.deepcopy(value)
        row["payload_encrypted"] = seal(row.pop("payload"))
        self.rows[row["id"]] = row

    def get(self, patch_id):
        if patch_id not in self.rows:
            raise PatchError("NOT_FOUND", "missing", 404)
        row = copy.deepcopy(self.rows[patch_id])
        row["payload"] = unseal(row.pop("payload_encrypted"))
        return row

    def save(self, value, expected_status):
        old = self.rows[value["id"]]
        if old["status"] != expected_status or old["revision"] != value["revision"]:
            raise PatchError("STALE_PATCH", "changed", 409)
        value["revision"] += 1
        self._store(value)

    def list(self, limit, offset):
        return [{key: r[key] for key in ("id", "status", "diagnosis_run_id", "requested_by")}
                for r in list(self.rows.values())[offset:offset + limit]]


def report_for(**kwargs):
    return {"summary": "S3 변경", "changes": [
        {"file_path": f["file_path"], "evidence": next(line for line in f["diff"].splitlines()
          if line.startswith("+") and not line.startswith("+++")), "explanation": "설정 변경"}
        for f in kwargs["files"] if f["diff"]], "risks": ["plan 미실행"], "checks": ["독립 검증 필요"],
        "impact": "Plan 이후 확인", "service_disruption": "미확인", "resource_replacement": "미확인"}


class AIActionRouteTest(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {"PATCH_ENCRYPTION_KEY": Fernet.generate_key().decode(),
                                          "OPENAI_API_KEY": "test-key", "ANTHROPIC_API_KEY": ""})
        self.env.start()
        self.addCleanup(self.env.stop)
        app.app.config.update(TESTING=True, SECRET_KEY="test-only")
        self.client = app.app.test_client()
        self.repo = MemoryRepository()
        self.source = Mock()
        self.source.terraform_paths.return_value = ("a" * 40, [
            "modules/security/kms_secrets_storage.tf", "modules/security/a.tf",
            "modules/security/b.tf"])
        self.source.snapshot.side_effect = lambda paths, check_secrets=True: {
            "repository": "org/repo", "ref": "main", "commit_sha": "a" * 40,
            "files": [{"file_path": p, "original_content": ORIGINAL, "blob_sha": "b" * 40}
                      for p in sorted(set(paths))]}
        self.gen = Mock(return_value={"proposed_content": PROPOSED, "diff": "UNTRUSTED AI DIFF"})
        self.report = Mock(side_effect=report_for)
        self.service = app.app.extensions["terraform_patches"]
        self.mocks = [patch.object(self.service, key, value) for key, value in {
            "repo": self.repo, "source_factory": lambda: self.source, "generate": self.gen, "report": self.report,
            "submit": lambda work: work()}.items()]
        for mock in self.mocks:
            mock.start()
            self.addCleanup(mock.stop)
        self.state = patch("services.terraform_mapping.state_index", return_value={
            "bucket-example": {("aws_s3_bucket", "example", "module.security")}})
        self.state.start()
        self.addCleanup(self.state.stop)
        self.reviewer = patch("services.terraform_remediation_service.review_terraform_fix")
        self.rev = self.reviewer.start()
        self.addCleanup(self.reviewer.stop)
        self.login("관리자", "operator")

    def login(self, role, username):
        with self.client.session_transaction() as session:
            session.update(authenticated=True, role=role, username=username)

    def create(self, **over):
        body = {"diagnosis_run_id": 7, "source_commit_sha": "a" * 40,
                "mapping": {"3.7": ["modules/security/kms_secrets_storage.tf"],
                            "4.3": ["modules/security/kms_secrets_storage.tf"]}}
        body.update(over)
        return self.client.post("/api/ai-actions/patches", json=body)

    def generated(self):
        row = self.create().get_json()
        return self.client.post("/api/ai-actions/terraform-fix", json={"patch_id": row["id"]}).get_json()

    def decision(self, row, **over):
        body = {"decision": "approve", "content_hash": row["content_hash"], "reviewed": True, "note": ""}
        body.update(over)
        return self.client.post(f'/api/ai-actions/patches/{row["id"]}/first-approval', json=body)

    def test_integrates_same_file_and_never_runs_second_ai(self):
        row = self.generated()
        self.assertEqual(row["status"], "AWAITING_FIRST_APPROVAL")
        self.gen.assert_called_once()
        self.assertEqual(len(self.gen.call_args.kwargs["finding"]["findings"]), 2)
        self.assertEqual(set(self.gen.call_args.kwargs["finding"]["target_rule_ids"]), {"3.7", "4.3"})
        self.assertEqual(row["payload"]["files"][0]["diff"], _unified_diff(ORIGINAL, PROPOSED, "modules/security/kms_secrets_storage.tf"))
        self.assertEqual(row["content_hash"], digest(row["payload"]))
        self.rev.assert_not_called()
        self.assertIsNone(row["payload"]["ai_review"])

    def test_mapping_preview_binds_patch_to_gyu_commit(self):
        preview = self.client.post("/api/ai-actions/mapping-preview",
                                   json={"diagnosis_run_id": 7, "rule_ids": ["3.7", "4.3"]})
        self.assertEqual(preview.status_code, 200)
        self.assertEqual(preview.get_json()["commit_sha"], "a" * 40)
        self.assertEqual(self.create(source_commit_sha="b" * 40).status_code, 409)
        self.assertEqual(self.create(mapping={"3.7": ["modules/unknown.tf"]}).status_code, 400)

    def test_mapping_preview_hides_non_matched_fail_items(self):
        self.repo.results = {"results": [
            {"rule_id": "3.7", "status": "FAIL", "reason": "public", "resource_ids": ["bucket-example"]},
            {"rule_id": "4.3", "status": "FAIL", "reason": "encryption"},
            {"rule_id": "1.6", "status": "FAIL", "reason": "root usage"},
            {"rule_id": "1.1", "status": "PASS"},
        ]}
        preview = self.client.post("/api/ai-actions/mapping-preview",
                                   json={"diagnosis_run_id": 7, "rule_ids": ["3.7", "4.3", "1.6"]})
        self.assertEqual(preview.status_code, 200)
        mapping = preview.get_json()["mapping"]
        self.assertEqual(list(mapping.keys()), ["3.7"])
        self.assertEqual(mapping["3.7"]["status"], "MATCHED")

    def test_only_matched_fail_items_can_create_patch(self):
        self.repo.results = {"results": [
            {"rule_id": "3.7", "status": "FAIL", "reason": "public", "resource_ids": ["bucket-example"]},
            {"rule_id": "4.3", "status": "FAIL", "reason": "encryption"},
            {"rule_id": "1.6", "status": "FAIL", "reason": "root usage"},
            {"rule_id": "1.1", "status": "PASS"},
        ]}
        response = self.client.post("/api/ai-actions/patches", json={
            "diagnosis_run_id": 7,
            "source_commit_sha": "a" * 40,
            "mapping": {
                "3.7": ["modules/security/kms_secrets_storage.tf"],
                "4.3": ["modules/security/kms_secrets_storage.tf"],
            },
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "AUTO_ACTION_UNAVAILABLE")

    def test_not_terraform_rule_cannot_create_patch(self):
        response = self.create(mapping={"1.6": ["modules/compute/iam.tf"]})
        self.assertEqual((response.status_code, response.get_json()["error"]), (400, "NOT_TERRAFORM_FIXABLE"))
        self.source.snapshot.assert_not_called()

    def test_unmatched_fail_and_unverified_file_cannot_create_patch(self):
        self.repo.results["results"].append({"rule_id": "4.2", "status": "FAIL", "resource_ids": ["db-1"]})
        response = self.create(mapping={"4.2": ["modules/security/a.tf"]})
        self.assertEqual((response.status_code, response.get_json()["error"]), (400, "AUTO_ACTION_UNAVAILABLE"))
        with patch("services.terraform_mapping.state_index", return_value={}):
            response = self.create(mapping={"3.7": ["modules/security/a.tf"]})
        self.assertEqual((response.status_code, response.get_json()["error"]), (400, "AUTO_ACTION_UNAVAILABLE"))
        self.assertEqual(self.repo.rows, {})

    def test_matched_rule_cannot_use_a_different_unmatched_file(self):
        def snapshot(paths, check_secrets=True):
            return {"repository": "org/repo", "ref": "main", "commit_sha": "a" * 40,
                    "files": [{"file_path": path, "original_content":
                               ORIGINAL if path.endswith("kms_secrets_storage.tf") else
                               'resource "aws_s3_bucket" "other" {}\n'} for path in paths]}
        self.source.snapshot.side_effect = snapshot
        response = self.create(mapping={"3.7": ["modules/security/a.tf"]})
        self.assertEqual((response.status_code, response.get_json()["error"]), (400, "AUTO_ACTION_UNAVAILABLE"))
        self.assertEqual(self.repo.rows, {})

    def test_state_lookup_failure_is_not_an_empty_mapping(self):
        with patch("services.terraform_mapping.state_index", side_effect=PatchError(
                "STATE_UNAVAILABLE", "State 조회 실패", 502)):
            response = self.client.post("/api/ai-actions/mapping-preview",
                json={"diagnosis_run_id": 7, "rule_ids": ["3.7"]})
            self.assertEqual((response.status_code, response.get_json()["error"]), (502, "STATE_UNAVAILABLE"))
            response = self.create(mapping={"3.7": ["modules/security/a.tf"]})
            self.assertEqual((response.status_code, response.get_json()["error"]), (502, "STATE_UNAVAILABLE"))

    def test_background_work_returns_before_ai_and_can_be_polled(self):
        tasks = []
        with patch.object(self.service, "submit", side_effect=tasks.append):
            row = self.create().get_json()
            self.assertEqual(row["status"], "FETCHING")
            self.source.snapshot.assert_called_once()
            tasks.pop()()
            response = self.client.post("/api/ai-actions/terraform-fix", json={"patch_id": row["id"]})
            self.assertEqual(response.get_json()["status"], "GENERATING")
            self.gen.assert_not_called()
            tasks.pop()()
            result = self.client.get(f'/api/ai-actions/patches/{row["id"]}').get_json()
            self.assertEqual(result["status"], "AWAITING_FIRST_APPROVAL")

    def test_approval_persisted_without_followup_execution(self):
        row = self.generated()
        self.login("승인자", "reviewer")
        response = self.decision(row)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "FIRST_APPROVED")
        self.assertEqual(data["payload"]["first_approval"]["content_hash"], row["content_hash"])
        self.assertEqual(data["payload"]["first_approval"]["actor"], "reviewer")
        self.rev.assert_not_called()
        self.assertEqual(self.decision(row).status_code, 409)
        self.assertEqual(self.client.get(f'/api/ai-actions/patches/{row["id"]}').get_json()["status"], "FIRST_APPROVED")

    def test_rejection_remains_in_history(self):
        row = self.generated()
        self.login("승인자", "reviewer")
        self.assertEqual(self.decision(row, decision="reject").status_code, 400)
        self.assertEqual(self.decision(row, decision="reject", note="범위 재검토").get_json()["status"], "REJECTED")
        self.assertEqual(self.client.get("/api/ai-actions/patches").get_json()["patches"][0]["status"], "REJECTED")

    def test_admin_cannot_approve(self):
        self.assertEqual(self.decision(self.generated()).status_code, 403)

    def test_self_approval_blocked_even_after_role_change(self):
        row = self.generated()
        self.login("승인자", "operator")
        self.assertEqual(self.decision(row).status_code, 403)

    def test_approver_cannot_generate(self):
        row = self.create().get_json()
        self.login("승인자", "reviewer")
        self.assertEqual(self.create().status_code, 403)
        self.assertEqual(self.client.post("/api/ai-actions/terraform-fix", json={"patch_id": row["id"]}).status_code, 403)

    def test_requires_login_and_reader_role(self):
        with self.client.session_transaction() as session:
            session.clear()
        self.assertEqual(self.client.get("/api/ai-actions/patches").status_code, 401)
        self.login("관찰자", "observer")
        self.assertEqual(self.client.get("/api/ai-actions/patches").status_code, 403)

    def test_forged_findings_and_paths_are_rejected(self):
        for mapping in ({}, {"1.1": ["modules/security/a.tf"]}, {"fake": ["modules/security/a.tf"]}, {"3.7": ["../a.tf"]},
                        {"3.7": [".terraform/a.tf"]}, {"3.7": ["a.tfvars"]}, {"3.7": ["https://x/a.tf"]},
                        {"3.7": []}, {"3.7": "a.tf"}):
            with self.subTest(mapping=mapping):
                self.assertEqual(self.create(mapping=mapping).status_code, 400)
        self.gen.assert_not_called()
        self.source.snapshot.assert_not_called()

    def test_legacy_pasted_code_cannot_bypass_workflow(self):
        result = self.client.post("/api/ai-actions/terraform-fix",
                                  json={"finding": {"status": "FAIL"}, "file_content": ORIGINAL, "file_path": "a.tf"})
        self.assertEqual(result.status_code, 400)
        self.assertEqual(result.get_json()["error"], "PATCH_REQUIRED")
        self.rev.assert_not_called()

    def test_unknown_and_invalid_requests(self):
        self.assertEqual(self.create(diagnosis_run_id=100).status_code, 400)
        self.assertEqual(self.client.post("/api/ai-actions/patches", json=[]).status_code, 400)
        self.assertEqual(self.client.get("/api/ai-actions/patches?offset=x").status_code, 400)
        self.assertEqual(self.client.get("/api/ai-actions/patches/00000000-0000-0000-0000-000000000000").status_code, 404)

    def test_stale_hash_and_tampered_content_cannot_be_approved(self):
        row = self.generated()
        self.login("승인자", "reviewer")
        self.assertEqual(self.decision(row, content_hash="stale").status_code, 409)
        edited = self.repo.get(row["id"])
        edited["payload"]["files"][0]["proposed_content"] += "\n# changed"
        self.repo._store(edited)
        self.assertEqual(self.decision(row).status_code, 409)

    def test_review_acknowledgement_required(self):
        row = self.generated()
        self.login("승인자", "reviewer")
        self.assertEqual(self.decision(row, reviewed=False).status_code, 400)

    def test_no_changes_is_retained_failure(self):
        self.gen.return_value = {"proposed_content": ORIGINAL}
        row = self.generated()
        self.assertEqual(row["status"], "FAILED")
        self.assertEqual(row["payload"]["error"]["code"], "NO_CHANGES")
        self.report.assert_not_called()

    def test_provider_errors_are_not_exposed(self):
        self.gen.side_effect = RuntimeError("secret-provider-content")
        row = self.generated()
        self.assertEqual(row["status"], "FAILED")
        self.assertNotIn("secret-provider-content", json.dumps(row))
        self.assertEqual(len(self.repo.list(50, 0)), 1)

    def test_report_evidence_must_match_real_diff(self):
        self.report.return_value = {"summary": "wrong", "changes": [{"file_path": "modules/security/kms_secrets_storage.tf",
            "evidence": "+ invented", "explanation": "wrong"}], "risks": [], "checks": []}
        self.report.side_effect = None
        self.assertEqual(self.generated()["status"], "FAILED")

    def test_github_error_is_retained(self):
        original_snapshot = self.source.snapshot.side_effect
        calls = 0
        def snapshot_then_error(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls > 1:
                raise PatchError("GITHUB_READ_FAILED", "조회 실패", 502)
            return original_snapshot(*args, **kwargs)
        self.source.snapshot.side_effect = snapshot_then_error
        row = self.create().get_json()
        self.assertEqual(row["status"], "FAILED")
        self.assertEqual(row["payload"]["error"]["code"], "GITHUB_READ_FAILED")

    def test_generated_secret_never_stored_or_reported(self):
        self.gen.return_value = {"proposed_content": 'password = "do-not-leak"'}
        row = self.generated()
        self.assertEqual(row["status"], "FAILED")
        self.assertNotIn("do-not-leak", json.dumps(row))
        self.report.assert_not_called()

    def test_multiple_files_are_each_generated_once(self):
        row = self.create(mapping={"3.7": ["modules/security/a.tf", "modules/security/b.tf"], "4.3": ["modules/security/a.tf"]}).get_json()
        result = self.client.post("/api/ai-actions/terraform-fix", json={"patch_id": row["id"]}).get_json()
        self.assertEqual(result["status"], "AWAITING_FIRST_APPROVAL")
        self.assertEqual(self.gen.call_count, 2)
        self.assertEqual(len(result["payload"]["report"]["changes"]), 2)

    def test_generating_twice_or_after_approval_is_blocked(self):
        row = self.generated()
        self.assertEqual(self.client.post("/api/ai-actions/terraform-fix", json={"patch_id": row["id"]}).status_code, 409)
        self.login("승인자", "reviewer")
        self.decision(row)
        self.login("관리자", "operator")
        self.assertEqual(self.client.post("/api/ai-actions/terraform-fix", json={"patch_id": row["id"]}).status_code, 409)
        self.gen.assert_called_once()

    def test_missing_ai_key_keeps_source_ready(self):
        row = self.create().get_json()
        with patch.dict(os.environ, {"OPENAI_API_KEY": ""}):
            self.assertEqual(self.client.post("/api/ai-actions/terraform-fix", json={"patch_id": row["id"]}).status_code, 503)
        self.assertEqual(self.repo.get(row["id"])["status"], "SOURCE_READY")

    def test_missing_encryption_key_fails_before_source_fetch(self):
        with patch.dict(os.environ, {"PATCH_ENCRYPTION_KEY": ""}):
            self.assertEqual(self.create().status_code, 503)
        self.source.snapshot.assert_not_called()

    def test_storage_encrypted_and_responses_not_cached(self):
        response = self.create()
        row = response.get_json()
        stored = json.dumps(self.repo.rows[row["id"]])
        self.assertNotIn("force_destroy", stored)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(unseal(seal({"source": ORIGINAL})), {"source": ORIGINAL})

    def test_optimistic_lock_rejects_stale_writer(self):
        row = self.create().get_json()
        stale = copy.deepcopy(row)
        row["status"] = "GENERATING"
        self.repo.save(row, "SOURCE_READY")
        with self.assertRaises(PatchError):
            self.repo.save(stale, "SOURCE_READY")


class SensitiveInputTest(unittest.TestCase):
    def test_rejects_literals_tokens_and_sensitive_defaults(self):
        for value in ('password = "example"', 'secret_key = "example"', 'token = <<EOF',
                      'variable "password" { default = "example" }',
                      'variable "x" { sensitive = true\n default = "value" }',
                      "AKIA" + "A" * 16, "-----BEGIN RSA PRIVATE KEY-----",
                      "https://user:password@example.com"):
            with self.subTest(value=value), self.assertRaises(PatchError):
                check_sensitive(value)

    def test_allows_imdsv2_http_tokens_but_not_other_token_literals(self):
        # AWS-Security-Infra modules/compute/compute.tf 의 metadata_options 블록
        check_sensitive('metadata_options {\n  http_endpoint = "enabled"\n  http_tokens   = "required"\n}')
        check_sensitive('{"http_tokens": "optional"}')
        for value in ('http_tokens = "s3cr3t-value"', 'api_token = "example"', 'db_password = "example"',
                      'access_token: "example"', 'http_tokens = "required"\npassword = "example"'):
            with self.subTest(value=value), self.assertRaises(PatchError):
                check_sensitive(value)

    def test_allows_secret_references(self):
        check_sensitive('password = var.db_password\nsecret = aws_secretsmanager_secret.db.arn')
        self.assertEqual(safe_path("infra/modules/db/main.tf"), "infra/modules/db/main.tf")

    def test_diff_without_final_newline_is_valid(self):
        diff = _unified_diff("old", "new", "a.tf")
        self.assertIn("-old\n\\ No newline at end of file\n+new\n", diff)


if __name__ == "__main__":
    unittest.main()
