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
from services.terraform_patch_service import TerraformPatches, digest, verified_resource_bindings
from services.terraform_remediation_service import _unified_diff, validate_change_report

ORIGINAL = 'resource "aws_s3_bucket" "example" {\n  force_destroy = true\n}\n'
PROPOSED = ORIGINAL.replace("true", "false")


class MemoryRepository:
    def __init__(self):
        self.rows = {}
        self.results = {"results": [
            {"rule_id": "3.7", "status": "FAIL", "reason": "public"},
            {"rule_id": "4.3", "status": "FAIL", "reason": "encryption"},
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

    def test_not_terraform_rule_cannot_create_patch(self):
        response = self.create(mapping={"1.6": ["modules/compute/iam.tf"]})
        self.assertEqual((response.status_code, response.get_json()["error"]), (400, "NOT_TERRAFORM_FIXABLE"))
        self.source.snapshot.assert_not_called()

    def test_iam_rules_can_be_manually_mapped_to_existing_module_file(self):
        path = "modules/compute/iam.tf"
        self.source.terraform_paths.return_value = ("a" * 40, [path])
        self.repo.results["results"].extend(
            {"rule_id": rule_id, "status": "FAIL", "resource_ids": [f"iam-{rule_id}"]}
            for rule_id in ("1.2", "1.3", "1.4", "1.9")
        )
        self.repo.results["results"] = [
            {**item, "status": "FAIL", "resource_ids": ["iam-1.1"]}
            if item["rule_id"] == "1.1" else item
            for item in self.repo.results["results"]
        ]
        for rule_id in ("1.1", "1.2", "1.3", "1.4", "1.9"):
            with self.subTest(rule_id=rule_id):
                response = self.create(mapping={rule_id: [path]})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.get_json()["status"], "SOURCE_READY")

    def test_background_work_returns_before_ai_and_can_be_polled(self):
        tasks = []
        with patch.object(self.service, "submit", side_effect=tasks.append):
            row = self.create().get_json()
            self.assertEqual(row["status"], "FETCHING")
            self.source.snapshot.assert_not_called()
            tasks.pop()()
            response = self.client.post("/api/ai-actions/terraform-fix", json={"patch_id": row["id"]})
            self.assertEqual(response.get_json()["status"], "GENERATING")
            self.gen.assert_not_called()
            tasks.pop()()
            result = self.client.get(f'/api/ai-actions/patches/{row["id"]}').get_json()
            self.assertEqual(result["status"], "AWAITING_FIRST_APPROVAL")

    def test_approval_persisted_without_followup_execution(self):
        row = self.generated()
        permissions = self.client.get("/api/ai-actions/patches").get_json()
        self.assertTrue(permissions["can_create"])
        self.assertFalse(permissions["can_approve"])
        response = self.decision(row)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "FIRST_APPROVED")
        self.assertEqual(data["payload"]["first_approval"]["content_hash"], row["content_hash"])
        self.assertEqual(data["payload"]["first_approval"]["actor"], "operator")
        self.rev.assert_not_called()
        self.assertEqual(self.decision(row).status_code, 409)
        self.assertEqual(self.client.get(f'/api/ai-actions/patches/{row["id"]}').get_json()["status"], "FIRST_APPROVED")

    def test_rejection_remains_in_history(self):
        row = self.generated()
        self.assertEqual(self.decision(row, decision="reject").status_code, 400)
        self.assertEqual(self.decision(row, decision="reject", note="범위 재검토").get_json()["status"], "REJECTED")
        self.assertEqual(self.client.get("/api/ai-actions/patches").get_json()["patches"][0]["status"], "REJECTED")

    def test_approver_cannot_make_first_decision(self):
        row = self.generated()
        self.login("승인자", "reviewer")
        self.assertEqual(self.decision(row).status_code, 403)

    def test_first_decision_requires_admin_role_even_for_requester(self):
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
        self.assertEqual(self.decision(row, content_hash="stale").status_code, 409)
        edited = self.repo.get(row["id"])
        edited["payload"]["files"][0]["proposed_content"] += "\n# changed"
        self.repo._store(edited)
        self.assertEqual(self.decision(row).status_code, 409)

    def test_review_acknowledgement_required(self):
        row = self.generated()
        self.assertEqual(self.decision(row, reviewed=False).status_code, 400)

    def test_no_changes_is_retained_failure(self):
        self.gen.return_value = {"proposed_content": ORIGINAL}
        row = self.generated()
        self.assertEqual(row["status"], "FAILED")
        self.assertEqual(row["payload"]["error"]["code"], "NO_CHANGES")
        self.report.assert_not_called()

    def test_3_2_state_binding_identifies_selected_security_group_for_generation(self):
        path = "modules/network/security_groups.tf"
        other_path = "modules/network/endpoints.tf"
        original = ('resource "aws_security_group" "shop_alb" {\n'
                    '  ingress { cidr_blocks = ["0.0.0.0/0"] }\n}\n')
        other_original = 'resource "aws_security_group" "vpce" {}\n'
        self.source.terraform_paths.return_value = ("a" * 40, [path, other_path])
        self.source.snapshot.side_effect = lambda paths, check_secrets=True: {
            "repository": "org/repo", "ref": "main", "commit_sha": "a" * 40,
            "files": [{"file_path": other_path, "original_content": other_original, "blob_sha": "c" * 40},
                      {"file_path": path, "original_content": original, "blob_sha": "b" * 40}]}
        self.repo.results = {"results": [{"rule_id": "3.2", "status": "FAIL",
            "resource_ids": ["sg-selected"], "recommendation": "승인된 소스로 제한",
            "evidence": [{"resource": "sg-selected", "value": "0.0.0.0/0"}]}]}
        self.gen.return_value = {"proposed_content": original.replace("0.0.0.0/0", "10.0.0.0/8")}
        with patch("services.terraform_patch_service.state_index", return_value={
                "sg-selected": {("aws_security_group", "shop_alb", "module.network")}}):
            row = self.create(mapping={"3.2": [other_path, path]},
                              remediation_constraints={"3.2": "sg-selected 인바운드 허용 소스 10.0.0.0/8"}).get_json()
        generated = self.client.post("/api/ai-actions/terraform-fix", json={"patch_id": row["id"]}).get_json()
        self.assertEqual(generated["status"], "AWAITING_FIRST_APPROVAL")
        self.gen.assert_called_once()
        binding = self.gen.call_args.kwargs["finding"]["verified_resource_bindings"][0]
        self.assertEqual((binding["resource_id"], binding["resource_name"], binding["module"]),
                         ("sg-selected", "shop_alb", "module.network"))
        self.assertEqual(generated["payload"]["resource_bindings"], [binding])
        untouched = next(file for file in generated["payload"]["files"] if file["file_path"] == other_path)
        self.assertEqual((untouched["proposed_content"], untouched["diff"]), (other_original, ""))

    def test_3_2_no_change_explains_missing_verified_mapping_and_source(self):
        path = "modules/network/security_groups.tf"
        self.source.terraform_paths.return_value = ("a" * 40, [path])
        self.repo.results = {"results": [{"rule_id": "3.2", "status": "FAIL",
            "resource_ids": ["sg-unmanaged"], "evidence": [
                {"resource": "sg-unmanaged", "value": "0.0.0.0/0"}]}]}
        self.gen.return_value = {"proposed_content": ORIGINAL}
        with patch("services.terraform_patch_service.state_index", return_value={}):
            row = self.create(mapping={"3.2": [path]}, remediation_constraints={
                "3.2": "sg-unmanaged 인바운드 소스 10.0.0.0/8"}).get_json()
        generated = self.client.post("/api/ai-actions/terraform-fix", json={"patch_id": row["id"]}).get_json()
        self.assertEqual(generated["payload"]["error"]["code"], "NO_CHANGES")
        self.assertIn("State에서 확인하지 못했습니다", generated["payload"]["error"]["message"])
        self.assertIn("허용 소스", generated["payload"]["error"]["message"])
        self.report.assert_not_called()

    def test_3_2_requires_allowed_source_before_creating_patch(self):
        path = "modules/network/security_groups.tf"
        self.source.terraform_paths.return_value = ("a" * 40, [path])
        self.repo.results = {"results": [{"rule_id": "3.2", "status": "FAIL",
            "resource_ids": ["sg-selected"]}]}
        response = self.create(mapping={"3.2": [path]})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "REMEDIATION_INPUT_REQUIRED")
        self.assertIn("허용", response.get_json()["message"])
        self.source.snapshot.assert_not_called()
        self.gen.assert_not_called()

    def test_3_2_no_change_with_verified_mapping_asks_for_allowed_source(self):
        path = "modules/network/security_groups.tf"
        self.source.terraform_paths.return_value = ("a" * 40, [path])
        self.source.snapshot.side_effect = lambda paths, check_secrets=True: {
            "repository": "org/repo", "ref": "main", "commit_sha": "a" * 40,
            "files": [{"file_path": path,
                       "original_content": 'resource "aws_security_group" "shop_alb" {}\n',
                       "blob_sha": "b" * 40}]}
        self.repo.results = {"results": [{"rule_id": "3.2", "status": "FAIL",
            "resource_ids": ["sg-selected"], "evidence": [
                {"resource": "sg-selected", "value": "0.0.0.0/0"}]}]}
        self.gen.return_value = {"proposed_content": 'resource "aws_security_group" "shop_alb" {}\n'}
        with patch("services.terraform_patch_service.state_index", return_value={
                "sg-selected": {("aws_security_group", "shop_alb", "module.network")}}):
            row = self.create(mapping={"3.2": [path]}, remediation_constraints={
                "3.2": "sg-selected 인바운드 소스 10.0.0.0/8"}).get_json()
        generated = self.client.post("/api/ai-actions/terraform-fix", json={"patch_id": row["id"]}).get_json()
        self.assertEqual(generated["payload"]["error"]["code"], "NO_CHANGES")
        self.assertIn("Source CIDR", generated["payload"]["error"]["message"])

    def test_3_2_binding_never_links_an_unselected_id_or_wrong_file(self):
        files = [{"file_path": "modules/network/security_groups.tf",
                  "original_content": 'resource "aws_security_group" "shop_alb" {}'},
                 {"file_path": "modules/network/endpoints.tf",
                  "original_content": 'resource "aws_security_group" "vpce" {}'}]
        bindings = verified_resource_bindings(files, [
            {"rule_id": "3.2", "resource_ids": ["sg-selected"]}],
            {"3.2": ["modules/network/security_groups.tf"]}, {
                "sg-selected": {("aws_security_group", "shop_alb", "module.network")},
                "sg-unselected": {("aws_security_group", "vpce", "module.network")}})
        self.assertEqual([(item["resource_id"], item["file_path"], item["resource_name"])
                          for item in bindings],
                         [("sg-selected", "modules/network/security_groups.tf", "shop_alb")])

    def test_newline_only_change_is_not_a_security_patch(self):
        self.gen.return_value = {"proposed_content": ORIGINAL.rstrip("\n")}
        row = self.generated()
        self.assertEqual(row["status"], "FAILED")
        self.assertEqual(row["payload"]["error"]["code"], "NO_CHANGES")
        self.report.assert_not_called()

    def test_partial_resource_scope_keeps_only_selected_evidence(self):
        self.repo.results = {"results": [{
            "rule_id": "3.7", "status": "FAIL", "resource_ids": ["sg-one", "sg-two"],
            "evidence": [{"resource": "sg-one", "path": "p1", "value": "v1"},
                         {"resource": "sg-two", "path": "p2", "value": "v2"}],
            "reason": "two resources", "recommendation": "fix both",
        }]}
        response = self.create(mapping={"3.7": ["modules/security/a.tf"]},
                               target_resource_ids={"3.7": ["sg-one"]},
                               remediation_constraints={"3.7": "443/TCP to VPC CIDR"})
        self.assertEqual(response.status_code, 200)
        finding = response.get_json()["payload"]["findings"][0]
        self.assertEqual(finding["resource_ids"], ["sg-one"])
        self.assertEqual([item["resource"] for item in finding["evidence"]], ["sg-one"])
        self.assertEqual(finding["remediation_scope"]["deferred_resource_ids"], ["sg-two"])
        self.assertEqual(finding["remediation_constraints"], "443/TCP to VPC CIDR")
        self.assertEqual(response.get_json()["payload"]["original_findings"][0]["resource_ids"], ["sg-one", "sg-two"])

    def test_4_4_https_exception_defers_listener_but_keeps_s3_patch_scope(self):
        shop_listener = "arn:aws:elasticloadbalancing:ap-northeast-2:123456789012:listener/app/shop/one/two"
        admin_listener = "arn:aws:elasticloadbalancing:ap-northeast-2:123456789012:listener/app/admin/one/two"
        bucket = "wonny-security-logs"
        self.repo.results = {"results": [{"rule_id": "4.4", "status": "FAIL",
            "resource_ids": [shop_listener, bucket, admin_listener],
            "evidence": [{"resource": resource_id, "path": "observed", "value": "HTTP"}
                         for resource_id in (shop_listener, bucket, admin_listener)]}]}
        reason = "도메인과 ACM 인증서 미준비로 HTTPS 전환을 추후 진행"
        response = self.create(mapping={"4.4": ["modules/security/a.tf"]},
                               target_resource_ids={"4.4": [bucket]},
                               https_exception_resource_ids={"4.4": [shop_listener]},
                               https_exception_reasons={"4.4": reason})
        self.assertEqual(response.status_code, 200)
        row = response.get_json()
        finding = row["payload"]["findings"][0]
        scope = finding["remediation_scope"]
        self.assertEqual(scope["selected_resource_ids"], [bucket])
        self.assertEqual(scope["https_exception_resource_ids"], [shop_listener])
        self.assertEqual(scope["https_exception_reason"], reason)
        self.assertEqual(scope["deferred_resource_ids"], [admin_listener])
        self.assertTrue(scope["rule_result_may_remain_fail_due_to_https_exception"])
        self.assertEqual(finding["resource_ids"], [bucket])
        self.assertEqual([item["resource"] for item in finding["evidence"]], [bucket])
        self.assertEqual(row["payload"]["original_findings"][0]["resource_ids"],
                         [shop_listener, bucket, admin_listener])
        self.assertEqual(row["payload"]["audit"][1]["event"], "HTTPS_EXCEPTION_DECLARED")
        before_hash = digest(row["payload"])
        row["payload"]["https_exception_reasons"]["4.4"] = "changed"
        self.assertNotEqual(digest(row["payload"]), before_hash)
        generated = self.client.post("/api/ai-actions/terraform-fix", json={
            "patch_id": row["id"]}).get_json()
        self.assertEqual(generated["status"], "AWAITING_FIRST_APPROVAL")
        context_scope = self.gen.call_args.kwargs["finding"]["findings"][0]["remediation_scope"]
        self.assertEqual(context_scope["selected_resource_ids"], [bucket])
        self.assertEqual(context_scope["https_exception_resource_ids"], [shop_listener])

    def test_3_9_https_exception_keeps_same_alb_selected_for_other_fixes(self):
        alb = "arn:aws:elasticloadbalancing:ap-northeast-2:123456789012:loadbalancer/app/shop/one"
        self.repo.results = {"results": [{"rule_id": "3.9", "status": "FAIL",
            "resource_ids": [alb], "evidence": [{"resource": alb, "path": "listener", "value": "HTTP"}]}]}
        response = self.create(mapping={"3.9": ["modules/security/a.tf"]},
                               target_resource_ids={"3.9": [alb]},
                               https_exception_resource_ids={"3.9": [alb]},
                               https_exception_reasons={"3.9": "인증서 준비 전, 삭제 보호와 헤더 설정은 이번에 조치"})
        self.assertEqual(response.status_code, 200)
        scope = response.get_json()["payload"]["findings"][0]["remediation_scope"]
        self.assertEqual(scope["selected_resource_ids"], [alb])
        self.assertEqual(scope["https_exception_resource_ids"], [alb])
        self.assertEqual(scope["deferred_resource_ids"], [])
        self.assertTrue(scope["rule_result_may_remain_fail_until_deferred_resources_are_fixed"])

    def test_https_exception_rejects_overlap_missing_reason_and_unrelated_rule(self):
        listener = "arn:aws:elasticloadbalancing:ap-northeast-2:123456789012:listener/app/shop/one/two"
        self.repo.results = {"results": [{"rule_id": "4.4", "status": "FAIL",
            "resource_ids": [listener, "bucket"], "evidence": [
                {"resource": listener, "path": "listener", "value": "HTTP"},
                {"resource": "bucket", "path": "policy", "value": "missing"}]}]}
        base = {"mapping": {"4.4": ["modules/security/a.tf"]},
                "https_exception_resource_ids": {"4.4": [listener]}}
        overlap = self.create(**base, target_resource_ids={"4.4": [listener, "bucket"]},
                              https_exception_reasons={"4.4": "cert pending"})
        self.assertEqual(overlap.get_json()["error"], "INVALID_HTTPS_EXCEPTION")
        missing_reason = self.create(**base, target_resource_ids={"4.4": ["bucket"]})
        self.assertEqual(missing_reason.get_json()["error"], "INVALID_HTTPS_EXCEPTION")
        self.repo.results = {"results": [{"rule_id": "3.7", "status": "FAIL",
            "resource_ids": ["bucket"], "evidence": [
                {"resource": "bucket", "path": "policy", "value": "missing"}]}]}
        unrelated = self.create(mapping={"3.7": ["modules/security/a.tf"]},
                                https_exception_resource_ids={"3.7": ["bucket"]},
                                https_exception_reasons={"3.7": "cert pending"})
        self.assertEqual(unrelated.get_json()["error"], "INVALID_HTTPS_EXCEPTION")

    def test_partial_scope_requires_real_diagnosis_evidence(self):
        self.repo.results = {"results": [{"rule_id": "3.7", "status": "FAIL",
            "resource_ids": ["sg-one", "sg-two"], "evidence": [{"resource": "sg-two", "path": "p", "value": "v"}]}]}
        response = self.create(mapping={"3.7": ["modules/security/a.tf"]},
                               target_resource_ids={"3.7": ["sg-one"]})
        self.assertEqual((response.status_code, response.get_json()["error"]), (400, "RESOURCE_EVIDENCE_MISSING"))

    def test_remediation_constraints_reject_credentials(self):
        response = self.create(remediation_constraints={"3.7": 'api_key = "do-not-store-this"'})
        self.assertEqual((response.status_code, response.get_json()["error"]), (400, "SENSITIVE_CONTENT"))

    def test_security_group_egress_delete_is_blocked_before_approval(self):
        self.repo.results = {"results": [{"rule_id": "3.1", "status": "FAIL"}]}
        original = 'resource "aws_security_group" "endpoint" {\n  name = "endpoint"\n}\n'
        self.source.snapshot.side_effect = lambda paths, check_secrets=True: {
            "repository": "org/repo", "ref": "main", "commit_sha": "a" * 40,
            "files": [{"file_path": path, "original_content": original, "blob_sha": "b" * 40}
                      for path in paths]}
        self.gen.return_value = {"proposed_content": original.replace("\n}", "\n  egress = []\n}")}
        row = self.create(mapping={"3.1": ["modules/security/a.tf"]}).get_json()
        result = self.client.post("/api/ai-actions/terraform-fix", json={"patch_id": row["id"]}).get_json()
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["payload"]["error"]["code"], "UNSAFE_PROPOSAL")
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
        self.source.snapshot.side_effect = PatchError("GITHUB_READ_FAILED", "조회 실패", 502)
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

    def test_more_than_five_files_can_be_in_one_patch(self):
        files = [f"modules/security/file_{index}.tf" for index in range(7)]
        self.source.terraform_paths.return_value = ("a" * 40, files)
        response = self.create(mapping={"3.7": files})
        self.assertEqual(response.status_code, 200)
        row = response.get_json()
        self.assertEqual(len(row["payload"]["files"]), 7)
        result = self.client.post("/api/ai-actions/terraform-fix", json={"patch_id": row["id"]}).get_json()
        self.assertEqual(result["status"], "AWAITING_FIRST_APPROVAL")
        self.assertEqual(self.gen.call_count, 7)
        self.assertEqual(len(result["payload"]["report"]["changes"]), 7)

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
