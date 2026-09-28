import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app
from services.patch_pdf import render_pdf
from services.patch_security import PatchError
from services.patch_authorization import issue

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("terraform_patch_ci", ROOT / "integrations/AWS-Security-Infra/scripts/terraform_patch_ci.py")
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)
verifier_spec = importlib.util.spec_from_file_location("infra_verify", ROOT / "integrations/AWS-Security-Infra/scripts/verify_patch_authorization.py")
infra_verify = importlib.util.module_from_spec(verifier_spec)
verifier_spec.loader.exec_module(infra_verify)


class PlanArtifactTest(unittest.TestCase):
    def test_infra_runner_verifies_exact_dashboard_approval(self):
        patch_row = {"id": "11111111-1111-1111-1111-111111111111", "payload": {
            "github_pr": {"head_sha": "b" * 40, "base_sha": "a" * 40,
                "branch": "ai-patch/11111111-1111-1111-1111-111111111111",
                "base_ref": "gyu", "number": 7},
            "checks": {"run_id": 50, "plan_sha256": "c" * 64,
                "plan_key": "terraform-patches/11111111-1111-1111-1111-111111111111/" + "b" * 40 + "/50.tfplan",
                "plan_version_id": "v1", "state": {"lineage": "l", "serial": 1}}}}
        key = "s" * 48
        with patch.dict(os.environ, {"PATCH_APPROVAL_SIGNING_KEY": key}):
            token = issue(patch_row, "approval-hash")
        self.assertEqual(infra_verify.verify(token, key.encode())["base_ref"], "gyu")
        with self.assertRaises(SystemExit):
            infra_verify.verify(token + "x", key.encode())

    def test_summary_omits_sensitive_state_and_resource_keys(self):
        plan = {"resource_changes": [{"type": "aws_s3_bucket", "address": "aws_s3_bucket.x[\"password-raw\"]",
            "change": {"actions": ["update"], "before": {"password": "raw-secret"},
                       "after": {"password": "new-secret"}}},
            {"type": "aws_caller_identity", "address": "data.aws_caller_identity.current",
             "change": {"actions": ["read"], "after": {"account_id": "123456789012"}}}]}
        with tempfile.TemporaryDirectory() as folder:
            source, target = Path(folder) / "plan.json", Path(folder) / "summary.json"
            source.write_text(json.dumps(plan), encoding="utf-8")
            ci.plan_summary(source, target)
            output = target.read_text(encoding="utf-8")
        self.assertNotIn("raw-secret", output)
        self.assertNotIn("password-raw", output)
        self.assertNotIn("123456789012", output)
        self.assertEqual(json.loads(output)["resources"]["update"], ["aws_s3_bucket"])
        self.assertEqual(json.loads(output)["resources"]["read"], ["aws_caller_identity"])

    def test_manifest_keeps_unrun_checks_unrun(self):
        env = {"RUN_URL": "https://github.com/org/repo/actions/runs/5", "PATCH_ID": "x",
               "HEAD_SHA": "a" * 40, "BASE_SHA": "b" * 40, "GITHUB_RUN_ID": "5",
               "CHECK_FMT": "success", "CHECK_VALIDATE": "skipped", "CHECK_PLAN": "failure",
               "CHECK_TFLINT": "failure", "CHECK_CHECKOV": "skipped"}
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, env, clear=True):
            target = Path(folder) / "manifest.json"
            ci.manifest(target)
            data = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual({k: v["status"] for k, v in data["results"].items()},
                         {"fmt": "PASS", "validate": "NOT_RUN", "plan": "FAIL",
                          "tflint": "FAIL", "checkov": "NOT_RUN"})

    def test_workflow_separates_plan_from_approved_apply(self):
        infra = ROOT / "integrations/AWS-Security-Infra/.github/workflows"
        plan = (infra / "terraform-patch.yml").read_text(encoding="utf-8")
        deploy = (infra / "terraform-patch-deploy.yml").read_text(encoding="utf-8")
        dashboard = (ROOT / ".github/workflows/deploy-dashboard.yml").read_text(encoding="utf-8")
        self.assertIn("pull_request:", plan)
        self.assertIn("branches: [gyu]", plan)
        self.assertIn("working-directory: .", plan)
        self.assertNotIn("terraform apply", plan)
        self.assertIn("workflow_dispatch:", deploy)
        self.assertIn("Verify server approval before loading patch code or AWS identity", deploy)
        self.assertLess(deploy.index("Verify server approval before loading patch code or AWS identity"),
                        deploy.index("terraform apply"))
        self.assertIn('"$MERGE_SHA"', deploy[deploy.index('name: Reconfirm state and apply exact approved saved plan'):])
        self.assertIn('paths:', dashboard)
        self.assertNotIn('wonny-sec-terraform/**', dashboard)
        self.assertIn("Trivy", dashboard)
        self.assertLess(dashboard.index("Scan image with Trivy"), dashboard.index("Push scanned image to ECR"))


class ReportArtifactTest(unittest.TestCase):
    def test_pdf_versions_and_rejected_patch_download_from_saved_payload(self):
        row = {"id": "patch-id", "status": "REJECTED", "payload": {
            "findings": [{"rule_id": "3.7", "status": "FAIL"}],
            "source": {"commit_sha": "a" * 40},
            "files": [{"file_path": "a.tf", "original_content": "old", "proposed_content": "new",
                       "diff": "-old\n+new\n"}],
            "report": {"summary": "변경", "changes": [], "risks": [], "checks": []},
            "final_report": {"version": "final-v1", "ai_assessment": {"assessment": "검증됨"}},
            "checks": {"results": {}}, "deployment": {"status": "FAILED"},
            "rediagnosis": None}}
        for kind in ("first", "final", "results"):
            with self.subTest(kind=kind):
                self.assertTrue(render_pdf(row, kind).startswith(b"%PDF"))
        row["payload"]["final_report"] = None
        with self.assertRaises(PatchError):
            render_pdf(row, "final")
