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
from services.patch_authorization import issue, verify

ROOT = Path(__file__).resolve().parents[2]
# 인프라 레포 쪽 스크립트(서명 검증, plan 요약, manifest)와 워크플로 테스트는
# protruser/AWS-Security-Infra 의 scripts/test_patch_scripts.py 에 있다.


class PlanArtifactTest(unittest.TestCase):
    def test_issued_approval_binds_exact_plan(self):
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
        claims = verify(token, key.encode())
        self.assertEqual((claims["base_ref"], claims["plan_version_id"]), ("gyu", "v1"))
        with self.assertRaises(PatchError):
            verify(token + "x", key.encode())

    def test_dashboard_workflow_scans_before_push(self):
        dashboard = (ROOT / ".github/workflows/deploy-dashboard.yml").read_text(encoding="utf-8")
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
