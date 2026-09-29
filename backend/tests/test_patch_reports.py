"""Final report explanations use recorded impact and keep pre-deployment limits clear."""
import json
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.patch_reports import change_details_from_diff, final_report


def report_patch():
    return {"id": "patch-1", "payload": {
        "findings": [{"rule_id": "3.9", "status": "FAIL", "resource_ids": ["alb-one"]}],
        "source": {"commit_sha": "a" * 40},
        "files": [{"file_path": "modules/edge/alb_waf.tf", "diff": "+enable_deletion_protection = true"}],
        "report": {"summary": "ALB 삭제 보호를 켭니다.", "impact": "ALB 삭제가 막힙니다.",
                   "service_disruption": "실제 중단 가능성은 Plan으로 확인합니다.",
                   "resource_replacement": "현재 근거로는 미확인입니다.",
                   "checks": ["HTTP 리스너 미해결 여부 확인"]},
        "ai_review": {"verdict": "NEEDS_HUMAN_REVIEW", "summary": "HTTP 리스너 미해결",
                      "concerns": ["HTTPS 전환 여부 확인 필요"]},
        "human_review_approval": {"event": "HUMAN_REVIEW_APPROVED", "note": "HTTP는 다음 패치에서 검토"},
        "checks": {"results": {"fmt": {"status": "PASS"}},
                   "plan_summary": {"counts": {"create": 0, "update": 1, "delete": 0, "replace": 0}}},
        "github_pr": {"url": "https://github.com/example/repo/pull/1"},
        "audit": [{"event": "HUMAN_REVIEW_APPROVED", "actor": "admin"}],
    }}


class FinalReportTest(unittest.TestCase):
    def test_plain_language_impact_is_recorded_with_unresolved_review(self):
        narrative = {"assessment": "삭제 보호 설정을 켜는 변경입니다. HTTP 문제는 남아 있습니다.",
                     "change_explanation": "실수로 ALB를 삭제하지 못하게 보호합니다.",
                     "user_impact": "이용자의 접속 방식은 이번 변경으로 달라지지 않습니다.",
                     "service_disruption": "Plan에는 기존 ALB의 설정 변경 1건이 표시됩니다.",
                     "resource_replacement": "Plan에는 교체 0건이 표시됩니다.",
                     "risks": ["HTTP 리스너 문제는 미해결입니다."],
                     "decision_points": ["HTTP 전환 계획을 확인하세요."],
                     "post_deploy_checks": ["ALB 설정과 진단 상태를 다시 확인하세요."]}
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}), patch(
                "services.patch_reports.OpenAI") as client:
            client.return_value.responses.create.return_value = SimpleNamespace(
                status="completed", output_text=json.dumps(narrative, ensure_ascii=False))
            result = final_report(report_patch())
            call = client.return_value.responses.create.call_args.kwargs
        self.assertEqual(result["version"], "final-v3")
        self.assertEqual(result["ai_assessment"]["user_impact"], narrative["user_impact"])
        self.assertIn("배포 후 재진단", result["report_notice"])
        self.assertEqual(json.loads(call["input"])["human_review_approval"]["note"], "HTTP는 다음 패치에서 검토")
        self.assertIn("비전공자", call["instructions"])
        self.assertFalse(call["store"])
        self.assertEqual(result["change_details"][0]["hunks"][0]["after_lines"],
                         ["enable_deletion_protection = true"])

    def test_https_exception_is_saved_as_unresolved_fact_in_final_report(self):
        row = report_patch()
        alb = row["payload"]["findings"][0]
        alb["remediation_scope"] = {
            "selected_resource_ids": ["alb-one"],
            "https_exception_resource_ids": ["alb-one"],
            "https_exception_reason": "ACM 인증서가 준비되지 않음",
        }
        narrative = {"assessment": "삭제 보호만 변경", "risks": [], "post_deploy_checks": []}
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}), patch(
                "services.patch_reports.OpenAI") as client:
            client.return_value.responses.create.return_value = SimpleNamespace(
                status="completed", output_text=json.dumps(narrative, ensure_ascii=False))
            result = final_report(row)
            supplied_facts = json.loads(client.return_value.responses.create.call_args.kwargs["input"])
        expected = [{"rule_id": "3.9", "resource_id": "alb-one",
                     "reason": "ACM 인증서가 준비되지 않음", "status": "미조치"}]
        self.assertEqual(result["https_exceptions"], expected)
        self.assertEqual(supplied_facts["https_exceptions"], expected)

    def test_older_ai_fields_get_fact_based_impact_fallbacks(self):
        old_narrative = {"assessment": "설정 변경을 검토했습니다.", "risks": [],
                         "post_deploy_checks": ["재진단"]}
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}), patch(
                "services.patch_reports.OpenAI") as client:
            client.return_value.responses.create.return_value = SimpleNamespace(
                status="completed", output_text=json.dumps(old_narrative, ensure_ascii=False))
            result = final_report(report_patch())
        assessment = result["ai_assessment"]
        self.assertEqual(assessment["change_explanation"], "ALB 삭제 보호를 켭니다.")
        self.assertEqual(assessment["user_impact"], "ALB 삭제가 막힙니다.")
        self.assertEqual(assessment["decision_points"], ["HTTP 리스너 미해결 여부 확인"])

    def test_every_changed_hunk_stays_with_its_file_and_ai_cannot_replace_it(self):
        row = report_patch()
        row["payload"]["files"] = [
            {"file_path": "alb.tf", "diff": "--- a/alb.tf\n+++ b/alb.tf\n@@ -1,2 +1,2 @@\n-old = false\n+old = true\n context\n@@ -10 +10 @@\n-port = 80\n+port = 443\n"},
            {"file_path": "sg.tf", "diff": "--- a/sg.tf\n+++ b/sg.tf\n@@ -1 +1 @@\n-protocol = \"-1\"\n+protocol = \"tcp\"\n"},
        ]
        row["payload"]["report"]["changes"] = [
            {"file_path": "alb.tf", "evidence": "+old = true", "explanation": "삭제 보호를 켭니다."},
            {"file_path": "sg.tf", "evidence": "+protocol = \"tcp\"", "explanation": "프로토콜을 제한합니다."},
        ]
        details = change_details_from_diff(row["payload"]["files"], row["payload"]["report"])
        self.assertEqual([item["file_path"] for item in details], ["alb.tf", "sg.tf"])
        self.assertEqual([h["after_lines"] for h in details[0]["hunks"]],
                         [["old = true"], ["port = 443"]])
        self.assertEqual(details[1]["hunks"][0]["before_lines"], ["protocol = \"-1\""])
        self.assertEqual(details[0]["explanations"][0]["explanation"], "삭제 보호를 켭니다.")
        self.assertEqual(details[1]["explanations"][0]["explanation"], "프로토콜을 제한합니다.")

        narrative = {"assessment": "설정 변경", "risks": [], "post_deploy_checks": [],
                     "change_details": [{"file_path": "fake.tf", "hunks": []}]}
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}), patch(
                "services.patch_reports.OpenAI") as client:
            client.return_value.responses.create.return_value = SimpleNamespace(
                status="completed", output_text=json.dumps(narrative, ensure_ascii=False))
            result = final_report(row)
        self.assertEqual(result["change_details"], details)
        self.assertNotIn("change_details", result["ai_assessment"])


if __name__ == "__main__":
    unittest.main()
