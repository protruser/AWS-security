"""The second model reviews the selected code change at the pre-PR stage."""

import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services import terraform_remediation_service as remediation


class SecondReviewTest(unittest.TestCase):
    def test_generator_preserves_original_file_ending(self):
        client = MagicMock()
        client.responses.create.return_value = SimpleNamespace(status="completed",
            output_text='resource "aws_security_group" "example" {}\n')
        with patch.object(remediation, "OpenAI", return_value=client):
            result = remediation.generate_terraform_fix(finding={"findings": []},
                file_path="modules/network/main.tf",
                file_content='resource "aws_security_group" "example" {}\n', api_key="test-key")
        self.assertEqual(result["proposed_content"], result["original_content"])
        self.assertFalse(result["changed"])

    def test_review_receives_scope_full_code_and_pre_plan_stage(self):
        client = MagicMock()
        client.messages.create.return_value = SimpleNamespace(content=[SimpleNamespace(
            type="text", text=json.dumps({"verdict": "APPROVE", "summary": "정적 코드 검토 통과", "concerns": []})
        )], stop_reason="end_turn")
        finding = {"findings": [{"rule_id": "3.1", "status": "FAIL", "resource_ids": ["sg-one"],
            "remediation_scope": {"selected_resource_ids": ["sg-one"],
                                  "deferred_resource_ids": ["sg-two"]}}]}
        files = [{"file_path": "modules/network/security_groups.tf",
                  "original_content": "old code\n", "proposed_content": "new code\n", "diff": "-old code\n+new code"}]
        with patch.object(remediation, "Anthropic", return_value=client):
            result = remediation.review_terraform_fix(
                finding=finding, diff_text=files[0]["diff"], files=files,
                mapping={"3.1": [files[0]["file_path"]]}, api_key="test-key")
        self.assertEqual(result["verdict"], "APPROVE")
        call = client.messages.create.call_args.kwargs
        payload = json.loads(call["messages"][0]["content"])
        self.assertEqual(payload["files"], files)
        self.assertEqual(payload["findings"][0]["remediation_scope"]["deferred_resource_ids"], ["sg-two"])
        self.assertIsNone(payload["terraform_plan"])
        self.assertIn("plan이 제공되지 않았", call["system"])
        self.assertEqual(call["output_config"]["format"]["schema"]["properties"]["verdict"]["enum"],
                         ["APPROVE", "REJECT", "NEEDS_HUMAN_REVIEW"])

    def test_real_rejection_is_preserved(self):
        client = MagicMock()
        client.messages.create.return_value = SimpleNamespace(content=[SimpleNamespace(
            type="text", text=json.dumps({"verdict": "REJECT", "summary": "egress 전체 삭제",
                                          "concerns": ["필요한 443/TCP도 차단"]})
        )], stop_reason="end_turn")
        with patch.object(remediation, "Anthropic", return_value=client):
            result = remediation.review_terraform_fix(finding={"findings": []},
                                                       diff_text="+  egress = []", api_key="test-key")
        self.assertEqual(result["verdict"], "REJECT")
        self.assertIn("443", result["concerns"][0])

    def test_invalid_response_does_not_become_approval(self):
        client = MagicMock()
        client.messages.create.return_value = SimpleNamespace(content=[SimpleNamespace(
            type="text", text='{"verdict":"APPROVE","summary":"ok","concerns":"none"}'
        )], stop_reason="end_turn")
        with patch.object(remediation, "Anthropic", return_value=client):
            with self.assertRaises(remediation.RemediationError):
                remediation.review_terraform_fix(finding={}, diff_text="+x", api_key="test-key")


if __name__ == "__main__":
    unittest.main()
