import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app  # noqa: E402


class AIActionRouteTest(unittest.TestCase):
    def setUp(self):
        app.app.config.update(TESTING=True, SECRET_KEY="test-only")
        self.client = app.app.test_client()
        self.login("관리자")

    def login(self, role):
        with self.client.session_transaction() as session:
            session.update(authenticated=True, role=role, username="operator")

    def body(self, **over):
        data = {"finding": {"rule_id": "3.1", "status": "FAIL", "recommendation": "S3 퍼블릭 차단"},
                "file_path": "storage.tf", "file_content": 'resource "aws_s3_bucket" "x" {}\n'}
        data.update(over)
        return data

    def _keys(self, openai=True, anthropic=True):
        env = {}
        env["OPENAI_API_KEY"] = "sk-test" if openai else ""
        env["ANTHROPIC_API_KEY"] = "sk-ant-test" if anthropic else ""
        return patch.dict(app.os.environ, env)

    def test_generates_fix_and_review(self):
        fix = {"file_path": "storage.tf", "original_content": "a", "proposed_content": "b",
               "diff": "--- a\n+++ b\n", "changed": True}
        review = {"verdict": "APPROVE", "summary": "안전함", "concerns": [], "model": "claude-opus-5"}
        with self._keys(), \
             patch.object(app, "generate_terraform_fix", return_value=fix) as gen, \
             patch.object(app, "review_terraform_fix", return_value=review) as rev:
            res = self.client.post("/api/ai-actions/terraform-fix", json=self.body())
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["review"]["verdict"], "APPROVE")
        self.assertEqual(data["diff"], "--- a\n+++ b\n")
        gen.assert_called_once()
        rev.assert_called_once()

    def test_unchanged_skips_review(self):
        fix = {"file_path": "storage.tf", "original_content": "a", "proposed_content": "a",
               "diff": "", "changed": False}
        with self._keys(), \
             patch.object(app, "generate_terraform_fix", return_value=fix), \
             patch.object(app, "review_terraform_fix") as rev:
            res = self.client.post("/api/ai-actions/terraform-fix", json=self.body())
        self.assertEqual(res.status_code, 200)
        self.assertIsNone(res.get_json()["review"])
        rev.assert_not_called()

    def test_missing_keys_return_503(self):
        with self._keys(openai=False):
            self.assertEqual(self.client.post("/api/ai-actions/terraform-fix", json=self.body()).status_code, 503)
        with self._keys(anthropic=False):
            self.assertEqual(self.client.post("/api/ai-actions/terraform-fix", json=self.body()).status_code, 503)

    def test_input_validation(self):
        with self._keys():
            cases = [
                (self.body(finding={}), "INVALID_FINDING"),
                (self.body(file_path="iam.txt"), "INVALID_FILE_PATH"),
                (self.body(file_path="../etc/iam.tf"), "INVALID_FILE_PATH"),
                (self.body(file_content="   "), "EMPTY_FILE"),
                (self.body(file_content="x" * 50_001), "FILE_TOO_LARGE"),
            ]
            for payload, expected in cases:
                with self.subTest(expected=expected):
                    res = self.client.post("/api/ai-actions/terraform-fix", json=payload)
                    self.assertEqual(res.status_code, 400)
                    self.assertEqual(res.get_json()["error"], expected)

    def test_service_error_maps_to_502(self):
        with self._keys(), \
             patch.object(app, "generate_terraform_fix", side_effect=app.RemediationError("OpenAI 실패")):
            res = self.client.post("/api/ai-actions/terraform-fix", json=self.body())
        self.assertEqual(res.status_code, 502)
        self.assertEqual(res.get_json()["error"], "AI_ACTION_FAILED")

    def test_requires_admin_role(self):
        self.login("승인자")
        with self._keys():
            res = self.client.post("/api/ai-actions/terraform-fix", json=self.body())
        self.assertEqual(res.status_code, 403)


if __name__ == "__main__":
    unittest.main()
