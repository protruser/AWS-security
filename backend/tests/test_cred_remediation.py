import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app  # noqa: E402
from services import event_analysis_service as analysis  # noqa: E402


def cred_event(user_name=None, **changes):
    """Lambda A 가 저장하는 cred 이벤트. 역할 키면 extracted.userName 이 없다."""
    logs = {"source": "securityhub", "scenario": "cred",
            "extracted": {"userName": user_name, "accessKeyId": "ASIAEXAMPLE", "ip": "203.0.113.5"}}
    event = {"id": "event-1", "scenario_type": "cred", "status": "검토 필요", "severity": "High",
             "title": "Credentials used from external IP", "attacker_ip": "203.0.113.5",
             "recommendation": "해당 IAM 사용자의 Access Key 즉시 비활성화",
             "logs": json.dumps(logs)}
    event.update(changes)
    return event


class AutoActionTest(unittest.TestCase):
    def test_decision_uses_data_needed_by_remediation_lambda(self):
        cases = [
            (cred_event("ci-deployer"), "disable_access_key"),
            (cred_event(None), None),                         # 역할 키: 비활성화할 Access Key 없음
            (cred_event(None, logs="not json"), None),
            ({"scenario_type": "port", "attacker_ip": "203.0.113.5"}, "block_ip"),
            ({"scenario_type": "port", "attacker_ip": ""}, None),  # IP 없는 포트 스캔
            ({"scenario_type": "sqli", "attacker_ip": "203.0.113.5"}, "block_ip"),
            ({"scenario_type": "vuln", "attacker_ip": None}, None),
        ]
        for event, expected in cases:
            with self.subTest(event=event.get("scenario_type"), expected=expected):
                self.assertEqual(app._auto_action(event), expected)

    def test_action_event_type_and_recommendation(self):
        role = app._event_to_action_event(cred_event(None))
        self.assertEqual(role["remediationType"], "MANUAL")
        self.assertEqual(role["recommendation"], app.ROLE_CRED_RECOMMENDATION)

        user = app._event_to_action_event(cred_event("ci-deployer"))
        self.assertEqual(user["remediationType"], "AUTO")
        self.assertEqual(user["recommendation"], "해당 IAM 사용자의 Access Key 즉시 비활성화")

    def test_ai_analysis_context_follows_same_decision(self):
        self.assertEqual(analysis.build_context(cred_event(None), app._auto_action)["remediation_type"], "MANUAL")
        self.assertEqual(analysis.build_context(cred_event("ci-deployer"), app._auto_action)["remediation_type"], "AUTO")


class RoleCredFlowTest(unittest.TestCase):
    """역할 키 탈취는 자동 조치 대신 기존 수동 조치(승인 요청) 흐름으로 처리할 수 있어야 한다."""

    def setUp(self):
        app.app.config.update(TESTING=True, SECRET_KEY="test-only")
        self.client = app.app.test_client()
        with self.client.session_transaction() as session:
            session.update(authenticated=True, role="관리자", username="operator")

    def connection(self, event, executed):
        class Cursor:
            lastrowid = 42
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def execute(self, query, params=None): executed.append(" ".join(query.split()))
            def fetchone(self): return event
            def fetchall(self): return [{"id": event["id"]}]

        class Connection:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def cursor(self): return Cursor()

        return Connection()

    def test_role_cred_is_refused_by_auto_remediation(self):
        executed = []
        with patch.object(app, "get_connection", return_value=self.connection(cred_event(None), executed)), \
             patch.object(app, "_execute_remediation_action") as execute:
            response = self.client.post("/api/remediate", json={"event_id": "event-1"})
        self.assertEqual(response.get_json()["error"], "MANUAL_REMEDIATION")
        execute.assert_not_called()

    def test_role_cred_can_request_manual_approval(self):
        executed = []
        with patch.object(app, "get_connection", return_value=self.connection(cred_event(None), executed)):
            response = self.client.post(
                "/api/approval-requests",
                json={"event_id": "event-1", "note": "역할 세션 폐기 후 CloudTrail 확인"},
            )
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertTrue(any(q.startswith("INSERT INTO approval_requests") for q in executed))

    def test_user_cred_still_refuses_manual_request(self):
        executed = []
        with patch.object(app, "get_connection", return_value=self.connection(cred_event("ci-deployer"), executed)):
            response = self.client.post("/api/approval-requests", json={"event_id": "event-1", "note": "x"})
        self.assertEqual(response.get_json()["error"], "AUTO_REMEDIATION")


if __name__ == "__main__":
    unittest.main()
