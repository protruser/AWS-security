import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app


class DirectRemediationTest(unittest.TestCase):
    def setUp(self):
        app.app.config.update(TESTING=True, SECRET_KEY="test-only")
        self.client = app.app.test_client()

    def login(self, role="관리자"):
        with self.client.session_transaction() as session:
            session.update(authenticated=True, role=role, username="operator")

    def connection(self, event):
        class Cursor:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def execute(self, query, params):
                assert query.startswith("SELECT * FROM security_events WHERE id")
                assert params == ("event-1",)
            def fetchone(self): return event

        class Connection:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def cursor(self): return Cursor()

        return Connection()

    def event(self, scenario="sqli", **changes):
        return {"id": "event-1", "scenario_type": scenario,
                "status": "검토 필요", "attacker_ip": "192.0.2.4",
                "title": "원본 제목", **changes}

    def test_auto_scenarios_call_existing_lambda_without_approval_request(self):
        self.login()
        for scenario, action in app.REMEDIATION_ACTIONS.items():
            with self.subTest(scenario=scenario):
                # cred 자동 조치(disable_access_key)는 Lambda A 가 뽑아 둔 IAM 사용자 이름이 있어야 한다.
                extra = ({"logs": '{"extracted": {"userName": "ci-deployer"}}'}
                         if action == "disable_access_key" else {})
                event = self.event(scenario, **extra)
                with patch.object(app, "get_connection", return_value=self.connection(event)), \
                     patch.object(app, "_execute_remediation_action", return_value=(True, None)) as execute:
                    response = self.client.post("/api/remediate", json={"event_id": "event-1"})
                self.assertEqual(response.status_code, 200)
                execute.assert_called_once_with(event, action, "operator")

    def test_manual_closed_and_missing_ip_do_not_run(self):
        self.login()
        cases = [
            (self.event("vuln"), "MANUAL_REMEDIATION"),
            (self.event(status="조치 완료"), "EVENT_NOT_ACTIONABLE"),
            (self.event(status=app.PENDING_APPROVAL_STATUS), "EVENT_NOT_ACTIONABLE"),
            # 조치에 필요한 IP 가 없으면 자동 조치가 아니라 수동 조치(승인 요청)로 보낸다.
            (self.event(attacker_ip=""), "MANUAL_REMEDIATION"),
        ]
        for event, error in cases:
            with self.subTest(error=error), \
                 patch.object(app, "get_connection", return_value=self.connection(event)), \
                 patch.object(app, "_execute_remediation_action") as execute:
                response = self.client.post("/api/remediate", json={"event_id": "event-1"})
                self.assertEqual(response.get_json()["error"], error)
                execute.assert_not_called()

    def test_lambda_failure_is_reported_and_request_needs_admin_role(self):
        self.login()
        event = self.event()
        with patch.object(app, "get_connection", return_value=self.connection(event)), \
             patch.object(app, "_execute_remediation_action", return_value=(False, "Lambda 실패")):
            response = self.client.post("/api/remediate", json={"event_id": "event-1"})
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.get_json()["message"], "Lambda 실패")
        self.login("승인자")
        self.assertEqual(self.client.post("/api/remediate", json={"event_id": "event-1"}).status_code, 403)

    def test_auto_cannot_create_new_approval_request(self):
        self.login()
        with patch.object(app, "get_connection", return_value=self.connection(self.event())):
            response = self.client.post("/api/approval-requests", json={"event_id": "event-1"})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()["error"], "AUTO_REMEDIATION")

    def test_manual_still_creates_pending_approval(self):
        self.login()
        statements = []

        class Cursor:
            lastrowid = 42
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def execute(self, query, params): statements.append((query, params))
            def fetchone(self): return self_event

        class Connection:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def cursor(self): return Cursor()

        self_event = self.event("vuln")
        with patch.object(app, "get_connection", return_value=Connection()), \
             patch.object(app, "_open_group_ids", return_value=["event-1"]):
            response = self.client.post("/api/approval-requests", json={"event_id": "event-1", "note": "패키지 업데이트"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["requestId"], 42)
        inserts = [params for query, params in statements if "INSERT INTO approval_requests" in query]
        self.assertEqual(len(inserts), 1)
        self.assertEqual(inserts[0][3:5], ("manual", app.APPROVAL_PENDING))


if __name__ == "__main__":
    unittest.main()
