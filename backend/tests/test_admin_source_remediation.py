import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app  # noqa: E402


def waf_event(source, scenario="brute", **changes):
    """Lambda B 가 저장하는 WAF 이벤트. source 는 logs.waf ("shop" | "admin")."""
    event = {"id": "event-1", "scenario_type": scenario, "status": "승인 대기", "severity": "High",
             "title": "로그인 무차별 대입 탐지 (14건)", "attacker_ip": "198.51.100.201",
             "recommendation": "출발지 IP 차단 및 관리자 접근 CIDR·MFA 점검",
             "logs": json.dumps({"source": "waf-logs", "waf": source, "count": 14, "blocked": 0})}
    event.update(changes)
    return event


class AdminSourceDecisionTest(unittest.TestCase):
    def test_admin_waf_events_are_manual(self):
        """관리자 WAF 의 IP 는 항상 보호 대역이라 IP 차단이 반드시 거부된다 → 수동 조치."""
        for scenario in ("brute", "flood", "sqli", "xss", "dir"):
            with self.subTest(scenario=scenario):
                self.assertIsNone(app._auto_action(waf_event("admin", scenario)))
                self.assertEqual(app._auto_action(waf_event("shop", scenario)), "block_ip")

    def test_action_event_type_and_recommendation(self):
        admin = app._event_to_action_event(waf_event("admin"))
        self.assertEqual(admin["remediationType"], "MANUAL")
        self.assertEqual(admin["recommendation"], app.ADMIN_SOURCE_RECOMMENDATION)

        shop = app._event_to_action_event(waf_event("shop"))
        self.assertEqual(shop["remediationType"], "AUTO")
        self.assertEqual(shop["recommendation"], "출발지 IP 차단 및 관리자 접근 CIDR·MFA 점검")

    def test_events_without_waf_source_keep_previous_behavior(self):
        # Lambda A(GuardDuty 등) 이벤트나 옛 형식 이벤트는 logs.waf 가 없다.
        self.assertEqual(app._auto_action({"scenario_type": "port", "attacker_ip": "203.0.113.5"}), "block_ip")
        self.assertEqual(app._auto_action(waf_event("shop", logs="not json")), "block_ip")


class AdminSourceFlowTest(unittest.TestCase):
    def setUp(self):
        app.app.config.update(TESTING=True, SECRET_KEY="test-only")
        self.client = app.app.test_client()
        with self.client.session_transaction() as session:
            session.update(authenticated=True, role="관리자", username="operator")

    def connection(self, event, executed):
        class Cursor:
            lastrowid = 7
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

    def test_admin_event_goes_through_manual_approval_not_lambda(self):
        executed = []
        with patch.object(app, "get_connection", return_value=self.connection(waf_event("admin"), executed)), \
             patch.object(app, "_execute_remediation_action") as execute:
            refused = self.client.post("/api/remediate", json={"event_id": "event-1"})
            requested = self.client.post("/api/approval-requests",
                                         json={"event_id": "event-1", "note": "관리자 PC 점검"})
        self.assertEqual(refused.get_json()["error"], "MANUAL_REMEDIATION")
        execute.assert_not_called()
        self.assertEqual(requested.status_code, 200, requested.get_json())
        self.assertTrue(any(q.startswith("INSERT INTO approval_requests") for q in executed))


if __name__ == "__main__":
    unittest.main()
