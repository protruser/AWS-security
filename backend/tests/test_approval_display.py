import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app


class ApprovalListScenarioTest(unittest.TestCase):
    def test_dashboard_history_responses_keep_original_titles_and_include_scenario(self):
        title = "CVE-2025-44168 - mariadb"
        detected = app._event_to_detect_history({
            "id": 1, "title": title, "scenario_type": "vuln",
        })
        remediated = app._remediation_to_history({
            "id": 2, "event_title": title, "scenario_type": "vuln",
        })
        for item in (detected, remediated):
            self.assertEqual(item["scenarioType"], "vuln")
            self.assertEqual(item["event"], title)

    def test_approval_response_exposes_db_scenario_without_changing_title(self):
        original_title = "CVE-2025-44168 - mariadb"

        class Cursor:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def execute(self, query, params):
                self.query = query
                self.params = params
            def fetchall(self):
                return [{
                    "id": 7,
                    "event_id": "event-123",
                    "event_title": original_title,
                    "event_scenario_type": "vuln",
                    "request_type": "manual",
                    "status": "대기",
                }]

        class Connection:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def cursor(self): return cursor

        cursor = Cursor()
        app.app.config.update(TESTING=True, SECRET_KEY="test-only")
        client = app.app.test_client()
        with client.session_transaction() as session:
            session.update(authenticated=True, role="승인자", username="test")
        with patch.object(app, "get_connection", return_value=Connection()):
            response = client.get("/api/approval-requests?status=대기")
        self.assertEqual(response.status_code, 200)
        request = response.get_json()["requests"][0]
        self.assertEqual(request["eventScenarioType"], "vuln")
        self.assertEqual(request["eventTitle"], original_title)
        self.assertIn("se.scenario_type AS event_scenario_type", cursor.query)


if __name__ == "__main__":
    unittest.main()
