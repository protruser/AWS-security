import json
import sys
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app  # noqa: E402
from services import attack_reach  # noqa: E402


def waf_row(event_id, ip, count, blocked, kind="sqli", **extra):
    row = {
        "id": event_id, "scenario_type": kind, "attacker_ip": ip, "asset": "Shop ALB / Flask App",
        "severity": "High", "title": kind, "status": "승인 대기", "detected_at": datetime(2026, 9, 26, 6, 0),
        "blocked": blocked == count, "block_result": "부분",
        "logs": json.dumps({"waf": "shop", "count": count, "blocked": blocked}),
        "highlight_assets": json.dumps(["attacker", "igw", "shopWAF", "shopALB", "k3s", "flaskApp", "cwLogs"]),
        "attack_path": json.dumps(["attacker", "igw", "shopWAF", "shopALB", "k3s", "flaskApp"]),
    }
    row.update(extra)
    return row


class MergeVerdictsTest(unittest.TestCase):
    def test_group_takes_max_stage_and_sums_requests(self):
        verdicts = [attack_reach.classify_event(waf_row("a", "1.1.1.1", 10, 10)),
                    attack_reach.classify_event(waf_row("b", "1.1.1.1", 8, 0))]
        merged = attack_reach.merge_verdicts(verdicts)
        self.assertEqual((merged["stage"], merged["requests"], merged["passed"], merged["grouped"]),
                         ("S4", 18, 8, 2))
        self.assertEqual(merged["confirmed"], ["attacker", "igw", "shopWAF", "shopALB"])
        self.assertEqual(merged["estimated"], ["k3s", "flaskApp"])

    def test_nothing_to_judge_is_none(self):
        self.assertIsNone(attack_reach.merge_verdicts([None]))
        self.assertIsNone(attack_reach.merge_verdicts([]))


class DashboardReachTest(unittest.TestCase):
    def test_detect_history_reach(self):
        blocked = app._event_to_detect_history(waf_row("x", "2.2.2.2", 6, 6, kind="xss"))
        self.assertEqual(blocked["reach"]["stage"], "S2")
        self.assertEqual(blocked["reach"]["confirmed"], ["attacker", "igw", "shopWAF"])
        # IP 없는 이벤트(vuln 등)는 판정하지 않는다 → 프론트가 기존 경로 사용
        self.assertIsNone(app._event_to_detect_history({"id": 1, "title": "t", "scenario_type": "vuln"})["reach"])

    def test_action_event_uses_whole_open_group(self):
        """묶음의 최신 1건은 전부 차단(S2)이어도, 같은 묶음에 통과 구간이 있으면 그 도달을 보여준다."""
        latest = waf_row("new", "3.3.3.3", 5, 5, occurrence_count=2, rn=1)
        older = waf_row("old", "3.3.3.3", 9, 3)
        results = [[latest], [older, latest], [], []]

        class Cursor:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def execute(self, query, params=None): pass
            def fetchall(self): return results.pop(0)

        class Connection:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def cursor(self): return Cursor()

        with patch.object(app, "get_connection", return_value=Connection()):
            data = app._read_dashboard_data()
        reach = data["events"][0]["reach"]
        self.assertEqual((reach["stage"], reach["grouped"], reach["passed"]), ("S3", 2, 6))


if __name__ == "__main__":
    unittest.main()
