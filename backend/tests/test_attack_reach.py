import json
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services import attack_reach  # noqa: E402

T0 = datetime(2026, 9, 26, 6, 0, 0)


def waf_row(event_id, ip, minutes, kind="sqli", count=10, blocked=0, waf="shop", status="승인 대기",
            block_result=None, blocked_col=None):
    logs = {"source": "waf-logs", "waf": waf, "count": count, "blocked": blocked, "samples": []}
    if block_result is None:
        block_result = "성공" if blocked == count else ("부분" if blocked else "실패")
    return {
        "id": event_id, "attacker_ip": ip, "scenario_type": kind, "severity": "High", "title": kind,
        "asset": "Admin ALB / Dashboard" if waf == "admin" else "Shop ALB / Flask App",
        "detected_at": T0 + timedelta(minutes=minutes), "status": status,
        "blocked": (blocked == count) if blocked_col is None else blocked_col,
        "block_result": block_result, "logs": json.dumps(logs),
    }


def finding_row(event_id, ip, minutes, kind, tags=None, resource_id="", asset=None):
    finding = {"Resources": [{"Type": "AwsEc2Instance", "Id": resource_id, "Tags": tags or {}}]}
    return {
        "id": event_id, "attacker_ip": ip, "scenario_type": kind, "severity": "Medium", "title": kind,
        "asset": asset, "detected_at": T0 + timedelta(minutes=minutes), "status": "검토 필요",
        "blocked": None, "block_result": None,
        "logs": json.dumps({"source": "securityhub", "finding": finding}),
    }


def block(event_id, ip, minutes, result="성공", detail="WAF IP 차단 목록에 추가"):
    at = T0 + timedelta(minutes=minutes)
    return {"event_id": event_id, "attacker_ip": ip, "action_type": "block_ip", "method": "자동",
            "result": result, "result_detail": detail, "requested_at": at, "completed_at": at}


class ClassifyEventTest(unittest.TestCase):
    def stage(self, row, **kwargs):
        return attack_reach.classify_event(row, **kwargs)

    def test_all_blocked_is_edge(self):
        v = self.stage(waf_row("e", "1.1.1.1", 0, count=6, blocked=6))
        self.assertEqual((v["stage"], v["confidence"]), ("S2", "confirmed"))
        self.assertEqual(v["reach"], {"confirmed": ["attacker", "igw", "shopWAF"], "estimated": []})

    def test_partial_pass_reaches_alb_and_estimates_inner(self):
        v = self.stage(waf_row("e", "1.1.1.1", 0, count=24, blocked=12))
        self.assertEqual((v["stage"], v["requests"], v["passed"]), ("S3", 24, 12))
        self.assertEqual(v["reach"]["confirmed"][-1], "shopALB")
        self.assertEqual(v["reach"]["estimated"], ["k3s", "flaskApp"])

    def test_nothing_blocked_is_s4(self):
        self.assertEqual(self.stage(waf_row("e", "1.1.1.1", 0, count=35, blocked=0))["stage"], "S4")

    def test_admin_waf_uses_admin_path(self):
        v = self.stage(waf_row("e", "1.1.1.1", 0, kind="brute", count=14, blocked=0, waf="admin"))
        self.assertEqual(v["reach"]["confirmed"], ["attacker", "igw", "adminWAF", "dashALB"])
        self.assertEqual(v["reach"]["estimated"], ["dashEC2"])

    def test_remediation_overwrite_does_not_hide_passed_requests(self):
        """조치 후 blocked=TRUE/'성공'으로 덮어써져도 logs 의 원래 수치로 판정한다."""
        row = waf_row("e", "1.1.1.1", 0, count=24, blocked=12, block_result="성공", blocked_col=True)
        self.assertEqual(self.stage(row, remediated=True)["stage"], "S3")

    def test_fallback_to_block_result_without_counts(self):
        row = waf_row("e", "1.1.1.1", 0)
        row["logs"] = json.dumps({"source": "sample_data.sql"})
        row["block_result"] = "부분"
        self.assertEqual((self.stage(row)["stage"], self.stage(row)["confidence"]), ("S3", "fallback"))
        self.assertEqual(self.stage(row, remediated=True)["confidence"], "uncertain")

    def test_waf_source_falls_back_to_asset_text(self):
        row = waf_row("e", "1.1.1.1", 0, waf="admin")
        row["logs"] = json.dumps({"count": 3, "blocked": 0})
        self.assertEqual(self.stage(row)["source"], "admin")

    def test_port_scan_target_from_name_tag(self):
        row = finding_row("p", "1.1.1.1", 0, "port", tags={"Name": "dragon-03-shop-app"})
        v = self.stage(row)
        self.assertEqual((v["stage"], v["target"]), ("S1", "flaskApp"))
        self.assertEqual(v["reach"]["confirmed"], ["attacker", "flaskApp"])

    def test_port_scan_target_from_instance_map(self):
        row = finding_row("p", "1.1.1.1", 0, "port",
                          resource_id="arn:aws:ec2:ap-northeast-2:1:instance/i-02ce93fab88c54df4")
        v = self.stage(row, instance_map={"i-02ce93fab88c54df4": "k3s"})
        self.assertEqual(v["target"], "k3s")

    def test_port_scan_unknown_target_paints_nothing_inside(self):
        v = self.stage(finding_row("p", "1.1.1.1", 0, "port", asset="AwsEc2Instance i-0aaaaaaaaaaaaaaaa"))
        self.assertIsNone(v["target"])
        self.assertEqual(v["reach"]["confirmed"], ["attacker"])

    def test_cred_is_cloud_stage(self):
        self.assertEqual(self.stage(finding_row("c", "1.1.1.1", 0, "cred"))["stage"], "C")

    def test_events_without_ip_or_out_of_scope_are_skipped(self):
        self.assertIsNone(self.stage(waf_row("e", "", 0)))
        self.assertIsNone(self.stage(finding_row("v", "1.1.1.1", 0, "vuln")))
        self.assertIsNone(self.stage(finding_row("g", "1.1.1.1", 0, "generic")))


class IpDetailTest(unittest.TestCase):
    def test_persistent_attacker_blocked_and_holding(self):
        ip = "198.51.100.23"
        rows = [
            finding_row("port", ip, 0, "port", tags={"Name": "dragon-01-k3s-nginx"}),
            waf_row("dir", ip, 10, kind="dir", count=22, blocked=0),
            waf_row("sqli1", ip, 20, count=24, blocked=12, block_result="성공", blocked_col=True, status="조치 완료"),
            waf_row("sqli2", ip, 120, count=15, blocked=15, status="자동 완료"),
        ]
        detail = attack_reach.build_ip_detail(ip, rows, [block("sqli1", ip, 30)])
        s = detail["summary"]
        self.assertEqual((s["maxStage"], s["maxStageConfidence"]), ("S4", "confirmed"))
        self.assertEqual(s["block"]["state"], "blocked")
        self.assertEqual((s["requestCount"], s["passedCount"]), (61, 34))
        self.assertEqual(s["scenarioTypes"], ["port", "dir", "sqli"])
        self.assertEqual(detail["reach"]["estimated"], ["flaskApp"])  # k3s 는 포트 스캔으로 확인됨
        self.assertIn("k3s", detail["reach"]["confirmed"])

    def test_passed_requests_after_block_are_bypass(self):
        ip = "185.220.101.5"
        rows = [waf_row("a", ip, 0, count=8, blocked=0, status="조치 완료"),
                waf_row("b", ip, 270, count=9, blocked=6)]
        s = attack_reach.build_ip_detail(ip, rows, [block("a", ip, 10)])["summary"]
        self.assertEqual(s["block"]["state"], "bypassed")

    def test_same_window_as_block_is_not_bypass(self):
        ip = "185.220.101.5"
        rows = [waf_row("a", ip, 0, count=8, blocked=0), waf_row("b", ip, 13, count=9, blocked=6)]
        s = attack_reach.build_ip_detail(ip, rows, [block("a", ip, 10)])["summary"]
        self.assertEqual(s["block"]["state"], "blocked")

    def test_exception_events_do_not_raise_max_stage(self):
        ip = "203.0.113.1"
        rows = [waf_row("a", ip, 0, count=5, blocked=5), waf_row("b", ip, 5, count=5, blocked=0, status="예외 처리")]
        detail = attack_reach.build_ip_detail(ip, rows, [])
        self.assertEqual(detail["summary"]["maxStage"], "S2")
        self.assertTrue(detail["timeline"][1]["excluded"])

    def test_block_states_for_unblockable_ips(self):
        admin = attack_reach.build_ip_detail(
            "203.0.113.2", [waf_row("a", "203.0.113.2", 0)],
            [block("a", "203.0.113.2", 5, result="실패", detail="관리자 IP 대역은 차단하지 않는다: 203.0.113.2")])
        self.assertEqual(admin["summary"]["block"]["reason"], "관리자 IP 대역")
        internal = attack_reach.build_ip_detail("10.0.1.5", [waf_row("a", "10.0.1.5", 0)], [])
        self.assertEqual((internal["summary"]["block"]["state"], internal["summary"]["isInternal"]),
                         ("excluded", True))
        # 문서용 예약 대역: Remediation 이 거부하지만 조직 내부 주소는 아니다.
        reserved = attack_reach.build_ip_detail("198.51.100.9", [waf_row("a", "198.51.100.9", 0)], [])
        self.assertEqual((reserved["summary"]["block"]["reason"], reserved["summary"]["isInternal"]),
                         ("예약 대역", False))
        public = attack_reach.build_ip_detail("8.8.4.4", [waf_row("a", "8.8.4.4", 0)], [])
        self.assertEqual(public["summary"]["block"]["state"], "none")

    def test_cloud_only_ip(self):
        s = attack_reach.build_ip_detail("45.155.205.100", [finding_row("c", "45.155.205.100", 0, "cred")], [])
        self.assertEqual((s["summary"]["maxStage"], s["summary"]["cloudAccess"]), (None, True))
        self.assertIsNone(s["summary"]["requestCount"])  # 요청 수를 모르면 0 이 아니라 null


class AttackerListTest(unittest.TestCase):
    def test_sorted_by_risk_and_summarized(self):
        rows = [
            waf_row("x", "203.0.113.77", 0, kind="xss", count=6, blocked=6),
            waf_row("b", "192.0.2.144", 10, kind="brute", count=35, blocked=0),
            waf_row("g1", "185.220.101.5", 0, count=8, blocked=0),
            waf_row("g2", "185.220.101.5", 270, count=9, blocked=6),
            finding_row("c", "45.155.205.100", 20, "cred"),
            finding_row("v", None, 20, "vuln"),
        ]
        rems = [block("g1", "185.220.101.5", 10)]
        result = attack_reach.build_attacker_list(rows, rems)
        self.assertEqual([s["ip"] for s in result["items"]],
                         ["185.220.101.5", "192.0.2.144", "203.0.113.77", "45.155.205.100"])
        self.assertEqual(result["summary"], {"ips": 4, "passedIps": 2, "bypassed": 1, "cloud": 1})


class InstanceMapTest(unittest.TestCase):
    def test_load_instance_map(self):
        self.assertEqual(attack_reach.load_instance_map('{"i-1": "k3s"}'), {"i-1": "k3s"})
        self.assertEqual(attack_reach.load_instance_map("not json"), {})
        self.assertEqual(attack_reach.load_instance_map(""), {})


if __name__ == "__main__":
    unittest.main()
