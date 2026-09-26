import sys
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app  # noqa: E402


class FakeCursor:
    def __init__(self, rows):
        self.rows = rows

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def execute(self, query, params):
        return None

    def fetchall(self):
        return self.rows


class FakeConnection:
    def __init__(self, rows):
        self.rows = rows

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def cursor(self):
        return FakeCursor(self.rows)


class OverviewMetricsTest(unittest.TestCase):
    def test_conversions_and_health_evaluation(self):
        timestamp = datetime(2026, 9, 21, 12, 0)
        rows = [
            {"metric_name": "CPUUtilization", "metric_value": 41.2, "period_seconds": 60, "collected_at": timestamp},
            {"metric_name": "mem_used_percent", "metric_value": 63.7, "period_seconds": 60, "collected_at": timestamp},
            {"metric_name": "TargetResponseTime", "metric_value": 0.182, "period_seconds": 60, "collected_at": timestamp},
            {"metric_name": "RequestCount", "metric_value": 900, "period_seconds": 60, "collected_at": timestamp},
            {"metric_name": "HTTPCode_Target_5XX_Count", "metric_value": 3, "period_seconds": 60, "collected_at": timestamp},
            {"metric_name": "HTTPCode_ELB_5XX_Count", "metric_value": 1, "period_seconds": 60, "collected_at": timestamp},
            {"metric_name": "StatusCheckFailed", "metric_value": 0, "period_seconds": 60, "collected_at": timestamp},
            {"metric_name": "HealthyHostCount", "metric_value": 2, "period_seconds": 60, "collected_at": timestamp},
            {"metric_name": "UnHealthyHostCount", "metric_value": 1, "period_seconds": 60, "collected_at": timestamp},
        ]

        with patch.object(app, "get_connection", return_value=FakeConnection(rows)):
            result = app._read_overview_metrics()

        self.assertEqual(result["latency"]["current"], 182.0)
        self.assertEqual(result["rps"]["current"], 15.0)
        self.assertEqual(result["errorRate"]["current"], 0.444)
        self.assertEqual(result["health"]["status"], "WARNING")

    def test_missing_metrics_remain_null(self):
        with patch.object(app, "get_connection", return_value=FakeConnection([])):
            result = app._read_overview_metrics()

        self.assertIsNone(result["memory"]["current"])
        self.assertEqual(result["memory"]["series"], [])
        self.assertIsNone(result["health"]["status"])

    def test_manual_monitoring_all_metrics(self):
        timestamp = datetime.now().replace(microsecond=0)
        rows = [
            {"metric_name": "CPUUtilization", "metric_value": 41.2, "period_seconds": 60, "collected_at": timestamp},
            {"metric_name": "mem_used_percent", "metric_value": 63.7, "period_seconds": 60, "collected_at": timestamp},
            {"metric_name": "TargetResponseTime", "metric_value": 0.182, "period_seconds": 60, "collected_at": timestamp},
            {"metric_name": "RequestCount", "metric_value": 900, "period_seconds": 60, "collected_at": timestamp},
            {"metric_name": "HTTPCode_Target_5XX_Count", "metric_value": 3, "period_seconds": 60, "collected_at": timestamp},
            {"metric_name": "HTTPCode_ELB_5XX_Count", "metric_value": 1, "period_seconds": 60, "collected_at": timestamp},
            {"metric_name": "StatusCheckFailed", "metric_value": 0, "period_seconds": 60, "collected_at": timestamp},
            {"metric_name": "HealthyHostCount", "metric_value": 2, "period_seconds": 60, "collected_at": timestamp},
            {"metric_name": "UnHealthyHostCount", "metric_value": 0, "period_seconds": 60, "collected_at": timestamp},
        ]

        with patch.object(app, "get_connection", return_value=FakeConnection(rows)):
            result = app._read_monitoring_metrics({"metric": "all", "range": "1h"})

        self.assertEqual(result["summaries"]["latency"]["current"], 182.0)
        self.assertEqual(result["summaries"]["rps"]["current"], 15.0)
        self.assertEqual(result["summaries"]["errorRate"]["current"], 0.444)
        self.assertEqual(result["summaries"]["health"]["current"], "NORMAL")
        self.assertEqual(len(result["series"]), 1)

    def test_manual_monitoring_rejects_invalid_custom_window(self):
        with self.assertRaisesRegex(ValueError, "시작 시간"):
            app._read_monitoring_metrics(
                {
                    "metric": "cpu",
                    "start": "2026-09-21T12:00:00",
                    "end": "2026-09-21T11:00:00",
                }
            )


if __name__ == "__main__":
    unittest.main()
