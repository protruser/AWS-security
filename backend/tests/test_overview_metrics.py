import sys
import unittest
from datetime import datetime, timedelta
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

    def execute(self, query, params=None):
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


def service_metric_rows(window_start, k3s_status="degraded", k3s_unhealthy=1):
    """Lambda C 가 5분 구간마다 남기는 service_metrics 행 (서버 5대).

    요청 지표는 ALB 뒤에 있는 k3s·dashboard 에만 있고, 나머지 서버는 CPU·메모리만 있다.
    """
    window_end = window_start + timedelta(minutes=5)

    def row(server, status, cpu, memory, requests=None, latency=None, error_rate=None,
            healthy=None, unhealthy=None):
        return {
            "server": server, "status": status, "cpu_percent": cpu, "memory_percent": memory,
            "request_count": requests, "avg_latency_ms": latency, "error_rate_percent": error_rate,
            "healthy_targets": healthy, "unhealthy_targets": unhealthy,
            "window_start": window_start, "window_end": window_end,
        }

    return [
        row("k3s", k3s_status, 40, 60, requests=900, latency=180, error_rate=0.5, healthy=1, unhealthy=k3s_unhealthy),
        row("dashboard", "healthy", 20, 50, requests=300, latency=60, error_rate=0.0, healthy=1, unhealthy=0),
        row("shop_app", "healthy", 30, 70),
        row("shop_db", "healthy", 10, 80),
        row("security_db", "healthy", 50, 40),
    ]


class OverviewMetricsTest(unittest.TestCase):
    def test_conversions_and_health_evaluation(self):
        rows = service_metric_rows(datetime(2026, 9, 21, 12, 0))

        with patch.object(app, "get_connection", return_value=FakeConnection(rows)):
            result = app._read_overview_metrics()

        # CPU·메모리: 값이 있는 서버 5대의 평균
        self.assertEqual(result["cpu"]["current"], 30.0)
        self.assertEqual(result["memory"]["current"], 60.0)
        # 지연시간: 요청 수로 가중 평균 (180*900 + 60*300) / 1200
        self.assertEqual(result["latency"]["current"], 150.0)
        # 초당 요청: 5분(300초) 합계 1200 / 300
        self.assertEqual(result["rps"]["current"], 4.0)
        # 오류율: ALB 뒤 서버만, (0.5% * 900) / 1200
        self.assertEqual(result["errorRate"]["current"], 0.375)
        # degraded 서버가 있으면 WARNING, 대상 수는 ALB 뒤 서버 합계
        self.assertEqual(result["health"]["status"], "WARNING")
        self.assertEqual((result["health"]["healthy"], result["health"]["unhealthy"]), (2, 1))
        self.assertEqual(result["cpu"]["collectedAt"], "2026-09-21T12:05:00Z")

    def test_missing_metrics_remain_null(self):
        with patch.object(app, "get_connection", return_value=FakeConnection([])):
            result = app._read_overview_metrics()

        self.assertIsNone(result["memory"]["current"])
        self.assertEqual(result["memory"]["series"], [])
        self.assertIsNone(result["health"]["status"])

    def test_manual_monitoring_all_metrics(self):
        rows = service_metric_rows(
            datetime.now().replace(second=0, microsecond=0) - timedelta(minutes=10),
            k3s_status="healthy",
            k3s_unhealthy=0,
        )

        with patch.object(app, "get_connection", return_value=FakeConnection(rows)):
            result = app._read_monitoring_metrics({"metric": "all", "range": "1h"})

        self.assertEqual(result["summaries"]["latency"]["current"], 150.0)
        self.assertEqual(result["summaries"]["rps"]["current"], 4.0)
        self.assertEqual(result["summaries"]["errorRate"]["current"], 0.375)
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
