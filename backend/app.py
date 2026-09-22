import hmac
import json
import os
from datetime import datetime, timedelta, timezone
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, jsonify, request, session
from flask_cors import CORS
from openai import OpenAI

from db import get_connection

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-only-change-this-secret")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)

origins = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS", "http://localhost:8443,http://localhost:5173"
    ).split(",")
    if origin.strip()
]
CORS(
    app,
    resources={r"/api/*": {"origins": origins}},
    supports_credentials=True,
)

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}
LOG_RANGE_DELTAS = {
    "15m": timedelta(minutes=15),
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
}
LOG_SOURCES = {"waf", "guardduty", "inspector"}
OVERVIEW_METRIC_NAMES = {
    "CPUUtilization",
    "mem_used_percent",
    "TargetResponseTime",
    "RequestCount",
    "HTTPCode_Target_5XX_Count",
    "HTTPCode_ELB_5XX_Count",
    "StatusCheckFailed",
    "HealthyHostCount",
    "UnHealthyHostCount",
}
OVERVIEW_SERIES_LIMIT = 20
MONITORING_METRIC_ALIASES = {
    "all": "all",
    "cpu": "cpu",
    "memory": "memory",
    "latency": "latency",
    "rps": "rps",
    "errorrate": "errorRate",
    "error-rate": "errorRate",
    "error_rate": "errorRate",
    "health": "health",
}
MONITORING_RAW_METRICS = {
    "cpu": {"CPUUtilization"},
    "memory": {"mem_used_percent"},
    "latency": {"TargetResponseTime"},
    "rps": {"RequestCount"},
    "errorRate": {
        "RequestCount",
        "HTTPCode_Target_5XX_Count",
        "HTTPCode_ELB_5XX_Count",
    },
    "health": {"StatusCheckFailed", "HealthyHostCount", "UnHealthyHostCount"},
}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            return jsonify({"error": "UNAUTHORIZED", "message": "로그인이 필요합니다."}), 401
        return view(*args, **kwargs)

    return wrapped


def _current_user():
    return {
        "username": session.get("username", "admin"),
        "role": session.get("role", os.getenv("ADMIN_ROLE", "관리자")),
        "team": session.get("team", os.getenv("ADMIN_TEAM", "보안관제팀")),
    }


def _json_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except json.JSONDecodeError:
            return []
    return []


def _format_datetime(value, fmt="%Y.%m.%d %H:%M"):
    if value is None:
        return "-"
    if isinstance(value, datetime):
        return value.strftime(fmt)
    return str(value)


def _elapsed_text(value):
    if not isinstance(value, datetime):
        return "-"

    now = datetime.now(value.tzinfo or timezone.utc)
    if value.tzinfo is None:
        now = datetime.now()

    minutes = max(0, int((now - value).total_seconds() // 60))
    if minutes < 60:
        return f"{minutes}분"

    hours, remain = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}시간 {remain}분"

    days, remain_hours = divmod(hours, 24)
    return f"{days}일 {remain_hours}시간"


def _severity(value):
    text = str(value or "Info").capitalize()
    return text if text in VALID_SEVERITIES else "Info"


def _event_to_action_event(row):
    return {
        "id": str(row["id"]),
        "severity": _severity(row.get("severity")),
        "title": row.get("title") or "보안 이벤트",
        "service": row.get("service") or "Unknown",
        "scenarioType": row.get("scenario_type") or "",
        "asset": row.get("asset") or "-",
        "detectedAt": _format_datetime(row.get("detected_at")),
        "elapsed": _elapsed_text(row.get("detected_at")),
        "status": row.get("status") or "검토 필요",
        "recommendation": row.get("recommendation") or "",
        "autoRemediation": bool(row.get("auto_remediation")),
        "highlightAssets": _json_list(row.get("highlight_assets")),
        "attackPath": _json_list(row.get("attack_path")),
        "details": {
            "attackerIP": row.get("attacker_ip") or "",
            "requestURL": row.get("request_url") or "",
            "rule": row.get("rule_name") or "",
            "blocked": (
                bool(row.get("blocked")) if row.get("blocked") is not None else None
            ),
            "logs": row.get("logs") or "",
        },
    }


def _event_to_detect_history(row):
    if row.get("block_result"):
        blocked_text = row["block_result"]
    elif row.get("blocked") is True or row.get("blocked") == 1:
        blocked_text = "차단"
    else:
        blocked_text = "-"

    detected_at = row.get("detected_at")
    return {
        "id": str(row["id"]),
        "time": _format_datetime(detected_at, "%H:%M"),
        "sev": _severity(row.get("severity")),
        "event": row.get("title") or "보안 이벤트",
        "service": row.get("service") or "Unknown",
        "asset": row.get("asset") or "-",
        "ip": row.get("attacker_ip") or "-",
        "blocked": blocked_text,
        "status": row.get("status") or "-",
    }


def _remediation_to_history(row):
    completed = row.get("completed_at")
    requested = row.get("requested_at")
    return {
        "id": str(row["id"]),
        "time": _format_datetime(requested or completed, "%H:%M"),
        "event": row.get("event_title") or row.get("action_type") or "보안 조치",
        "asset": row.get("asset") or "-",
        "method": row.get("method") or "수동",
        "approver": row.get("approver") or "-",
        "result": row.get("result") or row.get("status") or "-",
        "completedAt": _format_datetime(completed, "%H:%M:%S"),
    }


def _event_to_log(row):
    detected_at = row.get("detected_at")
    return {
        "id": str(row["id"]),
        "service": row.get("service") or "-",
        "scenarioType": row.get("scenario_type") or "-",
        "severity": _severity(row.get("severity")),
        "title": row.get("title") or "보안 이벤트",
        "asset": row.get("asset") or None,
        "detectedAt": (
            detected_at.isoformat(timespec="seconds")
            if isinstance(detected_at, datetime)
            else str(detected_at or "")
        ),
        "status": row.get("status") or "-",
        "attackerIp": row.get("attacker_ip") or None,
        "requestUrl": row.get("request_url") or None,
        "ruleName": row.get("rule_name") or None,
        "blocked": (
            bool(row.get("blocked")) if row.get("blocked") is not None else None
        ),
        "blockResult": row.get("block_result") or None,
        "recommendation": row.get("recommendation") or None,
        "autoRemediation": bool(row.get("auto_remediation")),
        "highlightAssets": _json_list(row.get("highlight_assets")),
        "attackPath": _json_list(row.get("attack_path")),
        "logs": row.get("logs") or None,
    }


def _parse_query_datetime(value, label):
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} 날짜/시간 형식이 올바르지 않습니다.") from exc


def _log_time_window(args):
    range_key = str(args.get("range") or "").strip().lower()
    start_text = str(args.get("start") or "").strip()
    end_text = str(args.get("end") or "").strip()

    if range_key:
        if range_key not in LOG_RANGE_DELTAS:
            raise ValueError("지원하지 않는 조회 기간입니다.")
        end_at = datetime.now()
        return end_at - LOG_RANGE_DELTAS[range_key], end_at

    if not start_text or not end_text:
        raise ValueError("조회 기간 또는 시작/종료 시간을 지정해 주세요.")

    start_at = _parse_query_datetime(start_text, "시작")
    end_at = _parse_query_datetime(end_text, "종료")
    if start_at >= end_at:
        raise ValueError("시작 시간은 종료 시간보다 빨라야 합니다.")
    return start_at, end_at


def _read_security_logs(args):
    source = str(args.get("source") or "").strip().lower()
    if source not in LOG_SOURCES:
        raise ValueError("WAF, GuardDuty, Inspector 중 하나를 선택해 주세요.")

    start_at, end_at = _log_time_window(args)
    conditions = ["detected_at >= %s", "detected_at <= %s"]
    params = [start_at, end_at]

    normalized_scenario = "LOWER(COALESCE(scenario_type, ''))"
    if source == "waf":
        conditions.append(f"{normalized_scenario} IN (%s, %s, %s, %s)")
        params.extend(["sqli", "xss", "dir", "brute"])
    elif source == "guardduty":
        conditions.append(f"{normalized_scenario} IN (%s, %s)")
        params.extend(["port", "cred"])
    else:
        conditions.append(f"{normalized_scenario} = %s")
        params.append("vuln")

    severity = str(args.get("severity") or "").strip().capitalize()
    if severity:
        if severity not in VALID_SEVERITIES:
            raise ValueError("지원하지 않는 Severity입니다.")
        conditions.append("severity = %s")
        params.append(severity)

    scenario_type = str(
        args.get("scenario_type") or args.get("finding_type") or ""
    ).strip().lower()
    scenario_filters = {
        "sqli": (f"{normalized_scenario} = %s", ["sqli"]),
        "xss": (f"{normalized_scenario} = %s", ["xss"]),
        "dir": (f"{normalized_scenario} = %s", ["dir"]),
        "brute": (f"{normalized_scenario} = %s", ["brute"]),
        "port": (f"{normalized_scenario} = %s", ["port"]),
        "cred": (f"{normalized_scenario} = %s", ["cred"]),
    }
    if scenario_type:
        allowed_for_source = {
            "waf": {"sqli", "xss", "dir", "brute"},
            "guardduty": {"port", "cred"},
            "inspector": set(),
        }
        if scenario_type not in allowed_for_source[source]:
            raise ValueError("선택한 로그 종류에서 지원하지 않는 공격 유형입니다.")
        scenario_sql, scenario_params = scenario_filters[scenario_type]
        conditions.append(scenario_sql)
        params.extend(scenario_params)

    attacker_ip = str(args.get("attacker_ip") or "").strip()
    if attacker_ip:
        conditions.append("attacker_ip = %s")
        params.append(attacker_ip)

    asset = str(args.get("asset") or "").strip()
    if asset:
        conditions.append("asset LIKE %s")
        params.append(f"%{asset}%")

    action = str(args.get("action") or "").strip().upper()
    if action:
        if source != "waf" or action not in {"BLOCK", "ALLOW"}:
            raise ValueError("지원하지 않는 Action입니다.")
        conditions.append("blocked = %s")
        params.append(action == "BLOCK")

    cve = str(args.get("cve") or "").strip()
    if cve:
        if source != "inspector":
            raise ValueError("CVE 필터는 Inspector 로그에서만 사용할 수 있습니다.")
        cve_like = f"%{cve}%"
        conditions.append("(rule_name LIKE %s OR title LIKE %s OR logs LIKE %s)")
        params.extend([cve_like, cve_like, cve_like])

    query = f"""
        SELECT
            id, service, scenario_type, severity, title, asset, detected_at,
            status, attacker_ip, request_url, rule_name, blocked,
            block_result, recommendation, auto_remediation,
            highlight_assets, attack_path, logs
        FROM security_events
        WHERE {' AND '.join(conditions)}
        ORDER BY detected_at DESC
    """

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(query, params)
            rows = cursor.fetchall()

    return [_event_to_log(row) for row in rows]


def _read_dashboard_data():
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT *
                FROM security_events
                WHERE status NOT IN ('조치 완료', '자동 완료', '예외 처리', '완료')
                ORDER BY detected_at DESC
                """
            )
            action_rows = cursor.fetchall()

            cursor.execute(
                """
                SELECT *
                FROM security_events
                ORDER BY detected_at DESC
                LIMIT 200
                """
            )
            detect_rows = cursor.fetchall()

            cursor.execute(
                """
                SELECT
                    rh.*,
                    se.title AS event_title,
                    se.asset AS asset
                FROM remediation_history rh
                LEFT JOIN security_events se ON se.id = rh.event_id
                ORDER BY COALESCE(rh.completed_at, rh.requested_at) DESC
                LIMIT 200
                """
            )
            remediation_rows = cursor.fetchall()

    return {
        "events": [_event_to_action_event(row) for row in action_rows],
        "detectHistory": [_event_to_detect_history(row) for row in detect_rows],
        "remediationHistory": [
            _remediation_to_history(row) for row in remediation_rows
        ],
    }


def _iso_datetime(value):
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    return str(value) if value else None


def _read_overview_metrics():
    placeholders = ", ".join(["%s"] * len(OVERVIEW_METRIC_NAMES))
    query = f"""
        SELECT metric_name, metric_value, period_seconds, collected_at
        FROM monitoring_metrics
        WHERE metric_name IN ({placeholders})
          AND collected_at >= UTC_TIMESTAMP() - INTERVAL 24 HOUR
        ORDER BY collected_at ASC
    """

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(query, tuple(sorted(OVERVIEW_METRIC_NAMES)))
            rows = cursor.fetchall()

    by_name = {name: [] for name in OVERVIEW_METRIC_NAMES}
    for row in rows:
        by_name[row["metric_name"]].append(row)

    def numeric_metric(name, transform=lambda value, row: value):
        points = by_name[name][-OVERVIEW_SERIES_LIMIT:]
        values = [transform(float(row["metric_value"]), row) for row in points]
        return {
            "current": round(values[-1], 3) if values else None,
            "series": [round(value, 3) for value in values],
            "collectedAt": _iso_datetime(points[-1]["collected_at"]) if points else None,
        }

    cpu = numeric_metric("CPUUtilization")
    memory = numeric_metric("mem_used_percent")
    latency = numeric_metric("TargetResponseTime", lambda value, _: value * 1000)
    rps = numeric_metric(
        "RequestCount",
        lambda value, row: value / max(int(row.get("period_seconds") or 60), 1),
    )

    target_5xx = {
        row["collected_at"]: float(row["metric_value"])
        for row in by_name["HTTPCode_Target_5XX_Count"]
    }
    elb_5xx = {
        row["collected_at"]: float(row["metric_value"])
        for row in by_name["HTTPCode_ELB_5XX_Count"]
    }
    request_rows = by_name["RequestCount"][-OVERVIEW_SERIES_LIMIT:]
    error_values = []
    for row in request_rows:
        request_count = float(row["metric_value"])
        if request_count <= 0:
            error_values.append(0.0)
            continue
        failed = target_5xx.get(row["collected_at"], 0.0) + elb_5xx.get(
            row["collected_at"], 0.0
        )
        error_values.append((failed / request_count) * 100)
    error_rate = {
        "current": round(error_values[-1], 3) if error_values else None,
        "series": [round(value, 3) for value in error_values],
        "collectedAt": (
            _iso_datetime(request_rows[-1]["collected_at"]) if request_rows else None
        ),
    }

    status_rows = by_name["StatusCheckFailed"]
    healthy_rows = by_name["HealthyHostCount"]
    unhealthy_rows = by_name["UnHealthyHostCount"]
    status_check = float(status_rows[-1]["metric_value"]) if status_rows else None
    healthy = float(healthy_rows[-1]["metric_value"]) if healthy_rows else None
    unhealthy = float(unhealthy_rows[-1]["metric_value"]) if unhealthy_rows else None

    health_status = None
    if status_check is not None and healthy is not None and unhealthy is not None:
        if status_check > 0 or healthy == 0:
            health_status = "CRITICAL"
        elif unhealthy > 0:
            health_status = "WARNING"
        else:
            health_status = "NORMAL"

    health_times = [
        points[-1]["collected_at"]
        for points in (status_rows, healthy_rows, unhealthy_rows)
        if points
    ]
    health = {
        "status": health_status,
        "healthy": round(healthy) if healthy is not None else None,
        "unhealthy": round(unhealthy) if unhealthy is not None else None,
        "collectedAt": _iso_datetime(max(health_times)) if health_times else None,
    }

    return {
        "cpu": cpu,
        "memory": memory,
        "latency": latency,
        "rps": rps,
        "errorRate": error_rate,
        "health": health,
    }


def _monitoring_summary(records, field, unit):
    values = [record[field] for record in records if record.get(field) is not None]
    return {
        "current": round(values[-1], 3) if values else None,
        "average": round(sum(values) / len(values), 3) if values else None,
        "max": round(max(values), 3) if values else None,
        "min": round(min(values), 3) if values else None,
        "unit": unit,
    }


def _service_health(status_check, healthy, unhealthy):
    if status_check is None or healthy is None or unhealthy is None:
        return None
    if status_check > 0 or healthy == 0:
        return "CRITICAL"
    if unhealthy > 0:
        return "WARNING"
    return "NORMAL"


def _read_monitoring_metrics(args):
    requested = str(args.get("metric") or "all").strip().lower()
    metric = MONITORING_METRIC_ALIASES.get(requested)
    if metric is None:
        raise ValueError("지원하지 않는 운영 지표입니다.")

    start_at, end_at = _log_time_window(args)
    raw_names = (
        set().union(*MONITORING_RAW_METRICS.values())
        if metric == "all"
        else MONITORING_RAW_METRICS[metric]
    )
    placeholders = ", ".join(["%s"] * len(raw_names))
    query = f"""
        SELECT metric_name, metric_value, period_seconds, collected_at
        FROM monitoring_metrics
        WHERE metric_name IN ({placeholders})
          AND collected_at >= %s
          AND collected_at <= %s
        ORDER BY collected_at ASC
    """
    params = [*sorted(raw_names), start_at, end_at]

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(query, params)
            rows = cursor.fetchall()

    raw_by_time = {}
    periods_by_time = {}
    for row in rows:
        collected_at = row["collected_at"]
        raw_by_time.setdefault(collected_at, {})[row["metric_name"]] = float(
            row["metric_value"]
        )
        periods_by_time.setdefault(collected_at, {})[row["metric_name"]] = int(
            row.get("period_seconds") or 60
        )

    records = []
    for collected_at in sorted(raw_by_time):
        raw = raw_by_time[collected_at]
        request_count = raw.get("RequestCount")
        period_seconds = max(
            periods_by_time[collected_at].get("RequestCount", 60), 1
        )
        error_rate = None
        if request_count is not None:
            if request_count <= 0:
                error_rate = 0.0
            else:
                failures = raw.get("HTTPCode_Target_5XX_Count", 0.0) + raw.get(
                    "HTTPCode_ELB_5XX_Count", 0.0
                )
                error_rate = failures / request_count * 100

        status_check = raw.get("StatusCheckFailed")
        healthy = raw.get("HealthyHostCount")
        unhealthy = raw.get("UnHealthyHostCount")
        record = {
            "timestamp": _iso_datetime(collected_at),
            "cpu": raw.get("CPUUtilization"),
            "memory": raw.get("mem_used_percent"),
            "latency": (
                raw["TargetResponseTime"] * 1000
                if "TargetResponseTime" in raw
                else None
            ),
            "rps": (
                request_count / period_seconds if request_count is not None else None
            ),
            "errorRate": error_rate,
            "health": _service_health(status_check, healthy, unhealthy),
            "healthy": round(healthy) if healthy is not None else None,
            "unhealthy": round(unhealthy) if unhealthy is not None else None,
        }
        records.append(record)

    units = {
        "cpu": "%",
        "memory": "%",
        "latency": "ms",
        "rps": "rps",
        "errorRate": "%",
    }
    summaries = {
        name: _monitoring_summary(records, name, unit)
        for name, unit in units.items()
    }
    health_records = [record for record in records if record["health"] is not None]
    health_summary = {
        "current": health_records[-1]["health"] if health_records else None,
        "healthy": health_records[-1]["healthy"] if health_records else None,
        "unhealthy": health_records[-1]["unhealthy"] if health_records else None,
    }

    if metric == "all":
        visible_records = [
            record
            for record in records
            if any(
                record[field] is not None
                for field in ("cpu", "memory", "latency", "rps", "errorRate", "health")
            )
        ]
        return {
            "metric": "all",
            "window": {"start": _iso_datetime(start_at), "end": _iso_datetime(end_at)},
            "summaries": {**summaries, "health": health_summary},
            "series": visible_records,
        }

    if metric == "health":
        return {
            "metric": "health",
            "window": {"start": _iso_datetime(start_at), "end": _iso_datetime(end_at)},
            "summary": health_summary,
            "series": health_records,
        }

    metric_records = [record for record in records if record[metric] is not None]
    return {
        "metric": metric,
        "window": {"start": _iso_datetime(start_at), "end": _iso_datetime(end_at)},
        "summary": summaries[metric],
        "series": [
            {"timestamp": record["timestamp"], "value": round(record[metric], 3)}
            for record in metric_records
        ],
    }


@app.get("/api/health")
def health():
    try:
        with get_connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1 AS ok")
                result = cursor.fetchone()
        return jsonify({"status": "ok", "db": result["ok"] == 1})
    except Exception as exc:
        app.logger.exception("DB health check failed")
        return jsonify({"status": "error", "message": str(exc)}), 500


@app.get("/api/auth/status")
def auth_status():
    if not session.get("authenticated"):
        return jsonify({"authenticated": False})
    return jsonify({"authenticated": True, "user": _current_user()})


@app.post("/api/auth/login")
def auth_login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username") or "").strip()
    password = str(data.get("password") or "")

    expected_username = os.getenv("ADMIN_USERNAME", "admin")
    expected_password = os.getenv("ADMIN_PASSWORD", "")

    if not expected_password:
        return (
            jsonify(
                {
                    "error": "AUTH_NOT_CONFIGURED",
                    "message": "backend/.env에 ADMIN_PASSWORD를 먼저 설정해 주세요.",
                }
            ),
            503,
        )

    username_ok = hmac.compare_digest(username, expected_username)
    password_ok = hmac.compare_digest(password, expected_password)
    if not (username_ok and password_ok):
        return jsonify({"error": "INVALID_CREDENTIALS", "message": "아이디 또는 비밀번호가 올바르지 않습니다."}), 401

    session.clear()
    session.permanent = True
    session["authenticated"] = True
    session["username"] = expected_username
    session["role"] = os.getenv("ADMIN_ROLE", "관리자")
    session["team"] = os.getenv("ADMIN_TEAM", "보안관제팀")

    return jsonify({"ok": True, "user": _current_user()})


@app.post("/api/auth/logout")
def auth_logout():
    session.clear()
    return jsonify({"ok": True})


@app.get("/api/dashboard")
@login_required
def dashboard():
    try:
        return jsonify(_read_dashboard_data())
    except Exception as exc:
        app.logger.exception("Failed to read dashboard data")
        return jsonify({"error": "DATABASE_READ_FAILED", "message": str(exc)}), 500


@app.get("/api/events")
@login_required
def events():
    try:
        return jsonify(_read_dashboard_data()["events"])
    except Exception as exc:
        app.logger.exception("Failed to read events")
        return jsonify({"error": "DATABASE_READ_FAILED", "message": str(exc)}), 500


@app.get("/api/overview-metrics")
@login_required
def overview_metrics():
    try:
        return jsonify(_read_overview_metrics())
    except Exception as exc:
        app.logger.exception("Failed to read overview metrics")
        return jsonify({"error": "DATABASE_READ_FAILED", "message": str(exc)}), 500


@app.get("/api/logs")
@login_required
def security_logs():
    try:
        logs = _read_security_logs(request.args)
        return jsonify({"logs": logs, "count": len(logs)})
    except ValueError as exc:
        return jsonify({"error": "INVALID_QUERY", "message": str(exc)}), 400
    except Exception as exc:
        app.logger.exception("Failed to read security logs")
        return jsonify({"error": "DATABASE_READ_FAILED", "message": str(exc)}), 500


@app.get("/api/monitoring/metrics")
@login_required
def monitoring_metrics():
    try:
        return jsonify(_read_monitoring_metrics(request.args))
    except ValueError as exc:
        return jsonify({"error": "INVALID_QUERY", "message": str(exc)}), 400
    except Exception as exc:
        app.logger.exception("Failed to read monitoring metrics")
        return jsonify({"error": "DATABASE_READ_FAILED", "message": str(exc)}), 500


@app.post("/api/chat")
@login_required
def chat():
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        return (
            jsonify(
                {
                    "error": "OPENAI_API_KEY_MISSING",
                    "message": "backend/.env에 OPENAI_API_KEY를 설정해 주세요.",
                }
            ),
            503,
        )

    data = request.get_json(silent=True) or {}
    message = str(data.get("message") or "").strip()
    if not message:
        return jsonify({"error": "EMPTY_MESSAGE", "message": "질문을 입력해 주세요."}), 400

    raw_history = data.get("history") if isinstance(data.get("history"), list) else []
    event = data.get("event") if isinstance(data.get("event"), dict) else None

    # 토큰/비용 폭증 방지를 위해 최근 대화만 전달한다.
    input_messages = []
    for item in raw_history[-10:]:
        if not isinstance(item, dict):
            continue
        role = "assistant" if item.get("role") == "bot" else "user"
        text = str(item.get("text") or "").strip()
        if text:
            input_messages.append({"role": role, "content": text[:4000]})
    input_messages.append({"role": "user", "content": message[:4000]})

    event_context = "선택된 보안 이벤트 없음"
    if event:
        safe_event = {
            "id": event.get("id"),
            "severity": event.get("severity"),
            "title": event.get("title"),
            "service": event.get("service"),
            "asset": event.get("asset"),
            "detectedAt": event.get("detectedAt"),
            "status": event.get("status"),
            "recommendation": event.get("recommendation"),
            "attackPath": event.get("attackPath"),
            "highlightAssets": event.get("highlightAssets"),
            "details": {
                "attackerIP": (event.get("details") or {}).get("attackerIP"),
                "requestURL": (event.get("details") or {}).get("requestURL"),
                "rule": (event.get("details") or {}).get("rule"),
                "blocked": (event.get("details") or {}).get("blocked"),
                "logs": str((event.get("details") or {}).get("logs") or "")[:4000],
            },
        }
        event_context = json.dumps(safe_event, ensure_ascii=False)

    instructions = f"""
너는 AWS Security Monitoring Center의 보안 분석 어시스턴트다.
답변은 한국어로 간결하고 실무적으로 작성한다.
선택된 이벤트 컨텍스트와 사용자가 제공한 정보에 근거해서만 사실을 단정한다.
정보가 부족하면 부족하다고 명확히 말하고 확인할 AWS 로그/서비스를 제안한다.
실제 AWS 변경이나 차단을 수행했다고 말하지 않는다. 대시보드 사용자가 판단할 수 있도록 분석과 권장 조치만 제공한다.

현재 선택된 이벤트 컨텍스트:
{event_context}
""".strip()

    try:
        client = OpenAI(api_key=api_key)
        response = client.responses.create(
            model=os.getenv("OPENAI_MODEL", "gpt-5.6-luna"),
            instructions=instructions,
            input=input_messages,
            store=False,
            max_output_tokens=int(os.getenv("OPENAI_MAX_OUTPUT_TOKENS", "700")),
        )
        answer = (response.output_text or "").strip()
        if not answer:
            answer = "분석 결과를 생성하지 못했습니다. 다시 질문해 주세요."

        actions = []
        if event:
            if event.get("attackPath"):
                actions.append("공격 경로 강조")
            if event.get("recommendation"):
                actions.append("권장 조치 보기")

        return jsonify({"text": answer, "actions": actions})
    except Exception as exc:
        app.logger.exception("OpenAI chat request failed")
        return (
            jsonify(
                {
                    "error": "OPENAI_REQUEST_FAILED",
                    "message": f"OpenAI API 요청 실패: {exc}",
                }
            ),
            502,
        )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)
