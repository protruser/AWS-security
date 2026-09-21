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


def _read_dashboard_data():
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT *
                FROM security_events
                WHERE status NOT IN ('조치 완료', '자동 완료', '예외 처리', '완료')
                ORDER BY detected_at DESC
                LIMIT 100
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
