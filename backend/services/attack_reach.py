"""IP별 공격 도달 단계 판정 (1단계: 기존 security_events 데이터만 사용).

DB 에 의존하지 않는 순수 함수만 둔다. app.py 가 행을 읽어 넘겨준다.

단계
  S1 정찰        GuardDuty 포트 스캔 (대상 인스턴스까지)
  S2 경계 차단   WAF 가 그 구간의 요청을 전부 막음
  S3 일부 통과   WAF 가 일부만 막음 → ALB 도달은 확인, 그 뒤는 추정
  S4 통과        WAF 가 하나도 못 막음 → ALB 도달은 확인, 그 뒤는 추정
  C  클라우드    탈취 자격증명으로 AWS API 호출 (네트워크 경로와 별개)

WAF 이벤트는 blocked/block_result 컬럼이 아니라 Lambda B 가 logs 에 남긴 원래 수치
(count/blocked)로 판정한다. Remediation Lambda 가 IP 차단에 성공하면 그 이벤트의
blocked/block_result 를 TRUE/'성공'으로 덮어써서, 컬럼만 보면 WAF 를 통과했던 공격도
경계에서 막힌 것처럼 보이기 때문이다.
"""
import ipaddress
import json
import re
from datetime import timedelta, timezone

WAF_TYPES = {"sqli", "xss", "dir", "brute", "flood"}
STAGE_RANK = {"S1": 1, "S2": 2, "S3": 3, "S4": 4}
SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
CLOSED_STATUSES = {"조치 완료", "자동 완료", "완료", "예외 처리"}
EXCLUDED_STATUS = "예외 처리"

# 차단 직후 같은 5분 구간(Lambda B 의 집계 단위)에 차단 전 요청이 섞여 있을 수 있어서,
# 차단 시각에서 한 구간이 지난 뒤의 통과만 "차단 후 재시도"로 본다.
BYPASS_GRACE = timedelta(minutes=5)

WAF_PATHS = {
    "shop": {"edge": ["attacker", "igw", "shopWAF"], "alb": "shopALB", "inner": ["k3s", "flaskApp"]},
    "admin": {"edge": ["attacker", "igw", "adminWAF"], "alb": "dashALB", "inner": ["dashEC2"]},
}

# EC2 Name 태그(예: dragon-01-k3s-nginx) 안의 역할 이름 → 대시보드 맵 자산 ID
NAME_TAG_ASSETS = [
    ("security-mysql", "secMySQL"),
    ("shop-mysql", "shopMySQL"),
    ("shop-app", "flaskApp"),
    ("k3s", "k3s"),
    ("dashboard", "dashEC2"),
]
INSTANCE_ID_RE = re.compile(r"\bi-[0-9a-f]{8,17}\b")
FALLBACK_BLOCK_RESULT = {"성공": "S2", "차단": "S2", "부분": "S3", "실패": "S4"}


def load_instance_map(text):
    """환경변수 INSTANCE_ASSET_MAP(JSON: {"i-...": "k3s"}) → dict. 잘못된 값이면 빈 dict."""
    try:
        value = json.loads(text or "{}")
    except (TypeError, ValueError):
        return {}
    return {str(k): str(v) for k, v in value.items()} if isinstance(value, dict) else {}


INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
    "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128",
)]


def is_internal_ip(ip):
    """조직 내부에서 나온 주소(RFC1918·CGNAT·루프백·링크로컬). 문서용 예약 대역은 포함하지 않는다."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in INTERNAL_NETWORKS if net.version == addr.version)


def _parse_logs(value):
    if isinstance(value, dict):
        return value
    try:
        parsed = json.loads(value or "{}")
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _waf_counts(logs):
    """Lambda B 가 남긴 (전체 요청 수, 차단 수). 없거나 이상하면 None."""
    count, blocked = logs.get("count"), logs.get("blocked")
    if isinstance(count, bool) or isinstance(blocked, bool):
        return None
    if not isinstance(count, int) or not isinstance(blocked, int) or count <= 0:
        return None
    return count, min(max(blocked, 0), count)


def _waf_source(logs, asset):
    source = logs.get("waf")
    if source in WAF_PATHS:
        return source
    return "admin" if "admin" in str(asset or "").lower() else "shop"


def _instance_asset(logs, asset, instance_map):
    """포트 스캔 대상 인스턴스 → 맵 자산 ID. Name 태그 → INSTANCE_ASSET_MAP 순으로 찾는다."""
    finding = logs.get("finding") if isinstance(logs.get("finding"), dict) else {}
    resources = finding.get("Resources") or [{}]
    resource = resources[0] if isinstance(resources[0], dict) else {}
    name = str((resource.get("Tags") or {}).get("Name") or "").lower()
    for marker, asset_id in NAME_TAG_ASSETS:
        if marker in name:
            return asset_id
    match = INSTANCE_ID_RE.search(f"{resource.get('Id') or ''} {asset or ''}")
    return instance_map.get(match.group(0)) if match else None


def classify_event(row, instance_map=None, remediated=False):
    """이벤트 1건 → 도달 판정 dict. IP 별 화면에 넣지 않을 이벤트면 None.

    remediated: 이 이벤트에 IP 차단 조치 기록이 있는지. logs 수치가 없어 block_result 로
    대신 판정할 때, 조치로 덮어쓴 값일 수 있으므로 신뢰도를 낮춘다.
    """
    if not str(row.get("attacker_ip") or "").strip():
        return None
    kind = str(row.get("scenario_type") or "").lower()
    logs = _parse_logs(row.get("logs"))

    if kind in WAF_TYPES:
        source = _waf_source(logs, row.get("asset"))
        counts = _waf_counts(logs)
        if counts:
            total, blocked = counts
            passed = total - blocked
            stage = "S2" if passed == 0 else ("S4" if blocked == 0 else "S3")
            confidence = "confirmed"
            requests = total
        else:
            passed = requests = None
            stage = FALLBACK_BLOCK_RESULT.get(str(row.get("block_result") or ""))
            if stage is None:
                stage = "S4" if row.get("blocked") in (0, False) else "S2"
                confidence = "uncertain"
            else:
                confidence = "uncertain" if remediated else "fallback"
        path = WAF_PATHS[source]
        if stage == "S2":
            reach = {"confirmed": list(path["edge"]), "estimated": []}
        else:
            reach = {"confirmed": path["edge"] + [path["alb"]], "estimated": list(path["inner"])}
        return {"stage": stage, "confidence": confidence, "source": source,
                "requests": requests, "passed": passed, "target": None, "reach": reach}

    if kind == "port":
        target = _instance_asset(logs, row.get("asset"), instance_map or {})
        return {"stage": "S1", "confidence": "confirmed", "source": None,
                "requests": None, "passed": None, "target": target,
                "reach": {"confirmed": ["attacker", target] if target else ["attacker"], "estimated": []}}

    if kind == "cred":
        return {"stage": "C", "confidence": "confirmed", "source": None,
                "requests": None, "passed": None, "target": None,
                "reach": {"confirmed": [], "estimated": []}}

    return None


def _iso(value):
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def _sum_known(values):
    known = [v for v in values if v is not None]
    return sum(known) if known else None


def _block_state(ip, timeline, remediations):
    blocks = [r for r in remediations if r.get("action_type") == "block_ip"]
    done = sorted(r["completed_at"] for r in blocks if r.get("result") == "성공" and r.get("completed_at"))
    if done:
        blocked_at = done[0]
        bypassed = any(
            item["stage"] in ("S3", "S4") and not item["excluded"]
            and item["_time"] >= blocked_at + BYPASS_GRACE
            for item in timeline
        )
        return {"state": "bypassed" if bypassed else "blocked", "at": _iso(blocked_at), "reason": None}
    if any("관리자" in str(r.get("result_detail") or "") for r in blocks):
        return {"state": "excluded", "at": None, "reason": "관리자 IP 대역"}
    # Remediation Lambda(block_ip)가 거부하는 주소: IPv6 / 사설·예약 대역 / 루프백 등
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"state": "none", "at": None, "reason": None}
    if addr.version != 4:
        return {"state": "excluded", "at": None, "reason": "IPv6"}
    if is_internal_ip(ip):
        return {"state": "excluded", "at": None, "reason": "내부 IP"}
    if addr.is_private or addr.is_multicast or addr.is_reserved:
        return {"state": "excluded", "at": None, "reason": "예약 대역"}
    return {"state": "none", "at": None, "reason": None}


def build_ip_detail(ip, rows, remediations, instance_map=None):
    """IP 하나의 이벤트 행(시간순)과 조치 이력 → 요약 + 타임라인."""
    remediated_ids = {str(r.get("event_id")) for r in remediations if r.get("action_type") == "block_ip"}
    timeline = []
    for row in rows:
        verdict = classify_event(row, instance_map, remediated=str(row.get("id")) in remediated_ids)
        if verdict is None:
            continue
        status = row.get("status") or "검토 필요"
        timeline.append({
            "eventId": str(row.get("id")),
            "time": _iso(row.get("detected_at")),
            "_time": row.get("detected_at"),
            "scenarioType": str(row.get("scenario_type") or "").lower(),
            "title": row.get("title") or "",
            "severity": row.get("severity") or "Info",
            "status": status,
            "excluded": status == EXCLUDED_STATUS,
            **verdict,
        })
    if not timeline:
        return None
    timeline.sort(key=lambda item: item["_time"])

    counted = [item for item in timeline if not item["excluded"]]
    staged = [item for item in counted if item["stage"] in STAGE_RANK]
    max_stage = max((item["stage"] for item in staged), key=STAGE_RANK.get, default=None)
    at_max = [item for item in staged if item["stage"] == max_stage]
    if not at_max:
        max_confidence = None
    elif any(item["confidence"] == "confirmed" for item in at_max):
        max_confidence = "confirmed"
    elif any(item["confidence"] == "fallback" for item in at_max):
        max_confidence = "fallback"
    else:
        max_confidence = "uncertain"

    confirmed, estimated = [], []
    for item in counted:
        for asset_id in item["reach"]["confirmed"]:
            if asset_id not in confirmed:
                confirmed.append(asset_id)
    for item in counted:
        for asset_id in item["reach"]["estimated"]:
            if asset_id not in confirmed and asset_id not in estimated:
                estimated.append(asset_id)

    scenario_types = []
    for item in timeline:
        if item["scenarioType"] not in scenario_types:
            scenario_types.append(item["scenarioType"])

    summary = {
        "ip": ip,
        "isInternal": is_internal_ip(ip),
        "firstSeen": timeline[0]["time"],
        "lastSeen": timeline[-1]["time"],
        "eventCount": len(timeline),
        # 요청 수를 아는 이벤트(Lambda B 수치가 있는 WAF 이벤트)가 하나도 없으면 null
        "requestCount": _sum_known(item["requests"] for item in counted),
        "passedCount": _sum_known(item["passed"] for item in counted),
        "scenarioTypes": scenario_types,
        "maxSeverity": max((item["severity"] for item in counted),
                           key=lambda s: SEVERITY_RANK.get(s, -1), default=None),
        "maxStage": max_stage,
        "maxStageConfidence": max_confidence,
        "cloudAccess": any(item["stage"] == "C" for item in counted),
        "openEvents": sum(1 for item in timeline if item["status"] not in CLOSED_STATUSES),
        "block": _block_state(ip, timeline, remediations),
    }
    for item in timeline:
        del item["_time"]
    remediation_items = [
        {
            "eventId": str(r.get("event_id")),
            "time": _iso(r.get("completed_at") or r.get("requested_at")),
            "action": r.get("action_type"),
            "method": r.get("method"),
            "result": r.get("result"),
            "detail": r.get("result_detail"),
        }
        for r in sorted(remediations, key=lambda r: r.get("completed_at") or r.get("requested_at"))
    ]
    return {"ip": ip, "summary": summary, "timeline": timeline,
            "remediations": remediation_items, "reach": {"confirmed": confirmed, "estimated": estimated}}


def _risk_key(summary):
    return (
        summary["block"]["state"] == "bypassed",
        STAGE_RANK.get(summary["maxStage"], 0),
        summary["cloudAccess"],
        summary["lastSeen"] or "",
    )


def build_attacker_list(rows, remediations, instance_map=None):
    """기간 내 이벤트 행과 조치 이력 → IP 별 요약 목록(위험도 순) + 전체 요약."""
    rows_by_ip, rem_by_ip = {}, {}
    for row in rows:
        ip = str(row.get("attacker_ip") or "").strip()
        if ip:
            rows_by_ip.setdefault(ip, []).append(row)
    for rem in remediations:
        ip = str(rem.get("attacker_ip") or "").strip()
        if ip:
            rem_by_ip.setdefault(ip, []).append(rem)

    items = []
    for ip, ip_rows in rows_by_ip.items():
        detail = build_ip_detail(ip, ip_rows, rem_by_ip.get(ip, []), instance_map)
        if detail:
            items.append(detail["summary"])
    items.sort(key=_risk_key, reverse=True)
    return {
        "items": items,
        "summary": {
            "ips": len(items),
            "passedIps": sum(1 for s in items if s["maxStage"] in ("S3", "S4")),
            "bypassed": sum(1 for s in items if s["block"]["state"] == "bypassed"),
            "cloud": sum(1 for s in items if s["cloudAccess"]),
        },
    }
