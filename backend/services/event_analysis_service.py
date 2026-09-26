"""Read-only event interpretation; never executes or changes remediation policy."""
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Literal

from openai import OpenAI
from pydantic import BaseModel, ConfigDict, Field

BASE = Path(__file__).resolve().parents[1]
RULES = json.loads((BASE / "rules/security_event_scenarios.json").read_text(encoding="utf-8"))
PROMPT = (BASE / "prompts/security_event_analysis.txt").read_text(encoding="utf-8")
ACTION_DESCRIPTIONS = {
    "block_ip": "승인 후 기존 IP 차단 정책에 출발지 IP를 등록합니다.",
    "disable_access_key": "승인 후 기존 정책에 따라 대상 Access Key를 비활성화합니다.",
}


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    label: str = Field(min_length=1, max_length=120)
    value: str = Field(min_length=1, max_length=4000)
    description: str = Field(min_length=1, max_length=1000)


class EventAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    event_status: Literal["CONFIRMED", "SUSPICIOUS", "INFORMATIONAL"]
    attack_type: str = Field(min_length=1, max_length=120)
    summary: str = Field(min_length=1, max_length=2000)
    key_evidence: list[Evidence] = Field(min_length=2, max_length=5)
    impact: str = Field(min_length=1, max_length=2000)
    remediation_type: Literal["AUTO", "MANUAL"]
    automatic_action: str | None
    recommended_actions: list[str] = Field(max_length=5)
    additional_check: list[str] = Field(max_length=3)


ANALYSIS_SCHEMA = EventAnalysis.model_json_schema()


class AnalysisUnavailable(Exception):
    pass


class AnalysisBusy(AnalysisUnavailable):
    pass


class EventNotFound(AnalysisUnavailable):
    pass


def _leaves(value, path=""):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _leaves(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _leaves(item, f"{path}[{index}]")
    elif value is not None:
        text = json.dumps(value) if isinstance(value, bool) else str(value)
        if text.strip():
            yield {"path": path, "value": text}


def build_context(event, actions):
    scenario = event.get("scenario_type")
    if scenario not in RULES:
        raise AnalysisUnavailable("Unsupported scenario")
    raw = event.get("logs")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            pass
    # actions: 유형 → 조치 dict, 또는 이벤트를 받아 조치를 돌려주는 함수(app._auto_action).
    # 함수면 역할 키 cred 처럼 조치에 필요한 데이터가 없는 이벤트를 수동으로 판단할 수 있다.
    action = actions(event) if callable(actions) else actions.get(scenario)
    if action and action not in ACTION_DESCRIPTIONS:
        raise AnalysisUnavailable("Unknown configured action")
    facts = {key: event.get(key) for key in (
        "service", "severity", "asset", "attacker_ip", "request_url", "rule_name", "blocked",
    )}
    raw_leaves = list(_leaves(raw, "raw_logs"))
    cves = sorted({match for leaf in raw_leaves for match in
                   re.findall(r"\bCVE-\d{4}-\d{4,}\b", leaf["value"], re.I)}) if scenario == "vuln" else []
    evidence = list(_leaves(facts, "event")) + raw_leaves
    # CVE can be embedded in an Inspector finding URL or unstructured log line.
    evidence += [{"path": "raw_logs.CVE", "value": value} for value in cves]
    return {
        "event_id": event["id"], "scenario_type": scenario,
        "scenario_rule": RULES[scenario],
        "remediation_type": "AUTO" if action else "MANUAL",
        "configured_action": ACTION_DESCRIPTIONS.get(action),
        "event": {**facts, "title": event.get("title"),
                  "detected_at": str(event["detected_at"]) if event.get("detected_at") else None},
        "raw_logs": raw, "evidence_values": evidence, "inspector_cves": cves,
    }


def _sentence_count(text):
    # Split sentence punctuation only at whitespace/end; IPs/versions/URLs stay intact.
    return len([part for part in re.split(r"[.!?。](?:\s+|$)", text.strip()) if part.strip()])


def validate_analysis(data, context):
    result = EventAnalysis.model_validate(data).model_dump()
    if not 2 <= _sentence_count(result["summary"]) <= 3 or not 1 <= _sentence_count(result["impact"]) <= 3:
        raise AnalysisUnavailable("Invalid sentence count")
    if result["attack_type"] != context["scenario_rule"]["display_name"]:
        raise AnalysisUnavailable("Wrong scenario")
    if result["remediation_type"] != context["remediation_type"]:
        raise AnalysisUnavailable("Policy mismatch")
    if result["remediation_type"] == "AUTO":
        if result["recommended_actions"] or result["automatic_action"] != context["configured_action"]:
            raise AnalysisUnavailable("Invented automatic action")
    elif result["automatic_action"] is not None or not 1 <= len(result["recommended_actions"]) <= 5:
        raise AnalysisUnavailable("Invalid manual action")
    if any(not item.strip() for key in ("recommended_actions", "additional_check") for item in result[key]):
        raise AnalysisUnavailable("Empty action")
    values = {item["value"] for item in context["evidence_values"]}
    if any(item["value"] not in values for item in result["key_evidence"]):
        raise AnalysisUnavailable("Ungrounded evidence")
    cves = set(context["inspector_cves"])
    if cves and not cves.intersection(item["value"] for item in result["key_evidence"]):
        raise AnalysisUnavailable("Missing Inspector CVE")
    output_cves = set(re.findall(r"\bCVE-\d{4}-\d{4,}\b", json.dumps(result), re.I))
    if not output_cves.issubset(cves):
        raise AnalysisUnavailable("Ungrounded CVE")
    ip_pattern = r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"
    source_ips = set(re.findall(ip_pattern, json.dumps([context["event"], context["raw_logs"]])))
    if not set(re.findall(ip_pattern, json.dumps(result))).issubset(source_ips):
        raise AnalysisUnavailable("Ungrounded IP")
    return result


def generate_analysis(context, model):
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise AnalysisUnavailable("Missing API configuration")
    content = json.dumps(context, ensure_ascii=False)
    # Reject oversized inputs rather than silently dropping potentially decisive logs.
    if len(content) > 100_000:
        raise AnalysisUnavailable("Event too large")
    with OpenAI(api_key=api_key, timeout=40, max_retries=0) as client:
        response = client.responses.create(
            model=model, store=False,
            input=[{"role": "system", "content": PROMPT}, {"role": "user", "content": content}],
            text={"format": {"type": "json_schema", "name": "security_event_analysis",
                             "strict": True, "schema": ANALYSIS_SCHEMA}},
        )
    if response.status != "completed" or not response.output_text:
        raise AnalysisUnavailable("Incomplete or refused analysis")
    return validate_analysis(json.loads(response.output_text), context)


def analyze_event(event_id, connection_factory, actions):
    model = os.getenv("OPENAI_EVENT_ANALYSIS_MODEL") or os.getenv("OPENAI_MODEL", "gpt-5.6-luna")
    # Connection-scoped MySQL lock serializes across Flask workers without locking
    # security_events rows or blocking approval/exception updates during AI calls.
    lock_name = "event-ai:" + hashlib.sha256(event_id.encode()).hexdigest()[:48]
    with connection_factory() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT GET_LOCK(%s, 0) AS acquired", (lock_name,))
            if cursor.fetchone()["acquired"] != 1:
                raise AnalysisBusy("Analysis in progress")
            try:
                cursor.execute("SELECT * FROM security_events WHERE id = %s", (event_id,))
                event = cursor.fetchone()
                if not event:
                    raise EventNotFound("Event not found")
                context = build_context(event, actions)
                fingerprint = hashlib.sha256(json.dumps(
                    [context, model, PROMPT, ANALYSIS_SCHEMA], ensure_ascii=False, sort_keys=True,
                ).encode()).hexdigest()
                cursor.execute("SELECT result, input_hash FROM event_ai_analyses WHERE event_id = %s", (event_id,))
                cached = cursor.fetchone()
                if cached and cached["input_hash"] == fingerprint:
                    value = cached["result"]
                    return validate_analysis(json.loads(value) if isinstance(value, str) else value, context)
                result = generate_analysis(context, model)
                # Validate at the persistence boundary too; never cache invalid output.
                result = validate_analysis(result, context)
                cursor.execute(
                    "INSERT INTO event_ai_analyses (event_id, input_hash, result, model) VALUES (%s, %s, %s, %s) "
                    "ON DUPLICATE KEY UPDATE input_hash=VALUES(input_hash), result=VALUES(result), "
                    "model=VALUES(model), created_at=CURRENT_TIMESTAMP",
                    (event_id, fingerprint, json.dumps(result, ensure_ascii=False), model),
                )
                return result
            finally:
                cursor.execute("SELECT RELEASE_LOCK(%s)", (lock_name,))
