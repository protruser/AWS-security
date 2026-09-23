"""AI diagnosis service for the SK Shieldus-based AWS 33-rule assessment.

Responsibilities
----------------
1. Load the structured 33-rule JSON file.
2. Receive the AWS current-state evidence produced by ``aws_collector.py``.
3. Split diagnosis into the four Shieldus categories to reduce prompt size and
   make missing results easier to detect.
4. Ask the OpenAI Responses API to perform the actual PASS/FAIL/REVIEW/N/A
   judgement using only the supplied rules and evidence.
5. Validate that every requested rule was returned exactly once.
6. Merge the four category results and build a dashboard-friendly summary.

This module DOES NOT modify AWS resources and DOES NOT perform remediation.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set

from openai import OpenAI


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_RULE_FILE = BASE_DIR / "rules" / "shieldus_aws_33_rules.json"
DEFAULT_PROMPT_FILE = BASE_DIR / "prompts" / "shieldus_diagnosis.txt"

CATEGORY_ORDER: Sequence[str] = (
    "계정 관리",
    "권한 관리",
    "가상 리소스 관리",
    "운영 관리",
)

VALID_STATUS: Set[str] = {"PASS", "FAIL", "REVIEW", "N/A"}

# Only the AWS sections needed by each category are sent to the model.
# This keeps the prompt smaller while preserving the evidence required by the
# current rule file.
CATEGORY_STATE_KEYS: Mapping[str, Sequence[str]] = {
    "계정 관리": (
        "metadata",
        "identity",
        "project_policy",
        "iam",
        "ec2",
    ),
    "권한 관리": (
        "metadata",
        "identity",
        "project_policy",
        "iam",
    ),
    "가상 리소스 관리": (
        "metadata",
        "identity",
        "project_policy",
        "ec2",
        "s3",
        "rds",
        "elbv2",
        "elb",
        "acm",
        "cloudtrail",
    ),
    "운영 관리": (
        "metadata",
        "identity",
        "project_policy",
        "ec2",
        "s3",
        "rds",
        "docdb",
        "elbv2",
        "elb",
        "acm",
        "cloudfront",
        "cloudtrail",
        "logs",
        "ssm",
    ),
}


DIAGNOSIS_TEXT_FORMAT: Dict[str, Any] = {
    "type": "json_schema",
    "name": "aws_security_diagnosis",
    "strict": True,
    "schema": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "category": {"type": "string"},
            "results": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "rule_id": {"type": "string"},
                        "status": {
                            "type": "string",
                            "enum": ["PASS", "FAIL", "REVIEW", "N/A"],
                        },
                        "severity": {"type": "string"},
                        "resource_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "current_value": {"type": "string"},
                        "expected_value": {"type": "string"},
                        "evidence": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": False,
                                "properties": {
                                    "resource": {"type": "string"},
                                    "path": {"type": "string"},
                                    "value": {"type": "string"},
                                },
                                "required": ["resource", "path", "value"],
                            },
                        },
                        "reason": {"type": "string"},
                        "recommendation": {"type": "string"},
                    },
                    "required": [
                        "rule_id",
                        "status",
                        "severity",
                        "resource_ids",
                        "current_value",
                        "expected_value",
                        "evidence",
                        "reason",
                        "recommendation",
                    ],
                },
            },
        },
        "required": ["category", "results"],
    },
}


class DiagnosisError(RuntimeError):
    """Raised when an AI diagnosis response cannot be trusted structurally."""


class AIDiagnosisService:
    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        rule_file: Path = DEFAULT_RULE_FILE,
        prompt_file: Path = DEFAULT_PROMPT_FILE,
        max_output_tokens: Optional[int] = None,
    ) -> None:
        self.api_key = (api_key or os.getenv("OPENAI_API_KEY", "")).strip()
        if not self.api_key:
            raise DiagnosisError("OPENAI_API_KEY가 설정되어 있지 않습니다.")

        self.model = model or os.getenv("OPENAI_DIAGNOSIS_MODEL") or os.getenv(
            "OPENAI_MODEL", "gpt-5.6-luna"
        )
        self.max_output_tokens = max_output_tokens or int(
            os.getenv("OPENAI_DIAGNOSIS_MAX_OUTPUT_TOKENS", "9000")
        )
        self.rule_file = Path(rule_file)
        self.prompt_file = Path(prompt_file)
        self.client = OpenAI(api_key=self.api_key)

        self.rule_bundle = self._load_json(self.rule_file)
        self.instructions = self.prompt_file.read_text(encoding="utf-8").strip()
        self.rules = list(self.rule_bundle.get("rules") or [])

        if len(self.rules) != 33:
            raise DiagnosisError(
                f"진단 기준 파일의 rules 개수가 33개가 아닙니다: {len(self.rules)}개"
            )

    @staticmethod
    def _load_json(path: Path) -> Dict[str, Any]:
        try:
            with path.open("r", encoding="utf-8") as fp:
                data = json.load(fp)
        except FileNotFoundError as exc:
            raise DiagnosisError(f"파일을 찾을 수 없습니다: {path}") from exc
        except json.JSONDecodeError as exc:
            raise DiagnosisError(f"JSON 형식이 올바르지 않습니다: {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise DiagnosisError(f"JSON 최상위 값은 object여야 합니다: {path}")
        return data

    def _rules_for_category(self, category: str) -> List[Dict[str, Any]]:
        rules = [r for r in self.rules if r.get("category") == category]
        if not rules:
            raise DiagnosisError(f"카테고리에 해당하는 규칙이 없습니다: {category}")
        return rules

    @staticmethod
    def _collection_errors_for_sections(
        errors: Iterable[Mapping[str, Any]], section_keys: Sequence[str]
    ) -> List[Mapping[str, Any]]:
        prefixes = {
            "iam": ("iam.",),
            "ec2": ("ec2.",),
            "s3": ("s3.", "s3control."),
            "rds": ("rds.",),
            "docdb": ("docdb.",),
            "elbv2": ("elbv2.",),
            "elb": ("elb.",),
            "acm": ("acm.",),
            "cloudfront": ("cloudfront.",),
            "cloudtrail": ("cloudtrail.",),
            "logs": ("logs.",),
            "ssm": ("ssm.",),
        }
        allowed_prefixes = tuple(
            prefix
            for key in section_keys
            for prefix in prefixes.get(key, ())
        )
        if not allowed_prefixes:
            return []
        return [
            error
            for error in errors
            if str(error.get("source") or "").startswith(allowed_prefixes)
        ]

    def _state_for_category(
        self, category: str, aws_state: Mapping[str, Any]
    ) -> Dict[str, Any]:
        keys = CATEGORY_STATE_KEYS.get(category)
        if not keys:
            raise DiagnosisError(f"지원하지 않는 카테고리입니다: {category}")

        state = {key: aws_state.get(key) for key in keys if key in aws_state}

        # The rule file uses sts.account_id as an evidence alias while the
        # collector stores the same value under identity.account_id.
        identity = aws_state.get("identity") or {}
        state["sts"] = {"account_id": identity.get("account_id")}

        all_errors = aws_state.get("collection_errors") or []
        state["collection_errors"] = self._collection_errors_for_sections(
            all_errors, keys
        )
        return state

    @staticmethod
    def _request_payload(
        *,
        category: str,
        rules: Sequence[Mapping[str, Any]],
        aws_state: Mapping[str, Any],
        diagnosis_contract: Mapping[str, Any],
    ) -> str:
        payload = {
            "task": "SK쉴더스 기반 AWS 보안 구성 진단",
            "category": category,
            "diagnosis_contract": diagnosis_contract,
            "rules": list(rules),
            "aws_state": aws_state,
        }
        return json.dumps(payload, ensure_ascii=False, default=str, separators=(",", ":"))

    @staticmethod
    def _parse_response_text(text: str) -> Dict[str, Any]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise DiagnosisError(f"AI 응답이 JSON이 아닙니다: {exc}") from exc
        if not isinstance(data, dict):
            raise DiagnosisError("AI 응답의 최상위 값은 object여야 합니다.")
        return data

    @staticmethod
    def _validate_category_result(
        category: str,
        rules: Sequence[Mapping[str, Any]],
        result: Mapping[str, Any],
    ) -> None:
        if result.get("category") != category:
            raise DiagnosisError(
                f"카테고리 불일치: 요청={category}, 응답={result.get('category')}"
            )

        rows = result.get("results")
        if not isinstance(rows, list):
            raise DiagnosisError(f"{category}: results가 배열이 아닙니다.")

        expected_ids = [str(rule.get("id")) for rule in rules]
        received_ids = [str(row.get("rule_id")) for row in rows if isinstance(row, dict)]

        missing = sorted(set(expected_ids) - set(received_ids))
        unknown = sorted(set(received_ids) - set(expected_ids))
        duplicates = sorted(
            rule_id for rule_id in set(received_ids) if received_ids.count(rule_id) > 1
        )

        if missing or unknown or duplicates:
            raise DiagnosisError(
                f"{category} 진단 rule_id 오류: missing={missing}, "
                f"unknown={unknown}, duplicates={duplicates}"
            )

        severity_by_id = {str(r.get("id")): str(r.get("severity")) for r in rules}
        for row in rows:
            rule_id = str(row.get("rule_id"))
            status = str(row.get("status"))
            if status not in VALID_STATUS:
                raise DiagnosisError(f"{rule_id}: 잘못된 status={status}")
            if str(row.get("severity")) != severity_by_id[rule_id]:
                raise DiagnosisError(
                    f"{rule_id}: 위험도 변경 금지. 기준={severity_by_id[rule_id]}, "
                    f"응답={row.get('severity')}"
                )
            if status in {"FAIL", "REVIEW"} and not row.get("evidence"):
                raise DiagnosisError(f"{rule_id}: {status}인데 evidence가 없습니다.")

    def diagnose_category(
        self, category: str, aws_state: Mapping[str, Any]
    ) -> Dict[str, Any]:
        rules = self._rules_for_category(category)
        state = self._state_for_category(category, aws_state)
        input_text = self._request_payload(
            category=category,
            rules=rules,
            aws_state=state,
            diagnosis_contract=self.rule_bundle.get("diagnosis_contract") or {},
        )

        try:
            response = self.client.responses.create(
                model=self.model,
                instructions=self.instructions,
                input=[{"role": "user", "content": input_text}],
                text={"format": DIAGNOSIS_TEXT_FORMAT},
                store=False,
                max_output_tokens=self.max_output_tokens,
            )
        except Exception as exc:
            raise DiagnosisError(f"OpenAI 진단 요청 실패({category}): {exc}") from exc

        output_text = (getattr(response, "output_text", None) or "").strip()
        if not output_text:
            raise DiagnosisError(f"OpenAI가 빈 진단 결과를 반환했습니다: {category}")

        result = self._parse_response_text(output_text)
        self._validate_category_result(category, rules, result)
        return result

    @staticmethod
    def _summary(results: Sequence[Mapping[str, Any]]) -> Dict[str, int]:
        summary = {
            "total": len(results),
            "pass": 0,
            "fail": 0,
            "review": 0,
            "na": 0,
        }
        for row in results:
            status = str(row.get("status") or "").upper()
            if status == "PASS":
                summary["pass"] += 1
            elif status == "FAIL":
                summary["fail"] += 1
            elif status == "REVIEW":
                summary["review"] += 1
            elif status == "N/A":
                summary["na"] += 1
        return summary

    def diagnose_all(self, aws_state: Mapping[str, Any]) -> Dict[str, Any]:
        """Run all 33 diagnoses in four category-scoped model calls."""
        category_results: List[Dict[str, Any]] = []
        merged_results: List[Dict[str, Any]] = []

        for category in CATEGORY_ORDER:
            result = self.diagnose_category(category, aws_state)
            category_results.append(result)
            merged_results.extend(result["results"])

        if len(merged_results) != 33:
            raise DiagnosisError(
                f"최종 진단 결과가 33개가 아닙니다: {len(merged_results)}개"
            )

        rule_order = {str(rule.get("id")): idx for idx, rule in enumerate(self.rules)}
        merged_results.sort(key=lambda row: rule_order.get(str(row.get("rule_id")), 999))

        return {
            "standard": "SK쉴더스 CSPM(DataDog) AWS 보안 가이드 기반",
            "model": self.model,
            "summary": self._summary(merged_results),
            "results": merged_results,
            "categories": category_results,
            "collection_errors": list(aws_state.get("collection_errors") or []),
            "collected_at": (aws_state.get("metadata") or {}).get("collected_at"),
            "region": (aws_state.get("metadata") or {}).get("region"),
        }


def diagnose_aws_state(
    aws_state: Mapping[str, Any],
    *,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
) -> Dict[str, Any]:
    """Convenience function for Flask route code."""
    service = AIDiagnosisService(api_key=api_key, model=model)
    return service.diagnose_all(aws_state)
