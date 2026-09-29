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
TARGET_RULE_IDS: Set[str] = {"1.1", "1.5", "2.1", "2.2", "2.3", "3.1", "4.3"}
ADMINISTRATOR_ACCESS_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"

# These are project classification hints for the source service families, not
# a claim that Shieldus published an exhaustive machine-readable policy list.
POLICY_NAME_MARKERS: Mapping[str, Sequence[str]] = {
    "2.1": ("ec2", "ecs", "ecr", "eks", "elasticfilesystem", "efs", "rds", "s3", "containerregistry"),
    "2.2": ("vpc", "cloudfront", "route53", "apigateway", "directconnect", "appmesh", "cloudmap", "servicediscovery"),
    "2.3": ("organizations", "cloudwatch", "autoscaling", "cloudformation", "cloudtrail", "config", "ssm", "systemsmanager", "guardduty", "inspector", "sso", "certificate", "kms", "waf", "shield", "securityhub", "datapipeline", "glue", "msk", "backup"),
}
POLICY_ACTION_PREFIXES: Mapping[str, Sequence[str]] = {
    "2.1": ("ec2", "ecs", "ecr", "eks", "elasticfilesystem", "rds", "s3"),
    "2.2": ("cloudfront", "route53", "apigateway", "directconnect", "appmesh", "servicediscovery"),
    "2.3": ("organizations", "cloudwatch", "autoscaling", "cloudformation", "cloudtrail", "config", "ssm", "guardduty", "inspector", "sso", "acm", "kms", "waf", "wafv2", "shield", "securityhub", "datapipeline", "glue", "kafka", "backup"),
}

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


def _evidence(resource: str, path: str, value: Any) -> Dict[str, str]:
    return {
        "resource": resource,
        "path": path,
        "value": value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str, sort_keys=True),
    }


def _diagnosis_row(
    rule: Mapping[str, Any], status: str, resource_ids: Sequence[str],
    evidence: Sequence[Mapping[str, str]], current_value: str, reason: str,
    *, recommendation: str = "설정 및 수집 근거를 검토하세요.",
    extra: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    row = {
        "rule_id": str(rule["id"]),
        "status": status,
        "severity": str(rule["severity"]),
        "resource_ids": list(dict.fromkeys(resource_ids)),
        "current_value": current_value,
        "expected_value": str((rule.get("ai_judgement") or {}).get("PASS") or ""),
        "evidence": list(evidence),
        "reason": reason,
        "recommendation": recommendation,
    }
    if extra:
        row.update(extra)
    return row


def _collection_errors(state: Mapping[str, Any], *sources: str) -> List[Mapping[str, Any]]:
    return [
        error for error in state.get("collection_errors", [])
        if isinstance(error, dict) and any(str(error.get("source", "")).startswith(source) for source in sources)
    ]


def _policy_document_scopes(document: Any) -> Set[str]:
    if not isinstance(document, dict):
        return set()
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    scopes: Set[str] = set()
    for statement in statements if isinstance(statements, list) else []:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        resources = statement.get("Resource", [])
        if "*" not in (resources if isinstance(resources, list) else [resources]):
            continue
        actions = statement.get("Action", [])
        actions = actions if isinstance(actions, list) else [actions]
        for rule_id, prefixes in POLICY_ACTION_PREFIXES.items():
            if any(str(action).lower() == f"{prefix}:*" for action in actions for prefix in prefixes):
                scopes.add(rule_id)
    return scopes


def _high_privilege_scopes(policy: Mapping[str, Any]) -> tuple[Set[str], bool]:
    name = str(policy.get("PolicyName") or "")
    arn = str(policy.get("PolicyArn") or "")
    if not name or not arn:
        return set(), True
    lowered = name.lower()
    name_scopes = {
        rule_id for rule_id, markers in POLICY_NAME_MARKERS.items()
        if any(marker in lowered for marker in markers)
    }
    detail = policy.get("policy_detail") or {}
    document = detail.get("document") if isinstance(detail, dict) else None
    document_scopes = _policy_document_scopes(document)
    aws_managed = arn.startswith("arn:aws:iam::aws:policy/")
    named_full_access = lowered.endswith(("fullaccess", "administrator"))
    if aws_managed and lowered in {"administratoraccess", "poweruseraccess", "iamfullaccess", "readonlyaccess"}:
        # These account/IAM-wide policies are not a named service-family
        # managed policy in the three source items.
        return set(), False
    if aws_managed and named_full_access:
        # Some network policies grant ec2:* for VPC operations. Their named
        # service family takes precedence over that shared action prefix.
        return name_scopes or document_scopes, not bool(name_scopes or document_scopes)
    if document is None:
        # An arbitrary customer policy name cannot establish its permissions.
        return set(), not (aws_managed and lowered.endswith("readonlyaccess"))
    if not isinstance(document, dict) or not isinstance(document.get("Statement"), (dict, list)):
        return set(), True
    statements = document.get("Statement", []) if isinstance(document, dict) else []
    statements = [statements] if isinstance(statements, dict) else statements
    if isinstance(statements, list) and any(
        isinstance(statement, dict) and statement.get("Effect") == "Allow"
        and "*" in (statement.get("Action") if isinstance(statement.get("Action"), list)
                    else [statement.get("Action")])
        for statement in statements
    ):
        # An account-wide wildcard cannot be assigned to one of the source's
        # three service families without an unpublished classification rule.
        return set(), True
    if name_scopes == {"2.2"} and document_scopes == {"2.1"} and "vpc" in lowered:
        return {"2.2"}, False
    return document_scopes, False


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

    @staticmethod
    def _evaluate_iam_admin(rule: Mapping[str, Any], state: Mapping[str, Any]) -> Dict[str, Any]:
        iam = state.get("iam") or {}
        users = iam.get("users")
        attachments = iam.get("user_attached_policies")
        if not isinstance(users, list) or not isinstance(attachments, dict):
            return _diagnosis_row(
                rule, "REVIEW", [], [_evidence("iam", "iam.users,iam.user_attached_policies", "필수 수집값 없음")],
                "직접 연결 정책 확인 불가", "IAM 사용자 또는 직접 연결 정책 목록을 수집하지 못했습니다.",
            )
        if not users:
            if _collection_errors(state, "iam.collect", "iam.list_users"):
                return _diagnosis_row(rule, "REVIEW", [], [_evidence("iam", "collection_errors", "IAM 사용자 목록 조회 실패")],
                                      "IAM 사용자 목록 확인 불가", "사용자 목록 수집 오류로 직접 연결 정책을 확인할 수 없습니다.")
            return _diagnosis_row(rule, "N/A", [], [], "IAM 사용자 없음", "진단 대상 IAM 사용자가 없습니다.")

        evidence: List[Dict[str, str]] = []
        resource_ids: List[str] = []
        direct: List[str] = []
        incomplete = bool(_collection_errors(state, "iam.collect", "iam.list_attached_user_policies"))
        group_members = iam.get("group_users") or {}
        group_policies = iam.get("groups_policies") or {}
        for user in users:
            if not isinstance(user, dict):
                incomplete = True
                continue
            name, arn = user.get("user_name"), user.get("arn")
            if not name or not arn or not isinstance(attachments.get(name), list):
                incomplete = True
                continue
            resource_ids.append(arn)
            policies = attachments[name]
            direct_policies = []
            for policy in policies:
                if not isinstance(policy, dict) or not policy.get("PolicyName") or not policy.get("PolicyArn"):
                    incomplete = True
                    continue
                direct_policies.append({"policy_name": policy["PolicyName"], "policy_arn": policy["PolicyArn"]})
                if policy["PolicyName"] == "AdministratorAccess" and policy["PolicyArn"] == ADMINISTRATOR_ACCESS_ARN:
                    direct.append(arn)
            evidence.append(_evidence(arn, f"iam.user_attached_policies.{name}", {
                "user_name": name, "user_arn": arn, "attachment_type": "direct",
                "policies": direct_policies,
            }))
            if isinstance(group_members, dict) and isinstance(group_policies, dict):
                for group_name, members in group_members.items():
                    if not isinstance(members, list) or name not in members:
                        continue
                    group_attached = (group_policies.get(group_name) or {}).get("attached", [])
                    for policy in group_attached if isinstance(group_attached, list) else []:
                        if isinstance(policy, dict) and policy.get("PolicyArn") == ADMINISTRATOR_ACCESS_ARN:
                            evidence.append(_evidence(arn, f"iam.groups_policies.{group_name}.attached", {
                                "user_name": name, "user_arn": arn, "group_name": group_name,
                                "policy_name": policy.get("PolicyName"), "policy_arn": policy["PolicyArn"],
                                "attachment_type": "via_group_not_counted",
                            }))

        if direct:
            status, reason = "FAIL", "IAM 사용자에게 AWS 관리형 AdministratorAccess가 직접 연결되어 있습니다."
        elif incomplete:
            status, reason = "REVIEW", "사용자 ARN 또는 직접 연결 관리형 정책 수집값이 부족합니다."
        else:
            status, reason = "PASS", "직접 연결된 AWS 관리형 AdministratorAccess가 없습니다. 그룹 상속과 인라인 정책은 이 탐지에 포함하지 않습니다."
        if incomplete:
            evidence.append(_evidence("iam", "collection_errors,iam.user_attached_policies", "일부 사용자·정책 연결 정보 확인 불가"))
        return _diagnosis_row(
            rule, status, resource_ids, evidence, f"직접 연결 사용자 {len(set(direct))}명",
            reason, recommendation="해당 IAM 사용자의 직접 연결 AdministratorAccess 정책을 검토하세요.",
        )

    @staticmethod
    def _evaluate_key_pair(rule: Mapping[str, Any], state: Mapping[str, Any]) -> Dict[str, Any]:
        ec2 = state.get("ec2") or {}
        instances = ec2.get("instances")
        if not isinstance(instances, list) or _collection_errors(state, "ec2.collect"):
            return _diagnosis_row(
                rule, "REVIEW", [], [_evidence("ec2", "ec2.instances", "EC2 인스턴스 조회 불가")],
                "Key Pair 할당 상태 확인 불가", "EC2 인스턴스 목록 수집에 실패했습니다.",
            )
        if not instances:
            return _diagnosis_row(rule, "N/A", [], [], "EC2 인스턴스 없음", "진단 대상 EC2 인스턴스가 없습니다.")

        evidence: List[Dict[str, str]] = []
        resource_ids: List[str] = []
        resource_results: List[Dict[str, Any]] = []
        absent = unknown = 0
        managed = {item.get("InstanceId") for item in (state.get("ssm") or {}).get("managed_instances", []) if isinstance(item, dict)}
        for instance in instances:
            if not isinstance(instance, dict) or not instance.get("instance_id"):
                unknown += 1
                continue
            instance_id = instance["instance_id"]
            resource_ids.append(instance_id)
            key_name = instance.get("key_name")
            pair_state = instance.get("key_pair_status")
            if pair_state is None and "key_name" in instance:
                pair_state = "ATTACHED" if key_name else "ABSENT"
            if pair_state == "ABSENT":
                status = "FAIL"
                absent += 1
            elif pair_state == "ATTACHED" and key_name:
                status = "PASS"
            else:
                status = "REVIEW"
                unknown += 1
            evidence.append(_evidence(instance_id, f"ec2.instances.{instance_id}.key_name", {
                "instance_id": instance_id, "key_name": key_name, "key_pair_status": pair_state,
            }))
            resource_results.append({"resource_id": instance_id, "status": status, "key_name": key_name})
        if unknown:
            evidence.append(_evidence("ec2", "ec2.instances", "일부 인스턴스 ID 또는 Key Pair 상태 확인 불가"))
        status = "FAIL" if absent else "REVIEW" if unknown else "PASS"
        return _diagnosis_row(
            rule, status, resource_ids, evidence,
            f"Key Pair 미할당 {absent}개, 확인 불가 {unknown}개",
            "Key Pair 미할당은 원본 탐지 조건입니다. SSM 관리 여부는 판정에 사용하지 않았습니다." if absent
            else "모든 인스턴스의 Key Pair 할당을 확인했습니다." if not unknown
            else "일부 EC2 인스턴스의 Key Pair 상태를 확인할 수 없습니다.",
            recommendation="Key Pair 미할당 인스턴스를 확인하고 접속 정책을 별도로 검토하세요.",
            extra={
                "resource_results": resource_results,
                "operational_context": {
                    "ssm_managed_instance_ids": sorted(item for item in managed if item in resource_ids),
                    "ssm_session_manager_usage": "수집하지 않음",
                    "key_pairless_access_policy": (state.get("project_policy") or {}).get("key_pairless_access_policy"),
                },
            },
        )

    @staticmethod
    def _evaluate_privileged_policy(rule: Mapping[str, Any], state: Mapping[str, Any]) -> Dict[str, Any]:
        rule_id = str(rule["id"])
        iam = state.get("iam") or {}
        principal_sources = (
            ("user", "users", "user_name", "users_policies"),
            ("group", "groups", "group_name", "groups_policies"),
            ("role", "roles", "role_name", "roles_policies"),
        )
        observed: Dict[str, Dict[str, Any]] = {}
        incomplete: List[str] = []
        if _collection_errors(state, "iam.collect", "iam.list_attached_user_policies", "iam.list_attached_group_policies", "iam.list_attached_role_policies"):
            incomplete.append("IAM 주체 또는 관리형 정책 연결 API 오류")

        for principal_type, list_key, name_key, policies_key in principal_sources:
            principals = iam.get(list_key)
            policies_by_name = iam.get(policies_key)
            if not isinstance(principals, list) or not isinstance(policies_by_name, dict):
                incomplete.append(f"iam.{list_key}/iam.{policies_key} 누락")
                continue
            for principal in principals:
                if not isinstance(principal, dict):
                    incomplete.append(f"iam.{list_key} 주체 형식 오류")
                    continue
                name, arn = principal.get(name_key), principal.get("arn")
                if not name or not arn:
                    incomplete.append(f"iam.{list_key} 이름/ARN 누락")
                    continue
                entry = policies_by_name.get(name)
                if not isinstance(entry, dict) or not isinstance(entry.get("attached"), list):
                    incomplete.append(f"{principal_type} {name}의 직접 연결 정책 목록 누락")
                    continue
                for policy in entry["attached"]:
                    if not isinstance(policy, dict):
                        incomplete.append(f"{principal_type} {name}의 정책 형식 오류")
                        continue
                    scopes, uncertain = _high_privilege_scopes(policy)
                    if uncertain:
                        incomplete.append(f"{principal_type} {name}의 정책 권한 확인 불가")
                    if rule_id not in scopes:
                        continue
                    current = observed.setdefault(arn, {
                        "principal_name": name,
                        "principal_arn": arn,
                        "principal_type": principal_type,
                        "policy_arns": set(),
                        "paths": set(),
                    })
                    current["policy_arns"].add(policy["PolicyArn"])
                    current["paths"].add(f"iam.{policies_key}.{name}.attached")

        evidence = [
            _evidence(arn, ",".join(sorted(item["paths"])), {
                "principal_name": item["principal_name"],
                "principal_arn": arn,
                "principal_type": item["principal_type"],
                "attachment_type": "direct",
                "high_privilege_policy_arns": sorted(item["policy_arns"]),
            })
            for arn, item in sorted(observed.items())
        ]
        if incomplete:
            evidence.append(_evidence("iam", "iam.policy_inventory,collection_errors", sorted(set(incomplete))))
        if not evidence:
            evidence.append(_evidence("iam", "iam.users_policies,iam.groups_policies,iam.roles_policies", {
                "observed_unique_high_privilege_principals": 0,
            }))

        count = len(observed)
        threshold = (rule.get("project_custom_threshold") or {}).get("minimum_unique_principals_for_fail", 3)
        status = "REVIEW" if incomplete else "FAIL" if count >= threshold else "PASS"
        reason = (
            f"프로젝트 Custom 기준: 고유 IAM 주체 {count}개, FAIL 임계값 {threshold}개. "
            "SK쉴더스 원본은 서비스 관리형 정책 연결 탐지를 기술하며 이 숫자 임계값을 제시하지 않습니다."
        )
        if incomplete:
            reason += " 필수 수집값 누락으로 정확한 최종 집계는 불가능합니다."
        return _diagnosis_row(
            rule, status, sorted(observed), evidence,
            f"직접 연결된 고권한 정책의 고유 IAM 주체 {count}개" + (" (집계 미완료)" if incomplete else ""),
            reason,
            recommendation="주체별 직접 연결 고권한 정책과 업무 필요성을 검토하세요.",
            extra={
                "assessment_basis": {
                    "shieldus_source_detection": rule.get("source_detection_summary"),
                    "project_custom_threshold": rule.get("project_custom_threshold"),
                    "policy_classification": "서비스별 AWS 관리형 FullAccess/Administrator 명칭 또는 확인된 서비스:* 고객 관리형 정책; 원본 전체 정책 목록은 미공개",
                },
                "observed_unique_principal_count": count,
            },
        )

    @staticmethod
    def _evaluate_security_group_any(rule: Mapping[str, Any], state: Mapping[str, Any]) -> Dict[str, Any]:
        ec2 = state.get("ec2") or {}
        groups = ec2.get("security_groups")
        if not isinstance(groups, list) or _collection_errors(state, "ec2.collect", "ec2.describe_security_groups"):
            return _diagnosis_row(rule, "REVIEW", [], [_evidence("ec2", "ec2.security_groups", "보안 그룹 목록 조회 불가")],
                                  "PORT ANY 확인 불가", "보안 그룹 수집 정보가 부족합니다.")
        if not groups:
            return _diagnosis_row(rule, "N/A", [], [], "보안 그룹 없음", "진단 대상 보안 그룹이 없습니다.")

        evidence: List[Dict[str, str]] = []
        resource_ids: List[str] = []
        resource_results: List[Dict[str, Any]] = []
        incomplete = False
        for group in groups:
            if not isinstance(group, dict) or not group.get("group_id"):
                incomplete = True
                continue
            group_id = group["group_id"]
            resource_ids.append(group_id)
            group_candidate = False
            group_evidence_start = len(evidence)
            for direction, key in (("inbound", "ip_permissions"), ("outbound", "ip_permissions_egress")):
                permissions = group.get(key)
                if not isinstance(permissions, list):
                    incomplete = True
                    continue
                for index, permission in enumerate(permissions):
                    if not isinstance(permission, dict):
                        incomplete = True
                        continue
                    protocol = permission.get("ip_protocol")
                    start, end = permission.get("from_port"), permission.get("to_port")
                    if protocol is None:
                        incomplete = True
                    all_protocols = str(protocol) == "-1"
                    all_ports = str(protocol).lower() in {"6", "17", "tcp", "udp"} and start == 0 and end == 65535
                    candidate = all_protocols or all_ports
                    group_candidate |= candidate
                    range_keys = ("ip_ranges", "ipv6_ranges", "prefix_list_ids", "user_id_group_pairs")
                    if any(not isinstance(permission.get(range_key), list) for range_key in range_keys):
                        incomplete = True
                    ipv4 = permission.get("ip_ranges")
                    ipv6 = permission.get("ipv6_ranges")
                    prefix_lists = permission.get("prefix_list_ids")
                    group_pairs = permission.get("user_id_group_pairs")
                    destinations = {
                        "ipv4": [item.get("cidr_ip") for item in ipv4 if isinstance(item, dict)] if isinstance(ipv4, list) else None,
                        "ipv6": [item.get("cidr_ipv6") for item in ipv6 if isinstance(item, dict)] if isinstance(ipv6, list) else None,
                        "prefix_lists": [item.get("PrefixListId") for item in prefix_lists if isinstance(item, dict)] if isinstance(prefix_lists, list) else None,
                        "security_groups": [item.get("GroupId") for item in group_pairs if isinstance(item, dict)] if isinstance(group_pairs, list) else None,
                    }
                    evidence.append(_evidence(group_id, f"ec2.security_groups.{group_id}.{key}.{index}", {
                        "security_group_id": group_id,
                        "direction": direction,
                        "protocol": protocol,
                        "from_port": start,
                        "to_port": end,
                        "source_or_destination": destinations,
                        "all_protocols": all_protocols,
                        "all_port_range": all_ports,
                        "project_interpretation_candidate": candidate,
                    }))
            if len(evidence) == group_evidence_start:
                evidence.append(_evidence(group_id, f"ec2.security_groups.{group_id}", {
                    "security_group_id": group_id,
                    "ip_permissions": group.get("ip_permissions"),
                    "ip_permissions_egress": group.get("ip_permissions_egress"),
                }))
            resource_results.append({"resource_id": group_id, "status": "REVIEW", "project_interpretation_candidate": group_candidate})
        if incomplete:
            evidence.append(_evidence("ec2", "ec2.security_groups", "일부 보안 그룹 ID, 프로토콜 또는 규칙 목록 누락"))
        # The source gives the default port list but does not publish the
        # Custom expression. A broad AWS permission alone cannot prove that
        # the original proprietary detector would return FAIL or PASS.
        return _diagnosis_row(
            rule, "REVIEW", resource_ids, evidence or [_evidence("ec2", "ec2.security_groups", "규칙 없음")],
            f"보안 그룹 {len(resource_ids)}개, 프로젝트 해석상 PORT ANY 후보 {sum(x['project_interpretation_candidate'] for x in resource_results)}개",
            "SK쉴더스 원본 Custom 검사식이 공개되지 않아 원본 PASS/FAIL을 확정할 수 없습니다.",
            recommendation="원본 Custom 검사식을 확인한 후 수집된 방향·프로토콜·포트·대상을 대조하세요.",
            extra={
                "resource_results": resource_results,
                "assessment_basis": {
                    "shieldus_source_detection": rule.get("source_detection_summary"),
                    "shieldus_default_ports": rule.get("source_default_ports"),
                    "project_interpretation": rule.get("project_interpretation"),
                    "source_custom_expression_verified": False,
                },
            },
        )

    @staticmethod
    def _evaluate_s3_encryption(rule: Mapping[str, Any], state: Mapping[str, Any]) -> Dict[str, Any]:
        s3 = state.get("s3") or {}
        buckets = s3.get("buckets")
        if not isinstance(buckets, list) or _collection_errors(state, "s3.list_buckets"):
            return _diagnosis_row(rule, "REVIEW", [], [_evidence("s3", "s3.buckets", "버킷 목록 조회 불가")],
                                  "S3 기본 암호화 확인 불가", "버킷 목록 수집 실패로 기본 암호화를 확인할 수 없습니다.")
        if not buckets:
            return _diagnosis_row(rule, "N/A", [], [], "S3 버킷 없음", "진단 대상 S3 버킷이 없습니다.")

        evidence: List[Dict[str, str]] = []
        resource_ids: List[str] = []
        resource_results: List[Dict[str, Any]] = []
        for bucket in buckets:
            if not isinstance(bucket, dict) or not bucket.get("name"):
                resource_results.append({"resource_id": None, "status": "REVIEW", "reason": "버킷 이름 누락"})
                continue
            name = bucket["name"]
            resource_ids.append(name)
            configuration = bucket.get("bucket_encryption")
            collection_status = bucket.get("bucket_encryption_status")
            if collection_status is None:
                collection_status = (s3.get("bucket_encryption_status") or {}).get(name)
            errors = [error for error in _collection_errors(state, "s3.get_bucket_encryption")
                      if error.get("resource") == name]
            types: List[str] = []
            if collection_status == "CONFIGURED" and isinstance(configuration, dict):
                rules = configuration.get("Rules")
                if isinstance(rules, list):
                    types = [str(rule_item.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm"))
                             for rule_item in rules if isinstance(rule_item, dict)
                             and isinstance(rule_item.get("ApplyServerSideEncryptionByDefault"), dict)]
            if errors or collection_status in {"ERROR", "UNKNOWN", None}:
                status = "REVIEW"
            elif collection_status == "ABSENT":
                status = "FAIL"
            elif collection_status == "CONFIGURED" and types and all(kind in {"AES256", "aws:kms"} for kind in types):
                status = "PASS"
            else:
                status = "REVIEW"
            evidence.append(_evidence(name, f"s3.buckets.{name}.bucket_encryption", {
                "bucket_name": name,
                "api_result": collection_status,
                "encryption_types": types,
                "configuration": configuration,
                "collection_errors": errors,
            }))
            resource_results.append({"resource_id": name, "status": status, "encryption_types": types})
        statuses = {item["status"] for item in resource_results}
        overall = "REVIEW" if "REVIEW" in statuses else "FAIL" if "FAIL" in statuses else "PASS"
        return _diagnosis_row(
            rule, overall, resource_ids, evidence or [_evidence("s3", "s3.buckets", "버킷 이름 누락")],
            f"암호화 확인 {sum(x['status'] == 'PASS' for x in resource_results)}개, 설정 없음 {sum(x['status'] == 'FAIL' for x in resource_results)}개, 확인 불가 {sum(x['status'] == 'REVIEW' for x in resource_results)}개",
            "실제 GetBucketEncryption 조회값과 오류 상태를 버킷별로 판정했습니다.",
            recommendation="설정 없음으로 확인된 버킷의 기본 암호화를 검토하고, 조회 오류는 권한·API 상태를 확인하세요.",
            extra={"resource_results": resource_results},
        )

    @staticmethod
    def _evaluate_target(rule: Mapping[str, Any], state: Mapping[str, Any]) -> Dict[str, Any]:
        rule_id = str(rule["id"])
        evaluators = {
            "1.1": AIDiagnosisService._evaluate_iam_admin,
            "1.5": AIDiagnosisService._evaluate_key_pair,
            "2.1": AIDiagnosisService._evaluate_privileged_policy,
            "2.2": AIDiagnosisService._evaluate_privileged_policy,
            "2.3": AIDiagnosisService._evaluate_privileged_policy,
            "3.1": AIDiagnosisService._evaluate_security_group_any,
            "4.3": AIDiagnosisService._evaluate_s3_encryption,
        }
        return evaluators[rule_id](rule, state)

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
        model_rules = [rule for rule in rules if str(rule["id"]) not in TARGET_RULE_IDS]
        model_rows: List[Dict[str, Any]] = []
        if model_rules:
            state = self._state_for_category(category, aws_state)
            input_text = self._request_payload(
                category=category,
                rules=model_rules,
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

            model_result = self._parse_response_text(output_text)
            self._validate_category_result(category, model_rules, model_result)
            model_rows = model_result["results"]

        rows_by_id = {str(row["rule_id"]): row for row in model_rows}
        for rule in rules:
            if str(rule["id"]) in TARGET_RULE_IDS:
                rows_by_id[str(rule["id"])] = self._evaluate_target(rule, aws_state)
        result = {"category": category, "results": [rows_by_id[str(rule["id"])] for rule in rules]}
        self._validate_category_result(category, rules, result)
        for row in result["results"]:
            if str(row["rule_id"]) in TARGET_RULE_IDS:
                resource_ids = set(row["resource_ids"])
                evidence_resources = {item["resource"] for item in row["evidence"]}
                if not resource_ids.issubset(evidence_resources):
                    raise DiagnosisError(f"{row['rule_id']}: resource_ids와 evidence 리소스가 일치하지 않습니다")
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

    def generate_consultant_comment(
        self, summary: Mapping[str, int], results: Sequence[Mapping[str, Any]]
    ) -> str:
        """33개 판정 결과를 근거로 3~5문장짜리 총평을 한 번 더 생성한다.

        이건 보고서를 읽는 사람이 33개 항목을 다 훑기 전에 전체 그림을 먼저
        파악하게 도와주는 보조 텍스트일 뿐이라, 실패해도(네트워크 오류 등)
        전체 진단 결과 자체를 버릴 이유는 없다 - 예외를 던지지 않고 빈
        문자열을 반환한다.
        """
        lines = [
            f"전체 {summary.get('total', 0)}개 항목 중 "
            f"PASS {summary.get('pass', 0)} / FAIL {summary.get('fail', 0)} / "
            f"REVIEW {summary.get('review', 0)} / N/A {summary.get('na', 0)}",
            "",
            "FAIL/REVIEW 판정 항목:",
        ]
        for row in results:
            if row.get("status") in ("FAIL", "REVIEW"):
                lines.append(
                    f"- [{row.get('severity')}/{row.get('status')}] "
                    f"{row.get('rule_id')}: {row.get('reason')}"
                )
        summary_text = "\n".join(lines)[:6000]

        try:
            response = self.client.responses.create(
                model=self.model,
                instructions=(
                    "당신은 AWS 클라우드 보안 진단 보고서를 작성하는 보안 컨설턴트다. "
                    "아래 진단 요약만 보고, 이번 진단의 전반적인 보안 수준과 우선 조치가 "
                    "필요한 부분을 한국어 3~5문장으로 간결하게 작성한다. 요약에 없는 내용은 "
                    "추측해서 쓰지 않고, 수치를 인용할 땐 요약에 있는 값만 그대로 쓴다."
                ),
                input=[{"role": "user", "content": summary_text}],
                store=False,
                max_output_tokens=500,
            )
            return (getattr(response, "output_text", None) or "").strip()
        except Exception:
            return ""

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

        summary = self._summary(merged_results)

        return {
            "standard": "SK쉴더스 CSPM(DataDog) AWS 보안 가이드 기반",
            "model": self.model,
            "summary": summary,
            "consultant_comment": self.generate_consultant_comment(summary, merged_results),
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


def load_rule_meta(rule_file: Path = DEFAULT_RULE_FILE) -> Dict[str, Dict[str, str]]:
    """rule_id -> {name, category} 매핑만 필요한 곳(예: 엑셀 보고서 생성)에서 쓴다.

    AIDiagnosisService()는 생성자에서 OPENAI_API_KEY를 요구하는데, 이미 끝난
    진단 결과를 엑셀로 내보내는 데는 OpenAI 호출이 전혀 필요 없다. 그런데도
    이름/카테고리 표시를 위해 API 키를 강제하지 않도록 별도 함수로 분리했다.
    """
    bundle = AIDiagnosisService._load_json(rule_file)
    return {
        str(rule.get("id")): {
            "name": rule.get("name") or "",
            "category": rule.get("category") or "",
        }
        for rule in bundle.get("rules") or []
    }
