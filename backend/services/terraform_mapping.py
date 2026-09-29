"""Conservative suggestions from the live gyu tree and Terraform declarations."""
import json
import os
import re
from pathlib import Path

from services.patch_security import PatchError


RULES = {item["id"]: item for item in json.loads(
    (Path(__file__).resolve().parents[1] / "rules" / "shieldus_aws_33_rules.json")
    .read_text(encoding="utf-8"))["rules"]}

RESOURCE = re.compile(r'^\s*resource\s+"(aws_[a-z0-9_]+)"\s+"([a-zA-Z0-9_-]+)"', re.M)

# 한 패치에 넣을 수 있는 파일 수(terraform_patch_service.create 와 같은 한도).
MAX_PATCH_FILES = 5

# 진단 항목별로 고쳐야 할 Terraform 리소스 타입. 진단 문장의 키워드로 추측하면
# 로그 그룹 이름에 "waf" 가 들어 있다는 이유로 WAF 파일을 고르는 식의 오탐이 생긴다.
# 여기 없는 항목은 resource_prefixes() 의 키워드 추측을 그대로 쓴다.
RULE_TARGETS = {
    "2.1": ("aws_iam_role", "aws_iam_role_policy", "aws_iam_role_policy_attachment", "aws_iam_policy"),
    "2.2": ("aws_iam_role", "aws_iam_role_policy", "aws_iam_role_policy_attachment", "aws_iam_policy"),
    "2.3": ("aws_iam_role", "aws_iam_role_policy", "aws_iam_role_policy_attachment", "aws_iam_policy"),
    "3.1": ("aws_security_group", "aws_security_group_rule",
            "aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule"),
    "3.2": ("aws_security_group", "aws_security_group_rule",
            "aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule"),
    "3.3": ("aws_default_security_group", "aws_network_acl", "aws_network_acl_rule", "aws_default_network_acl"),
    "3.4": ("aws_cloudtrail", "aws_cloudwatch_log_metric_filter", "aws_cloudwatch_metric_alarm"),
    "3.5": ("aws_cloudtrail", "aws_cloudwatch_log_metric_filter", "aws_cloudwatch_metric_alarm"),
    "3.6": ("aws_cloudtrail", "aws_cloudwatch_log_metric_filter", "aws_cloudwatch_metric_alarm"),
    "3.7": ("aws_s3_bucket", "aws_s3_bucket_policy", "aws_s3_bucket_acl", "aws_s3_bucket_public_access_block"),
    "3.8": ("aws_db_instance", "aws_db_subnet_group"),
    "3.9": ("aws_lb", "aws_lb_listener"),
    "4.1": ("aws_instance", "aws_ebs_volume", "aws_ebs_encryption_by_default"),
    "4.2": ("aws_db_instance",),
    "4.3": ("aws_s3_bucket", "aws_s3_bucket_server_side_encryption_configuration"),
    "4.4": ("aws_lb_listener", "aws_s3_bucket_policy", "aws_cloudfront_distribution"),
    "4.5": ("aws_cloudtrail",),
    "4.6": ("aws_cloudtrail",),
    "4.8": ("aws_db_instance", "aws_docdb_cluster"),
    "4.9": ("aws_cloudtrail",),
    "4.10": ("aws_flow_log",),
    "4.11": ("aws_cloudwatch_log_group",),
    "4.12": ("aws_db_instance", "aws_docdb_cluster"),
}

# 계정 설정이나 운영 조치라 이 인프라 Terraform 으로 고칠 수 없는 항목. 패치 생성을 막는다.
# (IAM 사용자·루트 계정·비밀번호 정책은 이 저장소가 관리하지 않는다)
NOT_TERRAFORM_RULES = {
    "1.1": "IAM 사용자 정책 연결은 이 Terraform이 관리하지 않습니다. IAM 콘솔에서 조치하세요.",
    "1.2": "IAM 사용자 계정 정리는 IAM 콘솔에서 조치하세요.",
    "1.3": "IAM 사용자 태그는 이 Terraform이 관리하지 않습니다. IAM 콘솔에서 조치하세요.",
    "1.4": "IAM 그룹 구성원은 이 Terraform이 관리하지 않습니다. IAM 콘솔에서 조치하세요.",
    "1.5": "EC2는 SSM 접속을 쓰도록 Key Pair 없이 설계되었습니다. 예외 승인 여부를 검토하세요.",
    "1.6": "루트 계정 사용은 계정 운영 조치입니다(루트 사용 중단, 사용 기록 점검).",
    "1.7": "루트/IAM Access Key 정리는 IAM 콘솔에서 조치하세요.",
    "1.8": "MFA 설정은 IAM 콘솔에서 사용자별로 조치하세요.",
    "1.9": "계정 비밀번호 정책은 이 Terraform이 관리하지 않습니다. IAM 콘솔에서 조치하세요.",
    "4.7": "CloudWatch 에이전트 설치는 SSM Run Command로 조치하세요. user_data 변경은 서버를 교체합니다.",
}


def state_index():
    """Read only Terraform state IDs; return no values or credentials to callers."""
    bucket, key = os.getenv("TF_STATE_BUCKET"), os.getenv("TF_STATE_KEY")
    if not bucket or not key:
        return None
    import boto3
    try:
        response = boto3.client("s3", region_name=os.getenv("TF_STATE_REGION") or None).get_object(
            Bucket=bucket, Key=key)
        if response.get("ContentLength", 20_000_001) > 20_000_000:
            raise ValueError("state too large")
        raw = response["Body"].read(20_000_001)
        if len(raw) > 20_000_000:
            raise ValueError("state too large")
        state = json.loads(raw)
        index = {}
        for resource in state.get("resources", []):
            if resource.get("mode") != "managed":
                continue
            identity = (resource.get("type"), resource.get("name"), resource.get("module", ""))
            for instance in resource.get("instances", []):
                attributes = instance.get("attributes") or {}
                for field in ("id", "arn", "name"):
                    value = attributes.get(field)
                    if isinstance(value, str) and value:
                        index.setdefault(value.lower(), set()).add(identity)
        return index
    except Exception:
        raise PatchError("STATE_UNAVAILABLE", "Terraform state could not be read for resource mapping.", 502) from None


def resource_prefixes(finding):
    rule = RULES.get(str(finding.get("rule_id")), {})
    evidence = " ".join(rule.get("required_evidence", []))
    text = " ".join(str(finding.get(key, "")) for key in
                    ("resource_type", "resource_ids", "reason", "current_value", "recommendation"))
    combined = (evidence + " " + text).lower()
    if "security_group" in combined or re.search(r"\bsg-[0-9a-f]+\b", combined):
        return ("aws_security_group", "aws_vpc_security_group", "aws_security_group_rule")
    if "cloudtrail" in combined:
        return ("aws_cloudtrail",)
    if "waf" in combined:
        return ("aws_wafv2",)
    if "secretsmanager" in combined or "secret" in combined:
        return ("aws_secretsmanager",)
    if "kms" in combined:
        return ("aws_kms",)
    if "iam.users" in combined or "iam.user_" in combined:
        return ("aws_iam_user", "aws_iam_user_policy", "aws_iam_access_key")
    for term, prefixes in (
        ("iam", ("aws_iam_",)), ("s3", ("aws_s3_",)),
        ("guardduty", ("aws_guardduty_",)), ("securityhub", ("aws_securityhub_",)),
        ("inspector", ("aws_inspector",)), ("cloudwatch", ("aws_cloudwatch_",)),
        ("flow_log", ("aws_flow_log",)), ("ec2", ("aws_instance", "aws_ebs_")),
    ):
        if term in combined:
            return prefixes
    return ()


def preview(source, findings, index=None):
    """Return candidates, never assert ownership from a matching AWS service alone."""
    commit_sha, paths = source.terraform_paths()
    if not paths:
        raise PatchError("INVALID_SOURCE", "No Terraform module files were found.", 502)
    # 후보를 찾으려고 modules/ 전체를 읽지만 리소스 이름만 쓴다. 여기서 비밀값 검사를 하면
    # 선택과 무관한 파일 하나 때문에 매핑 전체가 막힌다. 선택된 파일은 패치 생성 때 검사한다.
    snapshot = source.snapshot(paths, check_secrets=False)
    if snapshot["commit_sha"] != commit_sha:
        raise PatchError("BASE_CHANGED", "The gyu branch changed during mapping. Retry.", 409)
    catalog = {}
    if index is None:
        index = state_index()
    for item in snapshot["files"]:
        catalog[item["file_path"]] = {
            "resources": RESOURCE.findall(item["original_content"]),
        }
    results = {}
    for finding in findings:
        rule_id = str(finding["rule_id"])
        if rule_id in NOT_TERRAFORM_RULES:
            results[rule_id] = {"status": "NOT_TERRAFORM", "candidates": [], "suggested": [],
                                "total_candidates": 0, "reason": NOT_TERRAFORM_RULES[rule_id]}
            continue
        targets = RULE_TARGETS.get(rule_id)
        prefixes = () if targets else resource_prefixes(finding)
        resource_ids = finding.get("resource_ids") or []
        identifiers = [str(value).lower() for value in resource_ids if isinstance(value, str)]
        candidates = []
        for path, file in catalog.items():
            matches = [{"type": kind, "name": name} for kind, name in file["resources"]
                       if (kind in targets if targets else any(kind.startswith(prefix) for prefix in prefixes))]
            if not matches:
                continue
            modules = ("module." + path.split("/")[1], "")
            covered_ids = [resource_id for resource_id in identifiers
                           if any((kind, name, module) in (index or {}).get(resource_id, set())
                                  for kind, name in ((item["type"], item["name"]) for item in matches)
                                  for module in modules)]
            # A literal ID in code is useful context but is not proof of state ownership.
            candidates.append({"file_path": path, "resources": matches,
                               "identity_match": bool(covered_ids),
                               "covered_resource_ids": covered_ids})
        # State 로 확인된 파일, 대상 리소스가 많은 파일 순. 자동 입력은 한 패치 한도(5개)까지.
        candidates.sort(key=lambda item: (not item["identity_match"], -len(item["resources"]), item["file_path"]))
        if not candidates:
            status, reason = "NO_CANDIDATE", "이 항목의 대상 리소스가 선언된 Terraform 파일이 없습니다."
        elif identifiers and all(any(resource_id in item["covered_resource_ids"]
                                 for item in candidates) for resource_id in identifiers):
            status, reason = "MATCHED", "Terraform state links an AWS resource to this declaration. Confirm before patching."
        else:
            status, reason = "MANUAL_REVIEW", "State ownership was not established; manual confirmation is required."
        unmapped_resource_ids = [resource_id for resource_id in identifiers
                                 if not any(resource_id in item["covered_resource_ids"] for item in candidates)]
        results[rule_id] = {
            "status": status,
            "candidates": candidates[:10],
            "unmapped_resource_ids": unmapped_resource_ids,
            "suggested": [item["file_path"] for item in candidates[:MAX_PATCH_FILES]],
            "total_candidates": len(candidates),
            "reason": reason,
        }
    return {"repository": snapshot["repository"], "ref": snapshot["ref"],
            "commit_sha": commit_sha, "mapping": results}
