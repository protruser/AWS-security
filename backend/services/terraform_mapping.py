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
        prefixes = resource_prefixes(finding)
        resource_ids = finding.get("resource_ids") or []
        identifiers = [str(value).lower() for value in resource_ids if isinstance(value, str)]
        candidates = []
        state_matches = [(index or {}).get(resource_id, set()) for resource_id in identifiers]
        for path, file in catalog.items():
            matches = [{"type": kind, "name": name} for kind, name in file["resources"]
                       if any(kind.startswith(prefix) for prefix in prefixes)]
            if not matches:
                continue
            exact = bool(state_matches) and all(any(
                (kind, name, module) in matches
                for kind, name in file["resources"]
                for module in ("module." + path.split("/")[1], ""))
                for matches in state_matches)
            # A literal ID in code is useful context but is not proof of state ownership.
            candidates.append({"file_path": path, "resources": matches,
                               "identity_match": exact})
        candidates.sort(key=lambda item: (not item["identity_match"], item["file_path"]))
        results[str(finding["rule_id"])] = {
            "status": "MATCHED" if any(item["identity_match"] for item in candidates) else "MANUAL_REVIEW",
            "candidates": candidates[:10],
            "reason": ("Terraform state links an AWS resource to this declaration. Confirm before patching."
                       if any(item["identity_match"] for item in candidates)
                       else "State ownership was not established; manual confirmation is required."),
        }
    return {"repository": snapshot["repository"], "ref": snapshot["ref"],
            "commit_sha": commit_sha, "mapping": results}
