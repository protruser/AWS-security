"""AWS current-state collector for the SK Shieldus 33-rule AI diagnosis flow.

Purpose
-------
- Collect CURRENT AWS configuration/evidence only.
- Do NOT decide PASS/FAIL here.
- Return normalized JSON-serializable data for an LLM to compare against
  ``shieldus_aws_33_rules.json``.
- If one AWS API call fails, record the error and keep collecting other data.

Recommended runtime authentication
----------------------------------
Run this module on the dashboard/backend EC2 with an IAM Role. Do not hard-code
AWS access keys in source code.
"""

from __future__ import annotations

import csv
import io
import json
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError


DEFAULT_REGION = (
    os.getenv("AWS_REGION")
    or os.getenv("AWS_DEFAULT_REGION")
    or "ap-northeast-2"
)


class AWSCollector:
    """Collect normalized evidence required by the 33 diagnosis rules."""

    def __init__(
        self,
        region_name: str = DEFAULT_REGION,
        project_policy: Optional[Dict[str, Any]] = None,
        cloudtrail_lookback_hours: int = 24,
    ) -> None:
        self.region = region_name
        self.session = boto3.Session(region_name=region_name)
        self.errors: List[Dict[str, Any]] = []
        self._managed_policy_cache: Dict[str, Dict[str, Any]] = {}
        self.cloudtrail_lookback_hours = cloudtrail_lookback_hours

        # Organization/project-specific context is intentionally NOT guessed.
        # None means "not provided" so the AI can return REVIEW where required.
        self.project_policy = project_policy or {
            "required_iam_tags": None,
            "approved_group_memberships": None,
            "approved_privileged_identities": None,
            # Rule 4.11 uses 365 days as the guide/default assessment threshold.
            "minimum_log_retention_days": 365,
        }

    # ------------------------------------------------------------------
    # Common helpers
    # ------------------------------------------------------------------

    def _client(self, service_name: str, *, region_name: Optional[str] = None):
        return self.session.client(service_name, region_name=region_name or self.region)

    def _record_error(
        self,
        source: str,
        exc: Exception,
        resource: Optional[str] = None,
    ) -> None:
        if isinstance(exc, ClientError):
            err = exc.response.get("Error", {})
            code = err.get("Code", exc.__class__.__name__)
            message = err.get("Message", str(exc))
        else:
            code = exc.__class__.__name__
            message = str(exc)

        item: Dict[str, Any] = {
            "source": source,
            "error_code": code,
            "message": message,
        }
        if resource:
            item["resource"] = resource
        self.errors.append(item)

    @staticmethod
    def _iso(value: Any) -> Any:
        if isinstance(value, datetime):
            return value.astimezone(timezone.utc).isoformat()
        return value

    @classmethod
    def _json_safe(cls, value: Any) -> Any:
        if isinstance(value, datetime):
            return cls._iso(value)
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        if isinstance(value, dict):
            return {str(k): cls._json_safe(v) for k, v in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [cls._json_safe(v) for v in value]
        return value

    @staticmethod
    def _paginate(client, operation: str, result_key: str, **kwargs) -> List[Any]:
        paginator = client.get_paginator(operation)
        results: List[Any] = []
        for page in paginator.paginate(**kwargs):
            results.extend(page.get(result_key, []))
        return results

    # ------------------------------------------------------------------
    # STS / account metadata
    # ------------------------------------------------------------------

    def collect_identity(self) -> Dict[str, Any]:
        try:
            sts = self._client("sts")
            identity = sts.get_caller_identity()
            return {
                "account_id": identity.get("Account"),
                "arn": identity.get("Arn"),
                "user_id": identity.get("UserId"),
            }
        except (ClientError, BotoCoreError, Exception) as exc:
            self._record_error("sts.get_caller_identity", exc)
            return {"account_id": None, "arn": None, "user_id": None}

    # ------------------------------------------------------------------
    # IAM
    # ------------------------------------------------------------------

    def _managed_policy_document(self, iam, policy_arn: str) -> Dict[str, Any]:
        if policy_arn in self._managed_policy_cache:
            return self._managed_policy_cache[policy_arn]

        try:
            policy = iam.get_policy(PolicyArn=policy_arn).get("Policy", {})
            version_id = policy.get("DefaultVersionId")
            document: Dict[str, Any] = {}
            if version_id:
                document = iam.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=version_id,
                ).get("PolicyVersion", {}).get("Document", {})

            result = {
                "arn": policy_arn,
                "policy_name": policy.get("PolicyName"),
                "path": policy.get("Path"),
                "default_version_id": version_id,
                "document": document,
            }
            self._managed_policy_cache[policy_arn] = result
            return result
        except (ClientError, BotoCoreError, Exception) as exc:
            self._record_error("iam.get_policy_document", exc, policy_arn)
            return {"arn": policy_arn, "document": None, "collection_error": True}

    def _inline_user_policy(self, iam, user_name: str, policy_name: str) -> Dict[str, Any]:
        try:
            doc = iam.get_user_policy(UserName=user_name, PolicyName=policy_name).get("PolicyDocument")
            return {"policy_name": policy_name, "document": doc}
        except (ClientError, BotoCoreError, Exception) as exc:
            self._record_error("iam.get_user_policy", exc, f"{user_name}/{policy_name}")
            return {"policy_name": policy_name, "document": None, "collection_error": True}

    def _inline_group_policy(self, iam, group_name: str, policy_name: str) -> Dict[str, Any]:
        try:
            doc = iam.get_group_policy(GroupName=group_name, PolicyName=policy_name).get("PolicyDocument")
            return {"policy_name": policy_name, "document": doc}
        except (ClientError, BotoCoreError, Exception) as exc:
            self._record_error("iam.get_group_policy", exc, f"{group_name}/{policy_name}")
            return {"policy_name": policy_name, "document": None, "collection_error": True}

    def _inline_role_policy(self, iam, role_name: str, policy_name: str) -> Dict[str, Any]:
        try:
            doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name).get("PolicyDocument")
            return {"policy_name": policy_name, "document": doc}
        except (ClientError, BotoCoreError, Exception) as exc:
            self._record_error("iam.get_role_policy", exc, f"{role_name}/{policy_name}")
            return {"policy_name": policy_name, "document": None, "collection_error": True}

    def _credential_report(self, iam) -> List[Dict[str, Any]]:
        """Return parsed IAM credential report; generate it if not yet available."""
        try:
            try:
                response = iam.get_credential_report()
            except iam.exceptions.CredentialReportNotPresentException:
                iam.generate_credential_report()
                response = None
            except iam.exceptions.CredentialReportExpiredException:
                iam.generate_credential_report()
                response = None

            # Generation is usually quick. Keep the wait short because this endpoint
            # is user-triggered from the dashboard.
            if response is None:
                for _ in range(5):
                    try:
                        response = iam.get_credential_report()
                        break
                    except iam.exceptions.CredentialReportNotReadyException:
                        time.sleep(0.5)

            if not response:
                raise RuntimeError("IAM credential report is not ready")

            content = response["Content"].decode("utf-8")
            rows = list(csv.DictReader(io.StringIO(content)))
            return rows
        except (ClientError, BotoCoreError, Exception) as exc:
            self._record_error("iam.credential_report", exc)
            return []

    @staticmethod
    def _credential_report_view(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create rule-friendly aliases from the IAM credential report CSV."""
        def cv(value: Any) -> Any:
            if not isinstance(value, str):
                return value
            low = value.strip().lower()
            if low == "true":
                return True
            if low == "false":
                return False
            if low in {"n/a", "not_supported", "no_information", ""}:
                return None
            return value

        normalized = [{k: cv(v) for k, v in row.items()} for row in rows]
        root = next((r for r in normalized if r.get("user") == "<root_account>"), None)
        by_user = {str(r.get("user")): r for r in normalized if r.get("user")}

        def key_active(row: Dict[str, Any]) -> List[Any]:
            return [row.get("access_key_1_active"), row.get("access_key_2_active")]

        def key_rotated(row: Dict[str, Any]) -> List[Any]:
            return [row.get("access_key_1_last_rotated"), row.get("access_key_2_last_rotated")]

        return {
            "rows": normalized,
            "by_user": by_user,
            "root_user": root,
            "root_mfa_active": None if root is None else root.get("mfa_active"),
            "root_access_key_active": None if root is None else any(v is True for v in key_active(root)),
            "password_enabled": {u: r.get("password_enabled") for u, r in by_user.items()},
            "password_last_used": {u: r.get("password_last_used") for u, r in by_user.items()},
            "access_key_active": {u: key_active(r) for u, r in by_user.items()},
            "access_key_rotated": {u: key_rotated(r) for u, r in by_user.items()},
            "mfa_active": {u: r.get("mfa_active") for u, r in by_user.items()},
        }

    def collect_iam(self) -> Dict[str, Any]:
        try:
            iam = self._client("iam")

            users_raw = self._paginate(iam, "list_users", "Users")
            groups_raw = self._paginate(iam, "list_groups", "Groups")
            roles_raw = self._paginate(iam, "list_roles", "Roles")

            users: List[Dict[str, Any]] = []
            user_attached_policies: Dict[str, Any] = {}
            user_inline_policies: Dict[str, Any] = {}
            user_tags: Dict[str, Any] = {}
            access_keys: Dict[str, Any] = {}

            for user in users_raw:
                username = user["UserName"]
                tags: List[Dict[str, str]] = []
                attached: List[Dict[str, Any]] = []
                inline: List[Dict[str, Any]] = []
                keys: List[Dict[str, Any]] = []

                try:
                    tags = iam.list_user_tags(UserName=username).get("Tags", [])
                except Exception as exc:
                    self._record_error("iam.list_user_tags", exc, username)

                try:
                    attached_raw = self._paginate(
                        iam,
                        "list_attached_user_policies",
                        "AttachedPolicies",
                        UserName=username,
                    )
                    for policy in attached_raw:
                        detail = self._managed_policy_document(iam, policy["PolicyArn"])
                        attached.append({**policy, "policy_detail": detail})
                except Exception as exc:
                    self._record_error("iam.list_attached_user_policies", exc, username)

                try:
                    names = self._paginate(
                        iam,
                        "list_user_policies",
                        "PolicyNames",
                        UserName=username,
                    )
                    inline = [self._inline_user_policy(iam, username, name) for name in names]
                except Exception as exc:
                    self._record_error("iam.list_user_policies", exc, username)

                try:
                    key_meta = self._paginate(
                        iam,
                        "list_access_keys",
                        "AccessKeyMetadata",
                        UserName=username,
                    )
                    for key in key_meta:
                        last_used = None
                        try:
                            last_used = iam.get_access_key_last_used(
                                AccessKeyId=key["AccessKeyId"]
                            ).get("AccessKeyLastUsed", {})
                        except Exception as exc:
                            self._record_error(
                                "iam.get_access_key_last_used",
                                exc,
                                key.get("AccessKeyId"),
                            )
                        keys.append({
                            "user_name": key.get("UserName", username),
                            "access_key_id": key.get("AccessKeyId"),
                            "status": key.get("Status"),
                            "create_date": key.get("CreateDate"),
                            "last_used": {
                                "last_used_date": (last_used or {}).get("LastUsedDate"),
                                "service_name": (last_used or {}).get("ServiceName"),
                                "region": (last_used or {}).get("Region"),
                            },
                        })
                except Exception as exc:
                    self._record_error("iam.list_access_keys", exc, username)

                users.append(
                    {
                        "user_name": username,
                        "user_id": user.get("UserId"),
                        "arn": user.get("Arn"),
                        "path": user.get("Path"),
                        "create_date": user.get("CreateDate"),
                        "password_last_used": user.get("PasswordLastUsed"),
                    }
                )
                user_tags[username] = tags
                user_attached_policies[username] = attached
                user_inline_policies[username] = inline
                access_keys[username] = keys

            groups: List[Dict[str, Any]] = []
            group_users: Dict[str, Any] = {}
            groups_policies: Dict[str, Any] = {}

            for group in groups_raw:
                group_name = group["GroupName"]
                members: List[str] = []
                attached: List[Dict[str, Any]] = []
                inline: List[Dict[str, Any]] = []

                try:
                    group_data = iam.get_group(GroupName=group_name)
                    members = [u["UserName"] for u in group_data.get("Users", [])]
                except Exception as exc:
                    self._record_error("iam.get_group", exc, group_name)

                try:
                    attached_raw = self._paginate(
                        iam,
                        "list_attached_group_policies",
                        "AttachedPolicies",
                        GroupName=group_name,
                    )
                    attached = [
                        {**p, "policy_detail": self._managed_policy_document(iam, p["PolicyArn"])}
                        for p in attached_raw
                    ]
                except Exception as exc:
                    self._record_error("iam.list_attached_group_policies", exc, group_name)

                try:
                    names = self._paginate(
                        iam,
                        "list_group_policies",
                        "PolicyNames",
                        GroupName=group_name,
                    )
                    inline = [self._inline_group_policy(iam, group_name, name) for name in names]
                except Exception as exc:
                    self._record_error("iam.list_group_policies", exc, group_name)

                groups.append(
                    {
                        "group_name": group_name,
                        "group_id": group.get("GroupId"),
                        "arn": group.get("Arn"),
                        "path": group.get("Path"),
                        "create_date": group.get("CreateDate"),
                    }
                )
                group_users[group_name] = members
                groups_policies[group_name] = {"attached": attached, "inline": inline}

            roles: List[Dict[str, Any]] = []
            roles_policies: Dict[str, Any] = {}

            for role in roles_raw:
                role_name = role["RoleName"]
                attached: List[Dict[str, Any]] = []
                inline: List[Dict[str, Any]] = []

                try:
                    attached_raw = self._paginate(
                        iam,
                        "list_attached_role_policies",
                        "AttachedPolicies",
                        RoleName=role_name,
                    )
                    attached = [
                        {**p, "policy_detail": self._managed_policy_document(iam, p["PolicyArn"])}
                        for p in attached_raw
                    ]
                except Exception as exc:
                    self._record_error("iam.list_attached_role_policies", exc, role_name)

                try:
                    names = self._paginate(
                        iam,
                        "list_role_policies",
                        "PolicyNames",
                        RoleName=role_name,
                    )
                    inline = [self._inline_role_policy(iam, role_name, name) for name in names]
                except Exception as exc:
                    self._record_error("iam.list_role_policies", exc, role_name)

                roles.append(
                    {
                        "role_name": role_name,
                        "role_id": role.get("RoleId"),
                        "arn": role.get("Arn"),
                        "path": role.get("Path"),
                        "create_date": role.get("CreateDate"),
                    }
                )
                roles_policies[role_name] = {"attached": attached, "inline": inline}

            password_policy = None
            try:
                password_policy = iam.get_account_password_policy().get("PasswordPolicy")
            except iam.exceptions.NoSuchEntityException:
                password_policy = None
            except Exception as exc:
                self._record_error("iam.get_account_password_policy", exc)

            credential_rows = self._credential_report(iam)
            credential_report = self._credential_report_view(credential_rows)

            normalized_password_policy = None
            if password_policy is not None:
                normalized_password_policy = {
                    "minimum_password_length": password_policy.get("MinimumPasswordLength"),
                    "require_symbols": password_policy.get("RequireSymbols"),
                    "require_numbers": password_policy.get("RequireNumbers"),
                    "require_uppercase_characters": password_policy.get("RequireUppercaseCharacters"),
                    "require_lowercase_characters": password_policy.get("RequireLowercaseCharacters"),
                    "allow_users_to_change_password": password_policy.get("AllowUsersToChangePassword"),
                    "expire_passwords": password_policy.get("ExpirePasswords"),
                    "max_password_age": password_policy.get("MaxPasswordAge"),
                    "password_reuse_prevention": password_policy.get("PasswordReusePrevention"),
                    "hard_expiry": password_policy.get("HardExpiry"),
                }

            access_key_last_used = {
                user: [
                    {
                        "access_key_id": k.get("access_key_id"),
                        **(k.get("last_used") or {}),
                    }
                    for k in keys
                ]
                for user, keys in access_keys.items()
            }

            # Keep an alias inside credential_report because some diagnosis
            # rules refer to iam.credential_report.access_key_last_used.
            credential_report["access_key_last_used"] = access_key_last_used

            return {
                "users": users,
                "user_tags": user_tags,
                "user_attached_policies": user_attached_policies,
                "user_inline_policies": user_inline_policies,
                "access_keys": access_keys,
                "access_key_last_used": access_key_last_used,
                "credential_report": credential_report,
                "account_password_policy": normalized_password_policy,
                "groups": groups,
                "group_users": group_users,
                "roles": roles,
                # Aggregated aliases intentionally match required_evidence names.
                "users_policies": {
                    user: {
                        "attached": user_attached_policies.get(user, []),
                        "inline": user_inline_policies.get(user, []),
                    }
                    for user in user_attached_policies
                },
                "groups_policies": groups_policies,
                "roles_policies": roles_policies,
            }
        except (ClientError, BotoCoreError, Exception) as exc:
            self._record_error("iam.collect", exc)
            return {}

    # ------------------------------------------------------------------
    # EC2 / VPC
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_ip_permission(permission: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "ip_protocol": permission.get("IpProtocol"),
            "from_port": permission.get("FromPort"),
            "to_port": permission.get("ToPort"),
            "ip_ranges": [
                {"cidr_ip": x.get("CidrIp"), "description": x.get("Description")}
                for x in permission.get("IpRanges", [])
            ],
            "ipv6_ranges": [
                {"cidr_ipv6": x.get("CidrIpv6"), "description": x.get("Description")}
                for x in permission.get("Ipv6Ranges", [])
            ],
            "prefix_list_ids": permission.get("PrefixListIds", []),
            "user_id_group_pairs": permission.get("UserIdGroupPairs", []),
        }

    def collect_ec2(self) -> Dict[str, Any]:
        try:
            ec2 = self._client("ec2")

            reservations = self._paginate(ec2, "describe_instances", "Reservations")
            instances: List[Dict[str, Any]] = []
            for reservation in reservations:
                for instance in reservation.get("Instances", []):
                    instances.append({
                        "instance_id": instance.get("InstanceId"),
                        "state": instance.get("State", {}).get("Name"),
                        "vpc_id": instance.get("VpcId"),
                        "subnet_id": instance.get("SubnetId"),
                        "private_ip_address": instance.get("PrivateIpAddress"),
                        "public_ip_address": instance.get("PublicIpAddress"),
                        "key_name": instance.get("KeyName"),
                        "security_groups": instance.get("SecurityGroups", []),
                        "iam_instance_profile": instance.get("IamInstanceProfile"),
                        "tags": instance.get("Tags", []),
                    })

            raw_sgs = self._paginate(ec2, "describe_security_groups", "SecurityGroups")
            security_groups = []
            for sg in raw_sgs:
                security_groups.append({
                    "group_id": sg.get("GroupId"),
                    "group_name": sg.get("GroupName"),
                    "description": sg.get("Description"),
                    "vpc_id": sg.get("VpcId"),
                    "owner_id": sg.get("OwnerId"),
                    "ip_permissions": [self._normalize_ip_permission(p) for p in sg.get("IpPermissions", [])],
                    "ip_permissions_egress": [self._normalize_ip_permission(p) for p in sg.get("IpPermissionsEgress", [])],
                    "tags": sg.get("Tags", []),
                })
            default_security_groups = [sg for sg in security_groups if sg.get("group_name") == "default"]

            raw_acls = self._paginate(ec2, "describe_network_acls", "NetworkAcls")
            network_acls = [{
                "network_acl_id": acl.get("NetworkAclId"),
                "vpc_id": acl.get("VpcId"),
                "is_default": acl.get("IsDefault"),
                "entries": [{
                    "rule_number": e.get("RuleNumber"),
                    "protocol": e.get("Protocol"),
                    "rule_action": e.get("RuleAction"),
                    "egress": e.get("Egress"),
                    "cidr_block": e.get("CidrBlock"),
                    "ipv6_cidr_block": e.get("Ipv6CidrBlock"),
                    "port_range": e.get("PortRange"),
                    "icmp_type_code": e.get("IcmpTypeCode"),
                } for e in acl.get("Entries", [])],
                "associations": acl.get("Associations", []),
                "tags": acl.get("Tags", []),
            } for acl in raw_acls]

            raw_routes = self._paginate(ec2, "describe_route_tables", "RouteTables")
            route_tables = [{
                "route_table_id": rt.get("RouteTableId"),
                "vpc_id": rt.get("VpcId"),
                "routes": rt.get("Routes", []),
                "associations": rt.get("Associations", []),
                "tags": rt.get("Tags", []),
            } for rt in raw_routes]

            raw_igws = self._paginate(ec2, "describe_internet_gateways", "InternetGateways")
            internet_gateways = [{
                "internet_gateway_id": igw.get("InternetGatewayId"),
                "attachments": igw.get("Attachments", []),
                "tags": igw.get("Tags", []),
            } for igw in raw_igws]

            raw_nat = self._paginate(ec2, "describe_nat_gateways", "NatGateways")
            nat_gateways = [{
                "nat_gateway_id": nat.get("NatGatewayId"),
                "state": nat.get("State"),
                "subnet_id": nat.get("SubnetId"),
                "vpc_id": nat.get("VpcId"),
                "connectivity_type": nat.get("ConnectivityType"),
                "nat_gateway_addresses": nat.get("NatGatewayAddresses", []),
                "tags": nat.get("Tags", []),
            } for nat in raw_nat]

            # 리전마다 AWS가 기본으로 깔아주는 빈 default VPC는 실제로 아무것도
            # 안 올려서 쓰는 경우가 흔하다. 그런 VPC까지 4.10(VPC 플로우 로깅)
            # 진단 대상에 넣으면, 우리가 실제 쓰는 VPC는 Flow Log가 멀쩡히
            # 켜져 있어도 "쓰지도 않는 default VPC에 Flow Log가 없다"는 이유로
            # FAIL이 나는 오탐이 생긴다. default VPC라도 인스턴스가 떠 있으면
            # 실사용 중인 것이니 그대로 진단 대상에 남기고, 인스턴스가 하나도
            # 없는 default VPC만 evidence에서 뺀다.
            used_vpc_ids = {i.get("vpc_id") for i in instances if i.get("vpc_id")}
            raw_vpcs = self._paginate(ec2, "describe_vpcs", "Vpcs")
            vpcs = [
                {
                    "vpc_id": vpc.get("VpcId"),
                    "cidr_block": vpc.get("CidrBlock"),
                    "is_default": vpc.get("IsDefault"),
                    "state": vpc.get("State"),
                    "tags": vpc.get("Tags", []),
                }
                for vpc in raw_vpcs
                if not (vpc.get("IsDefault") and vpc.get("VpcId") not in used_vpc_ids)
            ]

            raw_flow = self._paginate(ec2, "describe_flow_logs", "FlowLogs")
            flow_logs = [{
                "flow_log_id": f.get("FlowLogId"),
                "resource_id": f.get("ResourceId"),
                "flow_log_status": f.get("FlowLogStatus"),
                "traffic_type": f.get("TrafficType"),
                "log_destination_type": f.get("LogDestinationType"),
                "log_destination": f.get("LogDestination"),
                "deliver_logs_status": f.get("DeliverLogsStatus"),
            } for f in raw_flow]

            raw_volumes = self._paginate(ec2, "describe_volumes", "Volumes")
            volumes = [{
                "volume_id": v.get("VolumeId"),
                "encrypted": v.get("Encrypted"),
                "kms_key_id": v.get("KmsKeyId"),
                "state": v.get("State"),
                "size": v.get("Size"),
                "attachments": v.get("Attachments", []),
                "tags": v.get("Tags", []),
            } for v in raw_volumes]

            snapshots: List[Dict[str, Any]] = []
            try:
                raw_snapshots = self._paginate(ec2, "describe_snapshots", "Snapshots", OwnerIds=["self"])
                snapshots = [{
                    "snapshot_id": snap.get("SnapshotId"),
                    "volume_id": snap.get("VolumeId"),
                    "encrypted": snap.get("Encrypted"),
                    "kms_key_id": snap.get("KmsKeyId"),
                    "state": snap.get("State"),
                    "start_time": snap.get("StartTime"),
                    "tags": snap.get("Tags", []),
                } for snap in raw_snapshots]
            except Exception as exc:
                self._record_error("ec2.describe_snapshots", exc)

            return {
                "instances": instances,
                "security_groups": security_groups,
                "default_security_groups": default_security_groups,
                "network_acls": network_acls,
                "route_tables": route_tables,
                "internet_gateways": internet_gateways,
                "nat_gateways": nat_gateways,
                "vpcs": vpcs,
                "flow_logs": flow_logs,
                "volumes": volumes,
                "snapshots": snapshots,
            }
        except (ClientError, BotoCoreError, Exception) as exc:
            self._record_error("ec2.collect", exc)
            return {}

    # ------------------------------------------------------------------
    # S3
    # ------------------------------------------------------------------

    def collect_s3(self, account_id: Optional[str]) -> Dict[str, Any]:
        s3 = self._client("s3")
        result: Dict[str, Any] = {"buckets": [], "account_public_access_block": None}

        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except Exception as exc:
            self._record_error("s3.list_buckets", exc)
            return result

        for bucket in buckets:
            name = bucket["Name"]
            item: Dict[str, Any] = {
                "name": name,
                "creation_date": bucket.get("CreationDate"),
                "region": None,
                "bucket_policy": None,
                "bucket_acl": None,
                "public_access_block": None,
                "bucket_encryption": None,
            }

            try:
                location = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
                item["region"] = location or "us-east-1"
            except Exception as exc:
                self._record_error("s3.get_bucket_location", exc, name)

            try:
                policy = s3.get_bucket_policy(Bucket=name).get("Policy")
                item["bucket_policy"] = json.loads(policy) if policy else None
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") not in {"NoSuchBucketPolicy", "NoSuchPolicy"}:
                    self._record_error("s3.get_bucket_policy", exc, name)
            except Exception as exc:
                self._record_error("s3.get_bucket_policy", exc, name)

            try:
                item["bucket_acl"] = s3.get_bucket_acl(Bucket=name)
            except Exception as exc:
                self._record_error("s3.get_bucket_acl", exc, name)

            try:
                item["public_access_block"] = s3.get_public_access_block(Bucket=name).get(
                    "PublicAccessBlockConfiguration"
                )
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") not in {
                    "NoSuchPublicAccessBlockConfiguration"
                }:
                    self._record_error("s3.get_public_access_block", exc, name)
            except Exception as exc:
                self._record_error("s3.get_public_access_block", exc, name)

            try:
                item["bucket_encryption"] = s3.get_bucket_encryption(Bucket=name).get(
                    "ServerSideEncryptionConfiguration"
                )
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") not in {
                    "ServerSideEncryptionConfigurationNotFoundError"
                }:
                    self._record_error("s3.get_bucket_encryption", exc, name)
            except Exception as exc:
                self._record_error("s3.get_bucket_encryption", exc, name)

            result["buckets"].append(item)

        if account_id:
            try:
                s3control = self._client("s3control")
                result["account_public_access_block"] = s3control.get_public_access_block(
                    AccountId=account_id
                ).get("PublicAccessBlockConfiguration")
            except ClientError as exc:
                # Account-level Public Access Block may simply be unset.
                code = exc.response.get("Error", {}).get("Code")
                if code not in {"NoSuchPublicAccessBlockConfiguration"}:
                    self._record_error("s3control.get_public_access_block", exc, account_id)
            except Exception as exc:
                self._record_error("s3control.get_public_access_block", exc, account_id)

        # Rule-friendly aliases keyed by bucket name.
        result["bucket_policy"] = {b["name"]: b.get("bucket_policy") for b in result["buckets"]}
        result["bucket_acl"] = {b["name"]: b.get("bucket_acl") for b in result["buckets"]}
        result["public_access_block"] = {b["name"]: b.get("public_access_block") for b in result["buckets"]}
        result["bucket_encryption"] = {b["name"]: b.get("bucket_encryption") for b in result["buckets"]}
        return result

    # ------------------------------------------------------------------
    # RDS / DocumentDB
    # ------------------------------------------------------------------

    def collect_rds(self) -> Dict[str, Any]:
        try:
            rds = self._client("rds")
            raw = self._paginate(rds, "describe_db_instances", "DBInstances")
            instances = []
            for db in raw:
                subnet_group = db.get("DBSubnetGroup") or {}
                instances.append(
                    {
                        "db_instance_identifier": db.get("DBInstanceIdentifier"),
                        "engine": db.get("Engine"),
                        "engine_version": db.get("EngineVersion"),
                        "db_instance_status": db.get("DBInstanceStatus"),
                        "storage_encrypted": db.get("StorageEncrypted"),
                        "kms_key_id": db.get("KmsKeyId"),
                        "publicly_accessible": db.get("PubliclyAccessible"),
                        "enabled_cloudwatch_logs_exports": db.get(
                            "EnabledCloudwatchLogsExports", []
                        ),
                        "backup_retention_period": db.get("BackupRetentionPeriod"),
                        "db_subnet_group": {
                            "name": subnet_group.get("DBSubnetGroupName"),
                            "vpc_id": subnet_group.get("VpcId"),
                            "subnet_group_status": subnet_group.get("SubnetGroupStatus"),
                            "subnets": [
                                {
                                    "subnet_id": s.get("SubnetIdentifier"),
                                    "subnet_status": s.get("SubnetStatus"),
                                    "availability_zone": (s.get("SubnetAvailabilityZone") or {}).get(
                                        "Name"
                                    ),
                                }
                                for s in subnet_group.get("Subnets", [])
                            ],
                        },
                        "vpc_security_groups": db.get("VpcSecurityGroups", []),
                    }
                )
            return {"db_instances": instances}
        except (ClientError, BotoCoreError, Exception) as exc:
            self._record_error("rds.collect", exc)
            return {"db_instances": []}

    def collect_docdb(self) -> Dict[str, Any]:
        try:
            docdb = self._client("docdb")
            clusters = self._paginate(docdb, "describe_db_clusters", "DBClusters")
            return {
                "db_clusters": [
                    {
                        "db_cluster_identifier": c.get("DBClusterIdentifier"),
                        "status": c.get("Status"),
                        "storage_encrypted": c.get("StorageEncrypted"),
                        "kms_key_id": c.get("KmsKeyId"),
                        "backup_retention_period": c.get("BackupRetentionPeriod"),
                        "enabled_cloudwatch_logs_exports": c.get(
                            "EnabledCloudwatchLogsExports", []
                        ),
                    }
                    for c in clusters
                ]
            }
        except (ClientError, BotoCoreError, Exception) as exc:
            self._record_error("docdb.collect", exc)
            return {"db_clusters": []}

    # ------------------------------------------------------------------
    # ELB / ACM / CloudFront
    # ------------------------------------------------------------------

    def collect_elb(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "load_balancers": [],
            "listeners": {},
            "attributes": {},
            "classic_load_balancers": [],
        }

        try:
            elbv2 = self._client("elbv2")
            lbs = self._paginate(elbv2, "describe_load_balancers", "LoadBalancers")
            result["load_balancers"] = lbs

            for lb in lbs:
                arn = lb.get("LoadBalancerArn")
                if not arn:
                    continue
                try:
                    listeners = self._paginate(
                        elbv2,
                        "describe_listeners",
                        "Listeners",
                        LoadBalancerArn=arn,
                    )
                    result["listeners"][arn] = listeners
                except Exception as exc:
                    self._record_error("elbv2.describe_listeners", exc, arn)
                try:
                    attrs = elbv2.describe_load_balancer_attributes(
                        LoadBalancerArn=arn
                    ).get("Attributes", [])
                    result["attributes"][arn] = attrs
                except Exception as exc:
                    self._record_error("elbv2.describe_load_balancer_attributes", exc, arn)
        except Exception as exc:
            self._record_error("elbv2.collect", exc)

        try:
            elb = self._client("elb")
            classic = self._paginate(elb, "describe_load_balancers", "LoadBalancerDescriptions")
            classic_output = []
            for lb in classic:
                name = lb.get("LoadBalancerName")
                attrs = None
                if name:
                    try:
                        attrs = elb.describe_load_balancer_attributes(
                            LoadBalancerName=name
                        ).get("LoadBalancerAttributes")
                    except Exception as exc:
                        self._record_error("elb.describe_load_balancer_attributes", exc, name)
                classic_output.append({**lb, "attributes": attrs})
            result["classic_load_balancers"] = classic_output
        except Exception as exc:
            self._record_error("elb.collect", exc)

        return result

    def collect_acm(self) -> Dict[str, Any]:
        try:
            acm = self._client("acm")
            certs = self._paginate(acm, "list_certificates", "CertificateSummaryList")
            output = []
            for cert in certs:
                arn = cert.get("CertificateArn")
                detail = None
                if arn:
                    try:
                        detail = acm.describe_certificate(CertificateArn=arn).get("Certificate")
                    except Exception as exc:
                        self._record_error("acm.describe_certificate", exc, arn)
                output.append({"summary": cert, "detail": detail})
            return {"certificates": output}
        except Exception as exc:
            self._record_error("acm.collect", exc)
            return {"certificates": []}

    def collect_cloudfront(self) -> Dict[str, Any]:
        try:
            cloudfront = self._client("cloudfront", region_name="us-east-1")
            distributions: List[Dict[str, Any]] = []
            paginator = cloudfront.get_paginator("list_distributions")
            for page in paginator.paginate():
                dist_list = page.get("DistributionList", {}) or {}
                for dist in dist_list.get("Items", []) or []:
                    distributions.append(
                        {
                            "id": dist.get("Id"),
                            "arn": dist.get("ARN"),
                            "domain_name": dist.get("DomainName"),
                            "enabled": dist.get("Enabled"),
                            "viewer_certificate": dist.get("ViewerCertificate"),
                            "aliases": dist.get("Aliases"),
                        }
                    )
            return {"distributions": distributions}
        except Exception as exc:
            self._record_error("cloudfront.collect", exc)
            return {"distributions": []}

    # ------------------------------------------------------------------
    # CloudTrail
    # ------------------------------------------------------------------

    def collect_cloudtrail(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "enabled": False,
            "trails": [],
            "event_selectors": {},
            "advanced_event_selectors": {},
            "events": {
                "route_table_changes": [],
                "internet_gateway_changes": [],
                "nat_gateway_changes": [],
            },
            "event_lookback_hours": self.cloudtrail_lookback_hours,
        }

        try:
            ct = self._client("cloudtrail")
            trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
            output_trails = []

            for trail in trails:
                name = trail.get("Name") or trail.get("TrailARN")
                status = None
                selectors_norm: List[Dict[str, Any]] = []
                advanced_norm: List[Dict[str, Any]] = []

                if name:
                    try:
                        status_raw = ct.get_trail_status(Name=name)
                        status = {
                            "is_logging": status_raw.get("IsLogging"),
                            "latest_delivery_time": status_raw.get("LatestDeliveryTime"),
                            "latest_delivery_error": status_raw.get("LatestDeliveryError"),
                        }
                    except Exception as exc:
                        self._record_error("cloudtrail.get_trail_status", exc, name)

                    try:
                        selector_resp = ct.get_event_selectors(TrailName=name)
                        for selector in selector_resp.get("EventSelectors", []):
                            selectors_norm.append({
                                "read_write_type": selector.get("ReadWriteType"),
                                "include_management_events": selector.get("IncludeManagementEvents"),
                                "data_resources": [
                                    {
                                        "type": d.get("Type"),
                                        "values": d.get("Values", []),
                                    }
                                    for d in selector.get("DataResources", [])
                                ],
                                "exclude_management_event_sources": selector.get("ExcludeManagementEventSources", []),
                            })
                        for selector in selector_resp.get("AdvancedEventSelectors", []):
                            advanced_norm.append({
                                "name": selector.get("Name"),
                                "field_selectors": [
                                    {
                                        "field": f.get("Field"),
                                        "equals": f.get("Equals", []),
                                        "starts_with": f.get("StartsWith", []),
                                        "ends_with": f.get("EndsWith", []),
                                        "not_equals": f.get("NotEquals", []),
                                        "not_starts_with": f.get("NotStartsWith", []),
                                        "not_ends_with": f.get("NotEndsWith", []),
                                    }
                                    for f in selector.get("FieldSelectors", [])
                                ],
                            })
                        result["event_selectors"][name] = selectors_norm
                        result["advanced_event_selectors"][name] = advanced_norm
                    except Exception as exc:
                        self._record_error("cloudtrail.get_event_selectors", exc, name)

                output_trails.append({
                    "name": trail.get("Name"),
                    "trail_arn": trail.get("TrailARN"),
                    "s3_bucket_name": trail.get("S3BucketName"),
                    "s3_key_prefix": trail.get("S3KeyPrefix"),
                    "cloud_watch_logs_log_group_arn": trail.get("CloudWatchLogsLogGroupArn"),
                    "cloud_watch_logs_role_arn": trail.get("CloudWatchLogsRoleArn"),
                    "kms_key_id": trail.get("KmsKeyId"),
                    "include_global_service_events": trail.get("IncludeGlobalServiceEvents"),
                    "is_multi_region_trail": trail.get("IsMultiRegionTrail"),
                    "home_region": trail.get("HomeRegion"),
                    "log_file_validation_enabled": trail.get("LogFileValidationEnabled"),
                    "status": status,
                    "event_selectors": selectors_norm,
                    "advanced_event_selectors": advanced_norm,
                })

            result["trails"] = output_trails
            result["enabled"] = any(bool((trail.get("status") or {}).get("is_logging")) for trail in output_trails)

            # Query recent management events once, then classify locally to avoid
            # excessive LookupEvents calls/rate limiting.
            start = datetime.now(timezone.utc) - timedelta(hours=self.cloudtrail_lookback_hours)
            events: List[Dict[str, Any]] = []
            try:
                paginator = ct.get_paginator("lookup_events")
                for page in paginator.paginate(
                    StartTime=start,
                    EndTime=datetime.now(timezone.utc),
                    PaginationConfig={"MaxItems": 500, "PageSize": 50},
                ):
                    events.extend(page.get("Events", []))
            except Exception as exc:
                self._record_error("cloudtrail.lookup_events", exc)

            route_names = {
                "CreateRoute", "ReplaceRoute", "DeleteRoute", "CreateRouteTable",
                "DeleteRouteTable", "AssociateRouteTable", "DisassociateRouteTable",
                "ReplaceRouteTableAssociation",
            }
            igw_names = {
                "CreateInternetGateway", "DeleteInternetGateway",
                "AttachInternetGateway", "DetachInternetGateway",
            }
            nat_names = {"CreateNatGateway", "DeleteNatGateway"}

            for event in events:
                compact = {
                    "event_id": event.get("EventId"),
                    "event_name": event.get("EventName"),
                    "event_time": event.get("EventTime"),
                    "event_source": event.get("EventSource"),
                    "username": event.get("Username"),
                    "resources": event.get("Resources", []),
                    "cloudtrail_event": self._try_parse_json(event.get("CloudTrailEvent")),
                }
                event_name = event.get("EventName")
                if event_name in route_names:
                    result["events"]["route_table_changes"].append(compact)
                if event_name in igw_names:
                    result["events"]["internet_gateway_changes"].append(compact)
                if event_name in nat_names:
                    result["events"]["nat_gateway_changes"].append(compact)

            return result
        except Exception as exc:
            self._record_error("cloudtrail.collect", exc)
            return result

    @staticmethod
    def _try_parse_json(value: Any) -> Any:
        if not isinstance(value, str):
            return value
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value

    # ------------------------------------------------------------------
    # CloudWatch Logs / SSM
    # ------------------------------------------------------------------

    def collect_logs(self) -> Dict[str, Any]:
        try:
            logs = self._client("logs")
            log_groups = self._paginate(logs, "describe_log_groups", "logGroups")
            normalized_groups: List[Dict[str, Any]] = []
            streams: Dict[str, Any] = {}

            for group in log_groups:
                name = group.get("logGroupName")
                normalized_groups.append(
                    {
                        "log_group_name": name,
                        "arn": group.get("arn"),
                        "retention_in_days": group.get("retentionInDays"),
                        "stored_bytes": group.get("storedBytes"),
                        "kms_key_id": group.get("kmsKeyId"),
                        "creation_time": group.get("creationTime"),
                    }
                )
                if name:
                    try:
                        resp = logs.describe_log_streams(
                            logGroupName=name,
                            orderBy="LastEventTime",
                            descending=True,
                            limit=5,
                        )
                        streams[name] = [
                            {
                                "log_stream_name": s.get("logStreamName"),
                                "last_event_timestamp": s.get("lastEventTimestamp"),
                                "last_ingestion_time": s.get("lastIngestionTime"),
                            }
                            for s in resp.get("logStreams", [])
                        ]
                    except Exception as exc:
                        self._record_error("logs.describe_log_streams", exc, name)

            return {"log_groups": normalized_groups, "log_streams": streams}
        except Exception as exc:
            self._record_error("logs.collect", exc)
            return {"log_groups": [], "log_streams": {}}

    def collect_ssm(self) -> Dict[str, Any]:
        result = {"managed_instances": [], "cloudwatch_agent_status": {}}
        try:
            ssm = self._client("ssm")
            instances = self._paginate(
                ssm, "describe_instance_information", "InstanceInformationList"
            )
            result["managed_instances"] = instances

            for instance in instances:
                instance_id = instance.get("InstanceId")
                if not instance_id:
                    continue
                try:
                    entries: List[Dict[str, Any]] = []
                    next_token = None
                    while True:
                        kwargs: Dict[str, Any] = {
                            "InstanceId": instance_id,
                            "TypeName": "AWS:Application",
                            "MaxResults": 50,
                        }
                        if next_token:
                            kwargs["NextToken"] = next_token
                        resp = ssm.list_inventory_entries(**kwargs)
                        entries.extend(resp.get("Entries", []))
                        next_token = resp.get("NextToken")
                        if not next_token:
                            break

                    cw_agent = [
                        entry
                        for entry in entries
                        if "cloudwatch" in str(entry.get("Name", "")).lower()
                        and "agent" in str(entry.get("Name", "")).lower()
                    ]
                    result["cloudwatch_agent_status"][instance_id] = {
                        "inventory_available": True,
                        "applications": cw_agent,
                        "installed": bool(cw_agent),
                    }
                except Exception as exc:
                    self._record_error("ssm.list_inventory_entries", exc, instance_id)
                    result["cloudwatch_agent_status"][instance_id] = {
                        "inventory_available": False,
                        "installed": None,
                    }
            return result
        except Exception as exc:
            self._record_error("ssm.collect", exc)
            return result

    # ------------------------------------------------------------------
    # Master collection
    # ------------------------------------------------------------------

    def collect_all(self) -> Dict[str, Any]:
        """Collect all current-state evidence required by the rule file."""
        identity = self.collect_identity()

        data = {
            "metadata": {
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "region": self.region,
                "collector_version": "1.0.1",
                "diagnosis_performed": False,
            },
            "identity": identity,
            "project_policy": self.project_policy,
            "iam": self.collect_iam(),
            "ec2": self.collect_ec2(),
            "s3": self.collect_s3(identity.get("account_id")),
            "rds": self.collect_rds(),
            "docdb": self.collect_docdb(),
            "elbv2": {},
            "elb": {},
            "acm": self.collect_acm(),
            "cloudfront": self.collect_cloudfront(),
            "cloudtrail": self.collect_cloudtrail(),
            "logs": self.collect_logs(),
            "ssm": self.collect_ssm(),
        }

        # Keep the evidence paths used by the rule file while reusing one ELB call.
        elb_data = self.collect_elb()
        data["elbv2"] = {
            "load_balancers": elb_data.get("load_balancers", []),
            "listeners": elb_data.get("listeners", {}),
            "attributes": elb_data.get("attributes", {}),
        }
        data["elb"] = {
            "classic_load_balancers": elb_data.get("classic_load_balancers", [])
        }

        data["collection_errors"] = self.errors
        return self._json_safe(data)


# ----------------------------------------------------------------------
# Public helpers for Flask/service code
# ----------------------------------------------------------------------


def collect_aws_state(
    region_name: str = DEFAULT_REGION,
    project_policy: Optional[Dict[str, Any]] = None,
    cloudtrail_lookback_hours: int = 24,
) -> Dict[str, Any]:
    """Convenience function used by the Flask diagnosis service."""
    collector = AWSCollector(
        region_name=region_name,
        project_policy=project_policy,
        cloudtrail_lookback_hours=cloudtrail_lookback_hours,
    )
    return collector.collect_all()


if __name__ == "__main__":
    # Local smoke test. On EC2, boto3 should use the attached IAM Role.
    state = collect_aws_state()
    print(json.dumps(state, ensure_ascii=False, indent=2))
