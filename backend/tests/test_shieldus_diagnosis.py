"""Evidence-grounded checks for the seven source-sensitive diagnosis rules."""

import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.ai_diagnosis_service import AIDiagnosisService, TARGET_RULE_IDS
from services import ai_diagnosis_service
from services.aws_collector import AWSCollector


def iam_state():
    return {
        "users": [], "groups": [], "roles": [],
        "user_attached_policies": {}, "group_users": {},
        "users_policies": {}, "groups_policies": {}, "roles_policies": {},
    }


def principal(kind, name, *policies):
    arn = f"arn:aws:iam::123456789012:{kind}/{name}"
    key = {"user": "user_name", "group": "group_name", "role": "role_name"}[kind]
    return {key: name, "arn": arn}, {"attached": list(policies), "inline": []}


def policy(name, action=None):
    result = {"PolicyName": name, "PolicyArn": f"arn:aws:iam::aws:policy/{name}"}
    if action:
        result["policy_detail"] = {"document": {"Statement": [{
            "Effect": "Allow", "Action": action, "Resource": "*",
        }]}}
    return result


def s3_bucket(name, status, encryption=None):
    return {"name": name, "bucket_encryption_status": status, "bucket_encryption": encryption}


def encryption(algorithm):
    return {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": algorithm}}]}


class SevenRuleDiagnosisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with patch.object(ai_diagnosis_service, "OpenAI"):
            cls.service = AIDiagnosisService(api_key="test-key")
        cls.rules = {str(rule["id"]): rule for rule in cls.service.rules}

    def evaluate(self, rule_id, state):
        return self.service._evaluate_target(self.rules[rule_id], state)

    def assert_linked(self, row):
        evidence_ids = {item["resource"] for item in row["evidence"]}
        self.assertTrue(set(row["resource_ids"]).issubset(evidence_ids))

    def test_1_1_direct_only_group_and_inline_not_counted(self):
        user, entry = principal("user", "alice", policy("AdministratorAccess"))
        state = {"iam": iam_state()}
        state["iam"].update({
            "users": [user], "user_attached_policies": {"alice": entry["attached"]},
            "group_users": {"admins": ["alice"]},
            "groups_policies": {"admins": {"attached": [policy("AdministratorAccess")]}},
        })
        row = self.evaluate("1.1", state)
        self.assertEqual(row["status"], "FAIL")
        self.assertEqual(row["resource_ids"], [user["arn"]])
        self.assert_linked(row)
        self.assertIn('"attachment_type": "direct"', row["evidence"][0]["value"])

        state["iam"]["user_attached_policies"]["alice"] = []
        state["iam"]["user_inline_policies"] = {"alice": [{"policy_name": "AdministratorAccess"}]}
        row = self.evaluate("1.1", state)
        self.assertEqual(row["status"], "PASS")
        self.assertTrue(any("via_group_not_counted" in item["value"] for item in row["evidence"]))
        state["iam"].pop("user_attached_policies")
        self.assertEqual(self.evaluate("1.1", state)["status"], "REVIEW")

    def test_1_1_multiple_users_have_distinct_evidence(self):
        state = {"iam": iam_state()}
        for name in ("alice", "bob"):
            user, _ = principal("user", name)
            state["iam"]["users"].append(user)
            state["iam"]["user_attached_policies"][name] = [policy("AdministratorAccess")]
        row = self.evaluate("1.1", state)
        self.assertEqual(len(row["resource_ids"]), 2)
        self.assert_linked(row)
        for evidence in row["evidence"]:
            self.assertIn(evidence["resource"], evidence["value"])

    def test_1_5_key_pair_and_ssm_are_separate(self):
        state = {"ec2": {"instances": [
            {"instance_id": "i-absent", "key_name": None, "key_pair_status": "ABSENT"},
            {"instance_id": "i-attached", "key_name": "my-key", "key_pair_status": "ATTACHED"},
        ]}, "ssm": {"managed_instances": [{"InstanceId": "i-absent"}]}}
        row = self.evaluate("1.5", state)
        self.assertEqual(row["status"], "FAIL")
        self.assertEqual(row["resource_results"][0]["status"], "FAIL")
        self.assertEqual(row["resource_results"][1]["status"], "PASS")
        self.assertIn("i-absent", row["operational_context"]["ssm_managed_instance_ids"])
        self.assert_linked(row)
        state["ec2"]["instances"] = [state["ec2"]["instances"][1]]
        self.assertEqual(self.evaluate("1.5", state)["status"], "PASS")
        state["ec2"]["instances"] = [{"instance_id": "i-unknown"}]
        self.assertEqual(self.evaluate("1.5", state)["status"], "REVIEW")

    def test_2_x_threshold_per_service_scope_and_direct_principal(self):
        names = {"2.1": "AmazonEC2FullAccess", "2.2": "AmazonVPCFullAccess", "2.3": "CloudWatchFullAccess"}
        for rule_id, policy_name in names.items():
            with self.subTest(rule_id=rule_id):
                state = {"iam": iam_state()}
                for kind, name in (("user", "alice"), ("group", "admins"), ("role", "deploy")):
                    item, entry = principal(kind, name, policy(policy_name), policy(policy_name))
                    state["iam"][{"user": "users", "group": "groups", "role": "roles"}[kind]].append(item)
                    state["iam"][{"user": "users_policies", "group": "groups_policies", "role": "roles_policies"}[kind]][name] = entry
                    if kind == "user":
                        state["iam"]["user_attached_policies"][name] = entry["attached"]
                row = self.evaluate(rule_id, state)
                self.assertEqual(row["status"], "FAIL")
                self.assertEqual(row["observed_unique_principal_count"], 3)
                self.assertEqual(len(row["resource_ids"]), 3)
                self.assert_linked(row)
                self.assertEqual(len([x for x in row["evidence"] if x["resource"] != "iam"]), 3)
                self.assertIn("project_custom_threshold", row["assessment_basis"])

                state["iam"]["roles"] = []
                state["iam"]["roles_policies"] = {}
                self.assertEqual(self.evaluate(rule_id, state)["status"], "PASS")
                state["iam"].pop("groups_policies")
                self.assertEqual(self.evaluate(rule_id, state)["status"], "REVIEW")

    def test_2_x_vpc_policy_does_not_count_as_instance_ec2_policy(self):
        state = {"iam": iam_state()}
        user, entry = principal("user", "alice", policy("AmazonVPCFullAccess", "ec2:*"))
        state["iam"]["users"] = [user]
        state["iam"]["users_policies"] = {"alice": entry}
        self.assertEqual(self.evaluate("2.1", state)["observed_unique_principal_count"], 0)
        self.assertEqual(self.evaluate("2.2", state)["observed_unique_principal_count"], 1)

    def test_2_x_unclassified_customer_managed_wildcard_requires_review(self):
        state = {"iam": iam_state()}
        user, entry = principal("user", "alice", {
            "PolicyName": "CustomAdmin",
            "PolicyArn": "arn:aws:iam::123456789012:policy/CustomAdmin",
            "policy_detail": {"document": {"Statement": [{
                "Effect": "Allow", "Action": "*", "Resource": "*",
            }]}},
        })
        state["iam"]["users"] = [user]
        state["iam"]["users_policies"] = {"alice": entry}
        for rule_id in ("2.1", "2.2", "2.3"):
            with self.subTest(rule_id=rule_id):
                self.assertEqual(self.evaluate(rule_id, state)["status"], "REVIEW")

    def test_missing_inventory_never_creates_findings_for_seven_rules(self):
        for rule_id in ("1.1", "1.5", "2.1", "2.2", "2.3", "3.1", "4.3"):
            with self.subTest(rule_id=rule_id):
                row = self.evaluate(rule_id, {})
                self.assertEqual(row["status"], "REVIEW")
                self.assertEqual(row["resource_ids"], [])
                self.assertTrue(row["evidence"])

    def test_empty_collections_follow_rule_specific_na_or_custom_zero(self):
        state = {"iam": iam_state(), "ec2": {"instances": [], "security_groups": []}, "s3": {"buckets": []}}
        for rule_id in ("1.1", "1.5", "3.1", "4.3"):
            with self.subTest(rule_id=rule_id):
                self.assertEqual(self.evaluate(rule_id, state)["status"], "N/A")
        for rule_id in ("2.1", "2.2", "2.3"):
            with self.subTest(rule_id=rule_id):
                row = self.evaluate(rule_id, state)
                self.assertEqual(row["status"], "PASS")
                self.assertEqual(row["observed_unique_principal_count"], 0)

    def test_3_1_preserves_direction_ports_and_unverified_custom_expression(self):
        state = {"ec2": {"security_groups": [{
            "group_id": "sg-one", "ip_permissions": [{
                "ip_protocol": "-1", "from_port": None, "to_port": None,
                "ip_ranges": [{"cidr_ip": "0.0.0.0/0"}], "ipv6_ranges": [],
                "prefix_list_ids": [], "user_id_group_pairs": [],
            }], "ip_permissions_egress": [{
                "ip_protocol": "tcp", "from_port": 0, "to_port": 65535,
                "ip_ranges": [{"cidr_ip": "10.0.0.0/8"}], "ipv6_ranges": [],
                "prefix_list_ids": [], "user_id_group_pairs": [],
            }],
        }, {"group_id": "sg-two", "ip_permissions": [], "ip_permissions_egress": []}]}}
        row = self.evaluate("3.1", state)
        self.assertEqual(row["status"], "REVIEW")
        self.assertEqual(len(row["resource_ids"]), 2)
        self.assert_linked(row)
        one = [json.loads(x["value"]) for x in row["evidence"] if x["resource"] == "sg-one"]
        self.assertEqual([x["direction"] for x in one], ["inbound", "outbound"])
        self.assertTrue(one[0]["all_protocols"])
        self.assertTrue(one[1]["all_port_range"])
        self.assertEqual(one[0]["source_or_destination"]["ipv4"], ["0.0.0.0/0"])
        self.assertFalse(row["assessment_basis"]["source_custom_expression_verified"])
        state["ec2"]["security_groups"] = [{"group_id": "sg-one", "ip_permissions": [], "ip_permissions_egress": []}]
        self.assertEqual(self.evaluate("3.1", state)["status"], "REVIEW")
        state["ec2"]["security_groups"] = [{"group_id": "sg-one"}]
        self.assertEqual(self.evaluate("3.1", state)["status"], "REVIEW")

    def test_4_3_encryption_absent_configured_and_api_error(self):
        state = {"s3": {"buckets": [
            s3_bucket("plain", "ABSENT"),
            s3_bucket("sse-s3", "CONFIGURED", encryption("AES256")),
            s3_bucket("sse-kms", "CONFIGURED", encryption("aws:kms")),
        ]}}
        row = self.evaluate("4.3", state)
        self.assertEqual(row["status"], "FAIL")
        self.assertEqual([x["status"] for x in row["resource_results"]], ["FAIL", "PASS", "PASS"])
        self.assert_linked(row)
        state["s3"]["buckets"] = state["s3"]["buckets"][1:]
        self.assertEqual(self.evaluate("4.3", state)["status"], "PASS")
        state["s3"]["buckets"].append(s3_bucket("error", "ERROR"))
        self.assertEqual(self.evaluate("4.3", state)["status"], "REVIEW")
        state["s3"]["buckets"] = [s3_bucket("unknown", "UNKNOWN")]
        self.assertEqual(self.evaluate("4.3", state)["status"], "REVIEW")

    def test_collector_distinguishes_s3_absent_from_access_denied(self):
        collector = AWSCollector()
        client = MagicMock()
        client.list_buckets.return_value = {"Buckets": [{"Name": "plain"}, {"Name": "denied"}]}
        client.get_bucket_location.return_value = {"LocationConstraint": "ap-northeast-2"}
        client.get_bucket_policy.side_effect = ClientError({"Error": {"Code": "NoSuchBucketPolicy"}}, "GetBucketPolicy")
        client.get_public_access_block.side_effect = ClientError({"Error": {"Code": "NoSuchPublicAccessBlockConfiguration"}}, "GetPublicAccessBlock")
        client.get_bucket_encryption.side_effect = [
            ClientError({"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}}, "GetBucketEncryption"),
            ClientError({"Error": {"Code": "AccessDenied"}}, "GetBucketEncryption"),
        ]
        collector._client = lambda *args, **kwargs: client
        result = collector.collect_s3(None)
        self.assertEqual(result["bucket_encryption_status"], {"plain": "ABSENT", "denied": "ERROR"})
        self.assertEqual(len([x for x in collector.errors if x["source"] == "s3.get_bucket_encryption"]), 1)

    def test_collector_preserves_ec2_key_name_and_permission_values(self):
        collector = AWSCollector()
        collector._client = lambda *args, **kwargs: MagicMock()
        responses = {
            "describe_instances": [{"Instances": [
                {"InstanceId": "i-none"},
                {"InstanceId": "i-key", "KeyName": "actual-key"},
            ]}],
            "describe_security_groups": [{
                "GroupId": "sg-real", "IpPermissions": [{
                    "IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535,
                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                }], "IpPermissionsEgress": [],
            }],
        }
        collector._paginate = lambda client, operation, result_key, **kwargs: responses.get(operation, [])
        state = collector.collect_ec2()
        self.assertEqual([item["key_pair_status"] for item in state["instances"]], ["ABSENT", "ATTACHED"])
        self.assertEqual(state["instances"][1]["key_name"], "actual-key")
        permission = state["security_groups"][0]["ip_permissions"][0]
        self.assertEqual((permission["from_port"], permission["to_port"]), (0, 65535))
        self.assertEqual(permission["ip_ranges"][0]["cidr_ip"], "10.0.0.0/8")

    def test_full_33_rule_flow_keeps_other_rules_and_existing_fields(self):
        service = self.service
        original_create = service.client.responses.create
        original_comment = service.generate_consultant_comment
        requested = []

        def fake_create(**kwargs):
            payload = json.loads(kwargs["input"][0]["content"])
            requested.extend(str(rule["id"]) for rule in payload["rules"])
            rows = [{
                "rule_id": str(rule["id"]), "status": "PASS", "severity": rule["severity"],
                "resource_ids": [], "current_value": "fixture", "expected_value": "fixture",
                "evidence": [], "reason": "fixture", "recommendation": "fixture",
            } for rule in payload["rules"]]
            return SimpleNamespace(output_text=json.dumps({"category": payload["category"], "results": rows}))

        try:
            service.client.responses.create = fake_create
            service.generate_consultant_comment = lambda *_: ""
            state = {"iam": iam_state(), "ec2": {"instances": [], "security_groups": []}, "s3": {"buckets": []}}
            result = service.diagnose_all(state)
        finally:
            service.client.responses.create = original_create
            service.generate_consultant_comment = original_comment

        self.assertEqual(result["summary"]["total"], 33)
        self.assertEqual(len(result["results"]), 33)
        self.assertEqual(len(requested), 26)
        self.assertFalse(set(requested) & TARGET_RULE_IDS)
        self.assertEqual(set(requested), {str(rule["id"]) for rule in service.rules} - TARGET_RULE_IDS)
        self.assertEqual([x["rule_id"] for x in result["results"]], [str(x["id"]) for x in service.rules])
        required = {"rule_id", "status", "severity", "resource_ids", "current_value", "expected_value", "evidence", "reason", "recommendation"}
        for row in result["results"]:
            self.assertTrue(required.issubset(row))


if __name__ == "__main__":
    unittest.main()
