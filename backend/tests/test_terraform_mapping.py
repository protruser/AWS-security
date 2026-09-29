import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.terraform_mapping import preview


def source_with(files):
    source = Mock()
    source.terraform_paths.return_value = ("a" * 40, sorted(files))
    source.snapshot.return_value = {"repository": "protruser/AWS-Security-Infra", "ref": "gyu",
        "commit_sha": "a" * 40, "files": [
            {"file_path": path, "original_content": content} for path, content in files.items()]}
    return source


def log_group(name):
    return f'resource "aws_cloudwatch_log_group" "{name}" {{\n  retention_in_days = 30\n}}\n'


class MappingTest(unittest.TestCase):
    def test_real_declarations_suggest_only_matching_files(self):
        source = source_with({
            "modules/network/security_groups.tf": 'resource "aws_security_group" "dashboard" {\n name = "dashboard"\n}\n',
            "modules/compute/iam_permissions.tf": 'resource "aws_iam_role_policy" "dashboard_aws_read" {}\n',
        })
        result = preview(source, [
            {"rule_id": "3.1", "resource_type": "security_group", "resource_ids": ["sg-123abc"]},
            {"rule_id": "3.2", "resource_type": "security_group", "resource_ids": ["sg-456def"]},
            {"rule_id": "1.1", "resource_type": "iam.users", "resource_ids": ["alice"]},
        ], index={"sg-123abc": {("aws_security_group", "dashboard", "module.network")}})
        for rule in ("3.1", "3.2"):
            self.assertEqual(result["mapping"][rule]["candidates"][0]["file_path"],
                             "modules/network/security_groups.tf")
        self.assertEqual(result["mapping"]["3.1"]["status"], "MATCHED")
        self.assertEqual(result["mapping"]["3.2"]["status"], "MANUAL_REVIEW")
        # 매핑은 리소스 이름만 쓰므로 선택과 무관한 파일의 비밀값 검사로 막히지 않는다.
        source.snapshot.assert_called_once_with(
            ["modules/compute/iam_permissions.tf", "modules/network/security_groups.tf"], check_secrets=False)

    def test_multi_resource_finding_shows_which_ids_each_file_covers(self):
        source = source_with({
            "modules/network/a.tf": 'resource "aws_security_group" "a" {}\n',
            "modules/network/b.tf": 'resource "aws_security_group" "b" {}\n',
        })
        index = {
            "sg-one": {("aws_security_group", "a", "module.network")},
            "sg-two": {("aws_security_group", "b", "module.network")},
        }
        item = preview(source, [{"rule_id": "3.1", "resource_ids": ["sg-one", "sg-two", "sg-three"]}],
                       index=index)["mapping"]["3.1"]
        self.assertEqual(item["status"], "MANUAL_REVIEW")
        self.assertEqual(item["unmapped_resource_ids"], ["sg-three"])
        covered = {candidate["file_path"]: candidate["covered_resource_ids"] for candidate in item["candidates"]}
        self.assertEqual(covered["modules/network/a.tf"], ["sg-one"])
        self.assertEqual(covered["modules/network/b.tf"], ["sg-two"])

    def test_rule_table_ignores_misleading_keywords(self):
        # 4.11 진단 문장에 WAF 로그 그룹 이름이 들어 있어도 WAF 파일이 아니라 로그 그룹 파일을 고른다.
        source = source_with({
            "modules/edge/alb_waf.tf": 'resource "aws_wafv2_web_acl" "shop" {}\n',
            "modules/security/logging.tf": log_group("vpc_flow"),
            "modules/security/waf_log_groups.tf": log_group("shop") + log_group("admin"),
        })
        item = preview(source, [{"rule_id": "4.11", "resource_ids": ["aws-waf-logs-wonny-sec-shop"],
                                 "reason": "waf 로그 그룹 보존기간 30일"}], index={})["mapping"]["4.11"]
        self.assertEqual(item["suggested"], ["modules/security/waf_log_groups.tf", "modules/security/logging.tf"])
        self.assertNotIn("modules/edge/alb_waf.tf", [c["file_path"] for c in item["candidates"]])

    def test_suggestions_are_capped_at_patch_file_limit(self):
        files = {f"modules/lambda_{i}/main.tf": log_group(f"l{i}") for i in range(6)}
        item = preview(source_with(files), [{"rule_id": "4.11"}], index={})["mapping"]["4.11"]
        self.assertEqual(len(item["suggested"]), 5)
        self.assertEqual(item["total_candidates"], 6)

    def test_account_level_rules_are_not_terraform(self):
        source = source_with({"modules/compute/iam.tf": 'resource "aws_iam_role" "ec2" {}\n'})
        item = preview(source, [{"rule_id": "1.6", "reason": "root iam usage"}], index={})["mapping"]["1.6"]
        self.assertEqual((item["status"], item["candidates"], item["suggested"]), ("NOT_TERRAFORM", [], []))

    def test_mapped_rule_without_declaration_has_no_candidate(self):
        source = source_with({"modules/security/logging.tf": log_group("vpc_flow")})
        item = preview(source, [{"rule_id": "4.2"}], index={})["mapping"]["4.2"]
        self.assertEqual((item["status"], item["suggested"]), ("NO_CANDIDATE", []))

    def test_source_change_rejected(self):
        source = Mock()
        source.terraform_paths.return_value = ("a" * 40, ["modules/network/main.tf"])
        source.snapshot.return_value = {"commit_sha": "b" * 40, "files": []}
        with self.assertRaises(Exception):
            preview(source, [{"rule_id": "3.7"}])


if __name__ == "__main__":
    unittest.main()
