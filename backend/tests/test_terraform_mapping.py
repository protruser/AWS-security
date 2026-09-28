import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.terraform_mapping import preview


class MappingTest(unittest.TestCase):
    def test_real_declarations_suggest_only_matching_files(self):
        source = Mock()
        source.terraform_paths.return_value = ("a" * 40, [
            "modules/network/security_groups.tf", "modules/compute/iam_permissions.tf"])
        source.snapshot.return_value = {"repository": "protruser/AWS-Security-Infra", "ref": "gyu",
            "commit_sha": "a" * 40, "files": [
                {"file_path": "modules/network/security_groups.tf",
                 "original_content": 'resource "aws_security_group" "dashboard" {\n name = "dashboard"\n}\n'},
                {"file_path": "modules/compute/iam_permissions.tf",
                 "original_content": 'resource "aws_iam_role_policy" "dashboard_aws_read" {}\n'},
            ]}
        result = preview(source, [
            {"rule_id": "3.7", "resource_type": "security_group", "resource_ids": ["sg-123abc"]},
            {"rule_id": "3.8", "resource_type": "security_group", "resource_ids": ["sg-456def"]},
            {"rule_id": "1.1", "resource_type": "iam.users", "resource_ids": ["alice"]},
        ], index={"sg-123abc": {("aws_security_group", "dashboard", "module.network")}})
        for rule in ("3.7", "3.8"):
            self.assertEqual(result["mapping"][rule]["candidates"][0]["file_path"],
                             "modules/network/security_groups.tf")
        self.assertEqual(result["mapping"]["3.7"]["status"], "MATCHED")
        self.assertEqual(result["mapping"]["3.8"]["status"], "MANUAL_REVIEW")
        self.assertEqual(result["mapping"]["1.1"]["status"], "MANUAL_REVIEW")

    def test_source_change_rejected(self):
        source = Mock()
        source.terraform_paths.return_value = ("a" * 40, ["modules/network/main.tf"])
        source.snapshot.return_value = {"commit_sha": "b" * 40, "files": []}
        with self.assertRaises(Exception):
            preview(source, [{"rule_id": "3.7"}])
