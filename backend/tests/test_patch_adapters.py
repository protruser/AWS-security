import base64
import hashlib
import json
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from cryptography.fernet import Fernet

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.github_terraform_source import GitHubSource, NoRedirect
from services.patch_repository import PatchRepository
from services.patch_security import PatchError, seal, unseal
from services.terraform_remediation_service import generate_change_report, generate_terraform_fix
import migrate_terraform_patches


def github_file(content='resource "aws_s3_bucket" "x" {}\n', path="infra/main.tf"):
    raw = content.encode()
    return {"path": path, "type": "file", "size": len(raw), "encoding": "base64",
            "content": base64.b64encode(raw).decode(),
            "sha": hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()}


class GitHubAdapterTest(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"PATCH_GITHUB_REPOSITORY": "protruser/AWS-Security-Infra", "PATCH_GITHUB_REF": "gyu",
                                      "GITHUB_TOKEN": "read-only-test-token"})
        env.start()
        self.addCleanup(env.stop)

    def test_commit_pinned_and_duplicate_paths_read_once(self):
        with patch.object(GitHubSource, "_get", side_effect=[{"sha": "a" * 40}, github_file()]) as get:
            result = GitHubSource().snapshot(["infra/main.tf", "infra/main.tf"])
        self.assertEqual(len(result["files"]), 1)
        self.assertEqual(get.call_count, 2)
        self.assertEqual(get.call_args.args[0], "contents/infra/main.tf?ref=" + "a" * 40)
        self.assertNotIn("read-only-test-token", json.dumps(result))

    def test_module_tree_excludes_unrelated_dashboard_files(self):
        tree = {"truncated": False, "tree": [
            {"type": "blob", "path": "modules/network/security_groups.tf", "size": 100},
            {"type": "blob", "path": "wonny-sec-terraform/security_groups.tf", "size": 100},
            {"type": "blob", "path": "modules/network/terraform.tfvars", "size": 100},
        ]}
        with patch.object(GitHubSource, "_get", side_effect=[{"sha": "a" * 40}, tree]):
            sha, paths = GitHubSource().terraform_paths()
        self.assertEqual(sha, "a" * 40)
        self.assertEqual(paths, ["modules/network/security_groups.tf"])

    def test_patch_pr_is_draft_until_signed_deployment(self):
        source = GitHubSource()
        patch_row = {"id": "11111111-1111-1111-1111-111111111111", "payload": {"github_pr": {
            "branch": "ai-patch/11111111-1111-1111-1111-111111111111",
            "head_sha": "b" * 40, "base_sha": "a" * 40}}}
        with patch.object(source, "ref_sha", return_value="b" * 40), \
             patch.object(source, "base_sha", return_value="a" * 40), \
             patch.object(source, "_get", return_value=[]), \
             patch.object(source, "_write", return_value={"number": 7, "html_url": "https://github.com/x"}) as write:
            source.create_pr(patch_row)
        self.assertIs(write.call_args.args[2]["draft"], True)

    def test_two_patches_get_distinct_branches_and_only_own_files(self):
        source = GitHubSource()
        def row(patch_id, path):
            return {"id": patch_id, "payload": {"source": {
                "repository": "protruser/AWS-Security-Infra", "ref": "gyu",
                "commit_sha": "a" * 40}, "files": [{"file_path": path,
                "proposed_content": 'resource "aws_s3_bucket" "safe" {}', "diff": "+safe"}]}}
        first = row("11111111-1111-1111-1111-111111111111", "modules/security/main.tf")
        second = row("22222222-2222-2222-2222-222222222222", "modules/network/main.tf")
        responses = [{"sha": "c" * 40}, {"sha": "d" * 40}, {},
                     {"sha": "e" * 40}, {"sha": "f" * 40}, {}]
        with patch.object(source, "base_sha", return_value="a" * 40), \
             patch.object(source, "_get", return_value={"tree": {"sha": "b" * 40}}), \
             patch.object(source, "_write", side_effect=responses) as write:
            info_one = source.commit_patch(first)
            info_two = source.commit_patch(second)
        self.assertNotEqual(info_one["branch"], info_two["branch"])
        self.assertEqual(write.call_args_list[0].args[2]["tree"][0]["path"], "modules/security/main.tf")
        self.assertEqual(write.call_args_list[3].args[2]["tree"][0]["path"], "modules/network/main.tf")

    def test_http_adapter_uses_get_fixed_host_and_time_limit(self):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b'{"sha":"example"}'
        with patch("services.github_terraform_source.build_opener") as opener:
            opener.return_value.open.return_value = response
            GitHubSource()._get("commits/gyu")
        args = opener.return_value.open.call_args
        self.assertEqual(args.args[0].get_method(), "GET")
        self.assertEqual(args.args[0].full_url, "https://api.github.com/repos/protruser/AWS-Security-Infra/commits/gyu")
        self.assertEqual(args.kwargs["timeout"], 20)
        self.assertIsNone(NoRedirect().redirect_request(None, None, 302, "", {}, "https://evil.example"))

    def test_http_failure_never_echoes_token_or_response(self):
        with patch("services.github_terraform_source.build_opener", side_effect=RuntimeError("read-only-test-token")):
            with self.assertRaises(PatchError) as error:
                GitHubSource()._get("commits/gyu")
        self.assertNotIn("read-only-test-token", str(error.exception))

    def test_secret_source_is_rejected(self):
        with patch.object(GitHubSource, "_get", side_effect=[{"sha": "a" * 40}, github_file('password = "secret"')]):
            with self.assertRaises(PatchError) as error:
                GitHubSource().snapshot(["infra/main.tf"])
        self.assertEqual(error.exception.code, "SENSITIVE_CONTENT")

    def test_size_symlink_wrong_path_and_integrity_are_rejected(self):
        for override in ({"size": 50_001}, {"type": "symlink"}, {"target": "secret.tf"},
                         {"encoding": "none"}, {"sha": "b" * 40}, {"path": "other.tf"}):
            with self.subTest(override=override), patch.object(GitHubSource, "_get", side_effect=[
                    {"sha": "a" * 40}, {**github_file(), **override}]):
                with self.assertRaises(PatchError):
                    GitHubSource().snapshot(["infra/main.tf"])

    def test_repository_configuration_cannot_override_host(self):
        with patch.dict(os.environ, {"PATCH_GITHUB_REPOSITORY": "https://evil.example/org/repo"}):
            with self.assertRaises(PatchError):
                GitHubSource()

    def test_pr_run_uses_branch_then_manifest_binds_checked_out_head(self):
        branch = "ai-patch/11111111-1111-1111-1111-111111111111"
        run = {"id": 7, "head_branch": branch, "head_sha": "c" * 40,
               "event": "pull_request"}
        with patch.object(GitHubSource, "_get", return_value={"workflow_runs": [run]}):
            self.assertEqual(GitHubSource().workflow_run(branch, "b" * 40), run)


class PersistenceAdapterTest(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"PATCH_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start()
        self.addCleanup(env.stop)
        self.connection = MagicMock()
        self.cursor = self.connection.__enter__.return_value.cursor.return_value.__enter__.return_value
        db = patch("services.patch_repository.get_connection", return_value=self.connection)
        db.start()
        self.addCleanup(db.stop)
        self.repo = PatchRepository()
        self.row = {"id": "a", "status": "AWAITING_FIRST_APPROVAL", "revision": 3,
                    "diagnosis_run_id": 7, "requested_by": "operator", "content_hash": "f" * 64,
                    "payload": {"files": [{"original_content": "private-source"}], "audit": []}}

    def test_atomic_status_and_revision_guard_encrypts_payload(self):
        self.cursor.rowcount = 1
        self.repo.save(self.row, "AWAITING_FIRST_APPROVAL")
        sql, params = self.cursor.execute.call_args.args
        self.assertIn("WHERE id = %s AND revision = %s AND status = %s", sql)
        self.assertEqual(params[-2:], (3, "AWAITING_FIRST_APPROVAL"))
        self.assertNotIn("private-source", params[2])
        self.assertEqual(unseal(params[2]), self.row["payload"])
        self.assertEqual(self.row["revision"], 4)

    def test_lost_race_is_conflict(self):
        self.cursor.rowcount = 0
        with self.assertRaises(PatchError) as error:
            self.repo.save(self.row, "AWAITING_FIRST_APPROVAL")
        self.assertEqual(error.exception.status, 409)
        self.assertEqual(self.row["revision"], 3)

    def test_stale_background_work_becomes_retained_failure(self):
        value = {**self.row, "status": "GENERATING",
                 "updated_at": datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=20)}
        value["payload_encrypted"] = seal(value.pop("payload"))
        self.cursor.fetchone.return_value = value
        self.cursor.rowcount = 1
        result = self.repo.get("a")
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["payload"]["error"]["code"], "WORKER_INTERRUPTED")
        self.assertEqual(result["payload"]["audit"][-1]["actor"], "system")

    def test_migration_is_additive_and_matches_fresh_schema(self):
        with patch.object(migrate_terraform_patches, "get_connection", return_value=self.connection):
            migrate_terraform_patches.main()
        statements = [call.args[0] for call in self.cursor.execute.call_args_list]
        self.assertTrue(any("CREATE TABLE IF NOT EXISTS terraform_patches" in sql for sql in statements))
        self.assertTrue(any("CREATE TABLE IF NOT EXISTS terraform_patch_deploy_lock" in sql for sql in statements))
        self.assertTrue(all("DROP TABLE" not in sql and "ALTER TABLE" not in sql for sql in statements))
        schema = (Path(__file__).parents[1] / "schema.sql").read_text(encoding="utf-8")
        self.assertIn("CREATE TABLE IF NOT EXISTS terraform_patches", schema)
        self.assertIn("CREATE TABLE IF NOT EXISTS terraform_patch_deploy_lock", schema)


class ModelAdapterTest(unittest.TestCase):
    def test_report_receives_actual_diff_and_disables_provider_storage(self):
        report = {"summary": "changed", "changes": [{"file_path": "a.tf", "evidence": "+safe",
                  "explanation": "change"}], "risks": [], "checks": [],
                  "impact": "unknown", "service_disruption": "unknown", "resource_replacement": "unknown"}
        with patch("services.terraform_remediation_service.OpenAI") as client:
            client.return_value.responses.create.return_value.output_text = json.dumps(report)
            client.return_value.responses.create.return_value.status = "completed"
            files = [{"file_path": "a.tf", "diff": "--- a/a.tf\n+++ b/a.tf\n-old\n+safe\n"}]
            self.assertEqual(generate_change_report(findings=[], files=files), report)
            arguments = client.return_value.responses.create.call_args.kwargs
            self.assertEqual(json.loads(arguments["input"])["diffs"], files)
            self.assertFalse(arguments["store"])

    def test_incomplete_model_code_is_not_accepted(self):
        with patch("services.terraform_remediation_service.OpenAI") as client:
            client.return_value.responses.create.return_value.status = "incomplete"
            from services.terraform_remediation_service import RemediationError
            with self.assertRaises(RemediationError):
                generate_terraform_fix(finding={}, file_path="a.tf", file_content="a", api_key="test")


if __name__ == "__main__":
    unittest.main()
