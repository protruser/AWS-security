"""Read-only GitHub source adapter. No write endpoints, redirects or git CLI."""
import base64
import hashlib
import json
import os
import re
import io
import zipfile
from urllib.parse import quote, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.error import HTTPError

from services.patch_security import PatchError, check_sensitive, safe_path


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHubSource:
    def __init__(self):
        self.repository = os.getenv("PATCH_GITHUB_REPOSITORY", "protruser/AWS-Security-Infra")
        self.ref = os.getenv("PATCH_GITHUB_REF", "gyu")
        if self.repository != "protruser/AWS-Security-Infra" or self.ref != "gyu":
            raise PatchError("GITHUB_CONFIG", "Terraform patches require protruser/AWS-Security-Infra at gyu.", 503)
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", self.repository) or not self.ref:
            raise PatchError("GITHUB_CONFIG", "패치용 GitHub 저장소와 기준 브랜치 설정이 필요합니다.", 503)

    def _get(self, path):
        return self._request("GET", path)

    def _request(self, method, path, payload=None):
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "security-patch-review",
                   "X-GitHub-Api-Version": "2022-11-28"}
        token = os.getenv("GITHUB_TOKEN", "").strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            data = json.dumps(payload).encode() if payload is not None else None
            if data is not None:
                headers["Content-Type"] = "application/json"
            req = Request(f"https://api.github.com/repos/{self.repository}/{path}", data=data,
                          headers=headers, method=method)
            with build_opener(NoRedirect()).open(req, timeout=20) as response:
                raw = response.read(1_000_001)
            if len(raw) > 1_000_000:
                raise ValueError("response limit")
            return json.loads(raw) if raw else {}
        except Exception:
            raise PatchError("GITHUB_API_FAILED", "GitHub 요청에 실패했습니다. 저장소와 권한을 확인하세요.", 502) from None

    def _write(self, method, path, payload):
        if os.getenv("PATCH_ENABLE_GITHUB_WRITES") != "true":
            raise PatchError("GITHUB_WRITES_DISABLED", "GitHub 쓰기 기능이 비활성화되어 있습니다.", 503)
        if not os.getenv("GITHUB_TOKEN", ""):
            raise PatchError("GITHUB_CONFIG", "GitHub 쓰기 토큰이 필요합니다.", 503)
        return self._request(method, path, payload)

    def base_sha(self):
        sha = self._get(f"commits/{quote(self.ref, safe='')}").get("sha", "")
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise PatchError("INVALID_SOURCE", "기준 브랜치 commit 확인에 실패했습니다.", 502)
        return sha

    def terraform_paths(self):
        """List actual module files at one commit; never infer a path from a rule."""
        sha = self.base_sha()
        tree = self._get(f"git/trees/{sha}?recursive=1")
        if tree.get("truncated") or not isinstance(tree.get("tree"), list):
            raise PatchError("INVALID_SOURCE", "Terraform file tree is incomplete.", 502)
        paths = []
        for item in tree["tree"]:
            path = item.get("path", "")
            if (item.get("type") == "blob" and path.startswith("modules/")
                    and path.endswith(".tf") and item.get("size", 50_001) <= 50_000):
                safe_path(path)
                paths.append(path)
        return sha, sorted(paths)

    def ref_sha(self, branch):
        sha = self._get(f"git/ref/heads/{quote(branch, safe='/')}").get("object", {}).get("sha", "")
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise PatchError("INVALID_SOURCE", "패치 브랜치 commit 확인에 실패했습니다.", 502)
        return sha

    def commit_patch(self, patch):
        source = patch["payload"]["source"]
        base = source["commit_sha"]
        if source["repository"] != self.repository or source["ref"] != self.ref or self.base_sha() != base:
            raise PatchError("BASE_CHANGED", "운영 브랜치가 변경되었습니다. 새 패치와 승인·검증이 필요합니다.", 409)
        branch = f'ai-patch/{patch["id"]}'
        commit = self._get(f"git/commits/{base}")
        tree_sha = commit.get("tree", {}).get("sha")
        if not tree_sha:
            raise PatchError("GITHUB_API_FAILED", "기준 commit의 트리를 확인할 수 없습니다.", 502)
        tree = [{"path": file["file_path"], "mode": "100644", "type": "blob",
                 "content": file["proposed_content"]} for file in patch["payload"]["files"] if file["diff"]]
        if not tree:
            raise PatchError("NO_CHANGES", "커밋할 변경사항이 없습니다.")
        new_tree = self._write("POST", "git/trees", {"base_tree": tree_sha, "tree": tree})["sha"]
        new_commit = self._write("POST", "git/commits", {
            "message": f"security: Terraform patch {patch['id']}", "tree": new_tree, "parents": [base]})["sha"]
        self._write("POST", "git/refs", {"ref": f"refs/heads/{branch}", "sha": new_commit})
        return {"branch": branch, "base_sha": base, "head_sha": new_commit,
                "repository": self.repository, "base_ref": self.ref}

    def create_pr(self, patch):
        info = patch["payload"]["github_pr"]
        if self.ref_sha(info["branch"]) != info["head_sha"] or self.base_sha() != info["base_sha"]:
            raise PatchError("CODE_CHANGED", "브랜치 또는 운영 코드가 변경되어 PR을 만들 수 없습니다.", 409)
        owner = self.repository.split("/", 1)[0]
        existing = self._get(f"pulls?state=open&head={quote(owner + ':' + info['branch'], safe='')}&base={quote(self.ref, safe='')}")
        if existing:
            if (len(existing) != 1 or existing[0].get("head", {}).get("sha") != info["head_sha"]
                    or existing[0].get("draft") is not True):
                raise PatchError("PR_CONFLICT", "동일 브랜치 PR의 코드가 변경되었습니다.", 409)
            return {"number": existing[0]["number"], "url": existing[0]["html_url"]}
        result = self._write("POST", "pulls", {
            "title": f"Terraform security patch {patch['id']}",
            "head": info["branch"], "base": self.ref,
            "body": f"Patch ID: {patch['id']}\nHuman first approval: recorded in dashboard.\n"
                    "Terraform apply requires a separate final approval.", "draft": True})
        return {"number": result["number"], "url": result["html_url"]}

    def pr_state(self, number):
        return self._get(f"pulls/{int(number)}")

    def repository_info(self):
        # Repository metadata is outside /repos/{owner}/{name}/... endpoints.
        return self._get("")

    def dispatch_deploy(self, patch_id, authorization):
        if os.getenv("PATCH_ENABLE_TERRAFORM_APPLY") != "true":
            raise PatchError("APPLY_DISABLED", "Terraform 배포 기능이 비활성화되어 있습니다.", 503)
        # The workflow must be installed on GitHub's default branch as well;
        # its dispatch ref remains the protected gyu branch.
        return self._write("POST", "actions/workflows/terraform-patch-deploy.yml/dispatches", {
            "ref": self.ref, "inputs": {"patch_id": patch_id, "authorization": authorization}})

    def deployment_run(self, patch_id, dispatched_at):
        runs = self._get("actions/workflows/terraform-patch-deploy.yml/runs?event=workflow_dispatch&per_page=100")
        candidates = [run for run in runs.get("workflow_runs", [])
                      if run.get("display_title") == f"Terraform patch {patch_id}"
                      and run.get("created_at", "") >= dispatched_at]
        return max(candidates, key=lambda run: run["id"]) if candidates else None

    def workflow_run(self, branch, head_sha, workflow="terraform-patch.yml"):
        query = f"actions/workflows/{workflow}/runs?event=pull_request&branch={quote(branch, safe='')}&per_page=30"
        for run in self._get(query).get("workflow_runs", []):
            # A pull_request run can use GitHub's synthetic merge SHA. The
            # uploaded manifest binds the actual checked-out PR head SHA.
            if run.get("head_branch") == branch and run.get("event") == "pull_request":
                return run
        return None

    def artifact_manifest(self, run_id, patch_id, name=None):
        artifacts = self._get(f"actions/runs/{int(run_id)}/artifacts?per_page=100").get("artifacts", [])
        matches = [a for a in artifacts if a.get("name") == (name or f"terraform-patch-{patch_id}") and not a.get("expired")]
        if len(matches) != 1 or matches[0].get("size_in_bytes", 1_000_001) > 1_000_000:
            raise PatchError("MISSING_CHECKS", "검증 결과 artifact를 확인할 수 없습니다.", 409)
        req = Request(f"https://api.github.com/repos/{self.repository}/actions/artifacts/{matches[0]['id']}/zip",
                      headers={"Authorization": f"Bearer {os.getenv('GITHUB_TOKEN', '')}",
                               "Accept": "application/vnd.github+json"})
        try:
            try:
                build_opener(NoRedirect()).open(req, timeout=20)
                raise ValueError("redirect expected")
            except HTTPError as exc:
                if exc.code != 302:
                    raise
                location = exc.headers.get("Location", "")
            target = urlparse(location)
            if target.scheme != "https" or not (
                target.hostname and (target.hostname.endswith(".blob.core.windows.net")
                                     or target.hostname.endswith(".githubusercontent.com"))):
                raise ValueError("untrusted artifact host")
            # The signed download request contains no GitHub bearer credential.
            with build_opener(NoRedirect()).open(Request(location), timeout=20) as response:
                data = response.read(1_000_001)
            if len(data) > 1_000_000:
                raise ValueError("artifact too large")
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                if archive.namelist() != ["manifest.json"] or archive.getinfo("manifest.json").file_size > 100_000:
                    raise ValueError("unexpected artifact")
                return json.loads(archive.read("manifest.json"))
        except Exception:
            raise PatchError("MISSING_CHECKS", "검증 결과 artifact 다운로드에 실패했습니다.", 502) from None

    def snapshot(self, paths):
        sha = self.base_sha()
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise PatchError("INVALID_SOURCE", "GitHub commit 확인에 실패했습니다.", 502)
        files = []
        for path in sorted(set(paths)):
            safe_path(path)
            item = self._get(f"contents/{quote(path, safe='/')}?ref={sha}")
            if (not isinstance(item, dict) or item.get("type") != "file"
                    or item.get("encoding") != "base64" or item.get("path") != path
                    or item.get("size", 50_001) > 50_000 or item.get("target") or item.get("submodule_git_url")):
                raise PatchError("INVALID_SOURCE", "일반 .tf 파일만 조회할 수 있습니다(파일당 50KB 이하).")
            try:
                content = base64.b64decode(item["content"]).decode("utf-8")
            except (KeyError, ValueError, UnicodeError):
                raise PatchError("INVALID_SOURCE", "Terraform 원본 인코딩을 확인하세요.") from None
            if not content.strip() or len(content.encode()) > 50_000:
                raise PatchError("INVALID_SOURCE", "비어 있거나 너무 큰 Terraform 파일입니다.")
            raw_content = content.encode("utf-8")
            blob_sha = hashlib.sha1(f"blob {len(raw_content)}\0".encode() + raw_content).hexdigest()
            if item.get("sha") != blob_sha:
                raise PatchError("INVALID_SOURCE", "GitHub 파일 무결성 확인에 실패했습니다.")
            check_sensitive(content)
            files.append({"file_path": path, "original_content": content, "blob_sha": item["sha"]})
        return {"repository": self.repository, "ref": self.ref, "commit_sha": sha, "files": files}
