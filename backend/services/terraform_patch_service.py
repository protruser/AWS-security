"""Phase 1 only: immutable proposals and explicit human decisions. No deployment."""
import hashlib
import copy
import json
import logging
import os
import re
import threading
import uuid
from datetime import datetime, timezone

from services.github_terraform_source import GitHubSource
from services.patch_repository import PatchRepository
from services.patch_security import PatchError, check_sensitive, cipher, safe_path
from services.terraform_mapping import NOT_TERRAFORM_RULES, preview as mapping_preview
from services.terraform_remediation_service import (
    _unified_diff, generate_change_report, generate_terraform_fix, validate_change_report,
)


def digest(payload):
    # Bind approval to exact findings, GitHub commit, source, proposal and report.
    value = {key: payload.get(key) for key in ("findings", "source", "files", "report", "mapping")}
    for key in ("original_findings", "target_resource_ids"):
        if key in payload:
            value[key] = payload[key]
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def scope_finding(finding, selected_ids):
    """Keep the original diagnosis while defining exactly what one patch claims to fix."""
    scoped = copy.deepcopy(finding)
    available = finding.get("resource_ids") or []
    if not isinstance(available, list) or not all(isinstance(item, str) and item for item in available):
        raise PatchError("INVALID_RESOURCE_SCOPE", "진단 리소스 ID 형식이 올바르지 않습니다.")
    if not available:
        if selected_ids:
            raise PatchError("INVALID_RESOURCE_SCOPE", "이 진단에는 선택 가능한 리소스 ID가 없습니다.")
        return scoped
    if (not isinstance(selected_ids, list) or not selected_ids
            or not all(isinstance(item, str) and item for item in selected_ids)
            or len(set(selected_ids)) != len(selected_ids)
            or not set(selected_ids).issubset(set(available))):
        raise PatchError("INVALID_RESOURCE_SCOPE", "진단에 실제 존재하는 리소스 ID를 하나 이상 선택하세요.")
    deferred = [item for item in available if item not in selected_ids]
    scoped["remediation_scope"] = {
        "selected_resource_ids": selected_ids,
        "deferred_resource_ids": deferred,
        "rule_result_may_remain_fail_until_deferred_resources_are_fixed": bool(deferred),
    }
    if deferred:
        evidence = scoped.get("evidence") or []
        if not isinstance(evidence, list):
            raise PatchError("INVALID_RESOURCE_SCOPE", "진단 근거 형식이 올바르지 않습니다.")
        selected_evidence = [item for item in evidence if isinstance(item, dict)
                             and item.get("resource") in selected_ids]
        if {item["resource"] for item in selected_evidence} != set(selected_ids):
            raise PatchError("RESOURCE_EVIDENCE_MISSING", "선택한 리소스와 연결된 실제 진단 근거가 없습니다.")
        scoped["resource_ids"] = selected_ids
        scoped["evidence"] = selected_evidence
    return scoped


def audit(payload, event, actor, **details):
    payload["audit"].append({"event": event, "actor": actor,
                             "at": datetime.now(timezone.utc).isoformat(), **details})


def dispatch(work):
    # Like the existing diagnosis worker: DB is the source of truth across workers.
    def guarded_work():
        try:
            work()
        except Exception:
            logging.getLogger(__name__).warning("Patch worker interrupted; detail read will expire stale work.")
    threading.Thread(target=guarded_work, daemon=True).start()


class TerraformPatches:
    def __init__(self, repository=None, source_factory=GitHubSource,
                 generate=generate_terraform_fix, report=generate_change_report, submit=dispatch):
        self.repo = repository or PatchRepository()
        self.source_factory, self.generate, self.report = source_factory, generate, report
        self.submit = submit

    def preview_mapping(self, body):
        run_id, rule_ids = body.get("diagnosis_run_id"), body.get("rule_ids")
        if type(run_id) is not int or not isinstance(rule_ids, list) or not 1 <= len(rule_ids) <= 33 \
                or len(set(rule_ids)) != len(rule_ids) or not all(isinstance(value, str) for value in rule_ids):
            raise PatchError("INVALID_SELECTION", "Select FAIL rule IDs from a completed diagnosis.")
        diagnosis = self.repo.diagnosis(run_id)
        failures = {item["rule_id"]: item for item in diagnosis["results"] if item.get("status") == "FAIL"}
        if not set(rule_ids).issubset(failures):
            raise PatchError("NOT_FAIL", "Only FAIL items can be mapped.")
        return mapping_preview(self.source_factory(), [failures[rule] for rule in rule_ids])

    def create(self, body, actor):
        cipher()  # Fail before reading any source if storage is not configured.
        run_id, mapping = body.get("diagnosis_run_id"), body.get("mapping")
        source_commit_sha = body.get("source_commit_sha")
        if type(run_id) is not int or run_id < 1 or not isinstance(mapping, dict) or not 1 <= len(mapping) <= 33:
            raise PatchError("INVALID_SELECTION", "완료된 진단과 FAIL 항목별 Terraform 파일 경로를 선택하세요.")
        blocked = sorted(rule for rule in mapping if rule in NOT_TERRAFORM_RULES)
        if blocked:
            raise PatchError("NOT_TERRAFORM_FIXABLE",
                             f"Terraform으로 조치할 수 없는 항목입니다: {', '.join(blocked)}. 선택에서 제외하세요.")
        paths = []
        for rule, selected_paths in mapping.items():
            if not isinstance(rule, str) or not isinstance(selected_paths, list) or not 1 <= len(selected_paths) <= 5:
                raise PatchError("INVALID_SELECTION", "각 FAIL 항목에 관련 파일을 지정하세요.")
            for path in selected_paths:
                safe_path(path)
                if not path.startswith("modules/"):
                    raise PatchError("INVALID_FILE_PATH", "운영 Terraform 저장소의 modules/ 경로만 수정할 수 있습니다.")
                paths.append(path)
        if len(set(paths)) > 5:
            raise PatchError("TOO_MANY_FILES", "한 패치는 최대 5개 파일까지 처리합니다.")
        diagnosis = self.repo.diagnosis(run_id)
        failures = {r["rule_id"]: r for r in diagnosis["results"] if r.get("status") == "FAIL"}
        if not set(mapping).issubset(failures):
            raise PatchError("NOT_FAIL", "저장된 진단 결과의 FAIL 항목만 선택할 수 있습니다.")
        source = self.source_factory()
        current_sha, valid_paths = source.terraform_paths()
        if source_commit_sha != current_sha:
            raise PatchError("BASE_CHANGED", "The gyu branch changed after mapping. Preview again.", 409)
        if not set(paths).issubset(valid_paths):
            raise PatchError("INVALID_FILE_PATH", "A selected file is absent from the gyu Terraform modules.")
        original_findings = [failures[rule] for rule in sorted(mapping)]
        requested_targets = body.get("target_resource_ids") or {}
        if not isinstance(requested_targets, dict) or not set(requested_targets).issubset(set(mapping)):
            raise PatchError("INVALID_RESOURCE_SCOPE", "선택한 규칙의 리소스 ID만 지정하세요.")
        constraints = body.get("remediation_constraints") or {}
        if (not isinstance(constraints, dict) or not set(constraints).issubset(set(mapping))
                or any(not isinstance(value, str) or len(value) > 2000 for value in constraints.values())):
            raise PatchError("INVALID_CONSTRAINTS", "선택한 규칙의 운영 통신 요건을 2,000자 이내로 입력하세요.")
        for constraint in constraints.values():
            check_sensitive(constraint)
        target_resource_ids = {
            rule: requested_targets.get(rule, failures[rule].get("resource_ids") or [])
            for rule in sorted(mapping)
        }
        findings = [scope_finding(failures[rule], target_resource_ids[rule]) for rule in sorted(mapping)]
        for finding in findings:
            constraint = constraints.get(finding["rule_id"], "").strip()
            if constraint:
                finding["remediation_constraints"] = constraint
        check_sensitive(json.dumps(original_findings, ensure_ascii=False))
        payload = {"findings": findings, "original_findings": original_findings,
                   "target_resource_ids": target_resource_ids,
                   "mapping": mapping, "source_commit_sha": current_sha,
                   "audit": [], "files": [], "source": None,
                   "report": None, "first_approval": None, "ai_review": None, "final_approval": None,
                   "github_pr": None, "checks": None, "deployment": None, "rediagnosis": None}
        audit(payload, "CREATED", actor)
        patch = {"id": str(uuid.uuid4()), "diagnosis_run_id": run_id, "requested_by": actor,
                 "status": "FETCHING", "revision": 1, "payload": payload}
        self.repo.insert(patch)
        self.submit(lambda: self._fetch_source(patch["id"], paths, actor))
        return self.repo.get(patch["id"])

    def _fetch_source(self, patch_id, paths, actor):
        patch = self.repo.get(patch_id)
        payload = patch["payload"]
        try:
            source = self.source_factory().snapshot(paths)
            if source["commit_sha"] != payload["source_commit_sha"]:
                raise PatchError("BASE_CHANGED", "The gyu branch changed after mapping.", 409)
            payload["source"] = {key: value for key, value in source.items() if key != "files"}
            payload["files"] = source["files"]
            patch["status"] = "SOURCE_READY"
            audit(payload, "SOURCE_READY", actor)
        except Exception as exc:
            self._failure(patch, exc, actor)
        self.repo.save(patch, "FETCHING")

    def _failure(self, patch, exc, actor):
        # Provider messages may contain prompts, tokens, or raw source. Never log them.
        code = exc.code if isinstance(exc, PatchError) else "GENERATION_FAILED"
        patch["status"] = "FAILED"
        patch["payload"]["error"] = {"code": code, "message": (
            exc.message if isinstance(exc, PatchError) else "AI 수정안 또는 변경 보고서 생성에 실패했습니다.")}
        audit(patch["payload"], "FAILED", actor, code=code)

    def generate_proposal(self, patch_id, actor):
        patch = self.repo.get(patch_id)
        if patch["status"] != "SOURCE_READY":
            raise PatchError("INVALID_STATE", "원본 조회가 완료된 새 패치에서만 생성할 수 있습니다.", 409)
        if not os.getenv("OPENAI_API_KEY", "").strip():
            raise PatchError("OPENAI_API_KEY_MISSING", "OPENAI_API_KEY 설정이 필요합니다.", 503)
        patch["status"] = "GENERATING"
        audit(patch["payload"], "GENERATION_STARTED", actor)
        self.repo.save(patch, "SOURCE_READY")  # Only one worker may generate.
        self.submit(lambda: self._build_proposal(patch, actor))
        return self.repo.get(patch_id)

    def _build_proposal(self, patch, actor):
        payload = patch["payload"]
        try:
            for file in payload["files"]:
                context = {"findings": payload["findings"], "target_rule_ids": [
                    rule for rule, paths in payload["mapping"].items() if file["file_path"] in paths],
                    "related_files": [{"file_path": f["file_path"],
                                       "content": f.get("proposed_content", f["original_content"])}
                                      for f in payload["files"] if f is not file]}
                # One integrated generation for each unique file, never competing per-rule diffs.
                fix = self.generate(finding=context, file_path=file["file_path"], file_content=file["original_content"])
                proposed = fix.get("proposed_content")
                if not isinstance(proposed, str) or not proposed.strip() or len(proposed.encode()) > 50_000 or "```" in proposed:
                    raise PatchError("INVALID_PROPOSAL", "수정안이 비어 있거나 파일 형식/크기 제한을 위반했습니다.")
                # The model response must preserve the file boundary. A trailing
                # newline-only edit is not a security remediation.
                if proposed.strip("\r\n") == file["original_content"].strip("\r\n"):
                    proposed = file["original_content"]
                if any(rule in {"3.1", "3.2", "3.3"} for rule in context["target_rule_ids"]):
                    for direction in ("egress", "ingress"):
                        empty_rule = rf"(?m)^\s*{direction}\s*=\s*\[\s*\]\s*$"
                        if (re.search(empty_rule, proposed)
                                and not re.search(empty_rule, file["original_content"])):
                            raise PatchError("UNSAFE_PROPOSAL",
                                             f"{direction} 전체 삭제는 포트 제한 조치가 아닙니다. 필요한 통신 범위를 확인해 새 수정안을 요청하세요.")
                check_sensitive(proposed)
                file["proposed_content"] = proposed
                file["diff"] = _unified_diff(file["original_content"], proposed, file["file_path"])
            if not any(file["diff"] for file in payload["files"]):
                raise PatchError("NO_CHANGES", "생성된 코드에 변경사항이 없어 승인할 수 없습니다.")
            report = self.report(findings=payload["findings"], files=payload["files"])
            validate_change_report(report, payload["files"])
            check_sensitive(json.dumps(report, ensure_ascii=False))
            payload["report"] = report
            patch["content_hash"] = digest(payload)
            patch["status"] = "AWAITING_FIRST_APPROVAL"
            audit(payload, "PROPOSAL_READY", actor, content_hash=patch["content_hash"])
        except Exception as exc:
            self._failure(patch, exc, actor)
        self.repo.save(patch, "GENERATING")

    def decide(self, patch_id, body, actor):
        patch = self.repo.get(patch_id)
        if patch["requested_by"] == actor:
            raise PatchError("SELF_APPROVAL", "요청자 본인은 승인·반려할 수 없습니다.", 403)
        if patch["status"] != "AWAITING_FIRST_APPROVAL":
            raise PatchError("INVALID_STATE", "1차 승인 대기 패치만 처리할 수 있습니다.", 409)
        if body.get("content_hash") != patch["content_hash"] or digest(patch["payload"]) != patch["content_hash"]:
            raise PatchError("STALE_PATCH", "코드 또는 보고서가 변경되었습니다. 새 패치 생성 및 재승인이 필요합니다.", 409)
        decision, note = body.get("decision"), body.get("note", "")
        if decision not in ("approve", "reject") or not isinstance(note, str) or len(note) > 2000:
            raise PatchError("INVALID_DECISION", "올바른 승인·반려 결정과 2,000자 이하 의견을 입력하세요.")
        if body.get("reviewed") is not True or (decision == "reject" and not note.strip()):
            raise PatchError("REVIEW_REQUIRED", "코드·Diff·보고서 확인이 필요하며 반려 시 사유를 입력해야 합니다.")
        check_sensitive(note)
        patch["status"] = "FIRST_APPROVED" if decision == "approve" else "REJECTED"
        audit(patch["payload"], patch["status"], actor, note=note, content_hash=patch["content_hash"])
        patch["payload"]["first_approval"] = patch["payload"]["audit"][-1]
        self.repo.save(patch, "AWAITING_FIRST_APPROVAL")
        return self.repo.get(patch_id)
