"""MySQL persistence with optimistic atomic transitions across workers."""
import json
from datetime import datetime, timedelta, timezone

from db import get_connection
from services.patch_security import PatchError, seal, unseal


class PatchRepository:
    def active_check_ids(self, limit=10):
        with get_connection() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT id FROM terraform_patches WHERE status = 'CHECKS_RUNNING' "
                           "ORDER BY updated_at, id LIMIT %s", (limit,))
            return [row["id"] for row in cursor.fetchall()]

    def pending_deploy_ids(self, limit=10):
        with get_connection() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT id FROM terraform_patches WHERE status = 'FINAL_APPROVED' "
                           "ORDER BY created_at, id LIMIT %s", (limit,))
            return [row["id"] for row in cursor.fetchall()]

    def active_deploy_ids(self, limit=10):
        with get_connection() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT id FROM terraform_patches WHERE status = 'DEPLOYING' "
                           "ORDER BY updated_at, id LIMIT %s", (limit,))
            return [row["id"] for row in cursor.fetchall()]

    def diagnosis(self, run_id):
        with get_connection() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT result FROM ai_diagnosis_runs WHERE id = %s AND status = 'done'", (run_id,))
            row = cursor.fetchone()
        if not row:
            raise PatchError("INVALID_DIAGNOSIS", "완료된 진단을 선택하세요.")
        return json.loads(row["result"]) if isinstance(row["result"], str) else row["result"]

    def store_rediagnosis(self, result, patch_id):
        with get_connection() as connection, connection.cursor() as cursor:
            cursor.execute("INSERT INTO ai_diagnosis_runs "
                           "(status, message, requested_by, result, started_at, finished_at) "
                           "VALUES ('done', NULL, %s, %s, UTC_TIMESTAMP(), UTC_TIMESTAMP())",
                           (f"patch:{patch_id}", json.dumps(result, ensure_ascii=False, default=str)))
            return cursor.lastrowid

    def insert(self, patch):
        encrypted = seal(patch["payload"])
        with get_connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO terraform_patches (id, diagnosis_run_id, status, requested_by, payload_encrypted, created_at, updated_at) "
                "VALUES (%s, %s, %s, %s, %s, UTC_TIMESTAMP(), UTC_TIMESTAMP())",
                (patch["id"], patch["diagnosis_run_id"], patch["status"], patch["requested_by"], encrypted))

    def get(self, patch_id):
        with get_connection() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT * FROM terraform_patches WHERE id = %s", (patch_id,))
            row = cursor.fetchone()
        if not row:
            raise PatchError("NOT_FOUND", "패치를 찾을 수 없습니다.", 404)
        row["payload"] = unseal(row.pop("payload_encrypted"))
        # Worker termination/restart must not leave an approvable or forever-running
        # patch. A later detail read records the interruption; retry requires a new ID.
        expired = {"FETCHING": "FAILED", "GENERATING": "FAILED",
                   "AI_REVIEWING": "AI_REVIEW_FAILED", "FINAL_REPORTING": "FINAL_REPORT_FAILED",
                   "REDIAGNOSING": "REDIAGNOSIS_FAILED"}
        if (row["status"] in expired
                and row["updated_at"] < datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=15)):
            previous = row["status"]
            row["status"] = expired[previous]
            row["payload"]["error"] = {"code": "WORKER_INTERRUPTED", "message": "작업이 중단되거나 시간 제한을 초과했습니다. 새 패치로 다시 요청하세요."}
            row["payload"]["audit"].append({"event": "FAILED", "actor": "system",
                "at": datetime.now(timezone.utc).isoformat(), "code": "WORKER_INTERRUPTED"})
            try:
                self.save(row, previous)
            except PatchError as exc:
                if exc.code != "STALE_PATCH":
                    raise
                return self.get(patch_id)
        return row

    def list(self, limit, offset):
        with get_connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT id, diagnosis_run_id, status, requested_by, created_at, updated_at, payload_encrypted "
                "FROM terraform_patches ORDER BY created_at DESC, id DESC LIMIT %s OFFSET %s", (limit, offset))
            rows = cursor.fetchall()
        for row in rows:
            payload = unseal(row.pop("payload_encrypted"))
            row["rule_ids"] = [r["rule_id"] for r in payload.get("findings", [])]
            row["first_approval"] = bool(payload.get("first_approval"))
            first_event = (payload.get("first_approval") or {}).get("event")
            row["first_decision"] = ("approve" if first_event == "FIRST_APPROVED"
                                     else "reject" if first_event == "REJECTED" else None)
            row["ai_verdict"] = (payload.get("ai_review") or {}).get("verdict")
            check_states = [item.get("status") for item in
                            (payload.get("checks") or {}).get("results", {}).values()]
            row["checks_status"] = (
                "FAIL" if row["status"] == "CHECKS_FAILED" or any(
                    value in ("FAIL", "ERROR") for value in check_states)
                else "PASS" if check_states and all(value == "PASS" for value in check_states)
                else "RUNNING" if row["status"] == "CHECKS_RUNNING" or "RUNNING" in check_states
                else "NOT_RUN")
            row["final_approval"] = bool(payload.get("final_approval"))
            final_event = (payload.get("final_approval") or {}).get("event")
            row["final_decision"] = ("approve" if final_event == "FINAL_APPROVED"
                                     else "reject" if final_event == "FINAL_REJECTED" else None)
            row["deployment_status"] = (payload.get("deployment") or {}).get("status")
        return rows

    def save(self, patch, expected_status):
        encrypted = seal(patch["payload"])
        with get_connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                "UPDATE terraform_patches SET status = %s, content_hash = %s, payload_encrypted = %s, "
                "revision = revision + 1, updated_at = UTC_TIMESTAMP() WHERE id = %s AND revision = %s AND status = %s",
                (patch["status"], patch.get("content_hash"), encrypted, patch["id"], patch["revision"], expected_status))
            if cursor.rowcount != 1:
                raise PatchError("STALE_PATCH", "패치 상태가 변경되었습니다. 새로 조회한 뒤 검토하세요.", 409)
        patch["revision"] += 1

    def acquire_deploy_lock(self, patch_id):
        with get_connection() as connection, connection.cursor() as cursor:
            cursor.execute("UPDATE terraform_patch_deploy_lock SET patch_id = %s, acquired_at = UTC_TIMESTAMP() "
                           "WHERE id = 1 AND patch_id IS NULL", (patch_id,))
            if cursor.rowcount != 1:
                raise PatchError("DEPLOY_BUSY", "다른 Terraform 패치가 배포 중입니다.", 409)

    def release_deploy_lock(self, patch_id):
        with get_connection() as connection, connection.cursor() as cursor:
            cursor.execute("UPDATE terraform_patch_deploy_lock SET patch_id = NULL, acquired_at = NULL "
                           "WHERE id = 1 AND patch_id = %s", (patch_id,))
