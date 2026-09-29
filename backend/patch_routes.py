"""Authenticated patch API with exact state/role gates."""
import io
import os
from functools import wraps

from flask import Response, jsonify, request, send_file, session
from services.patch_security import PatchError
from services.patch_workflow import PatchWorkflow, approval_digest, human_review_digest
from services.patch_pdf import render_pdf


def register_patch_routes(app, role_required):
    service = PatchWorkflow()
    app.extensions["terraform_patches"] = service
    admin = role_required(os.getenv("ADMIN_ROLE", "관리자"))
    approver = role_required(os.getenv("APPROVER_ROLE", "승인자"))
    reader = role_required(os.getenv("ADMIN_ROLE", "관리자"), os.getenv("APPROVER_ROLE", "승인자"))

    def guarded(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            try:
                value = view(*args, **kwargs)
                response = value if isinstance(value, Response) else jsonify(value)
            except PatchError as exc:
                response = jsonify(error=exc.code, message=exc.message)
                response.status_code = exc.status
            except Exception:
                # Never expose provider/DB errors containing credentials or source.
                response = jsonify(error="PATCH_UNAVAILABLE", message="패치 처리에 실패했습니다. DB migration 및 서버 설정을 확인하세요.")
                response.status_code = 503
            response.headers["Cache-Control"] = "no-store"
            return response
        return wrapper

    def body():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise PatchError("INVALID_REQUEST", "JSON 객체가 필요합니다.")
        return data

    def actor():
        username = session.get("username")
        if not isinstance(username, str) or not username:
            raise PatchError("UNAUTHORIZED", "다시 로그인하세요.", 401)
        return username

    @app.get("/api/ai-actions/patches")
    @reader
    @guarded
    def list_patches():
        try:
            offset = max(0, int(request.args.get("offset", "0")))
        except ValueError:
            raise PatchError("INVALID_OFFSET", "올바른 페이지를 지정하세요.") from None
        return {"patches": service.repo.list(50, offset), "offset": offset,
                "can_create": session.get("role") == os.getenv("ADMIN_ROLE", "관리자"),
                "can_approve": session.get("role") == os.getenv("APPROVER_ROLE", "승인자")}

    @app.get("/api/ai-actions/patches/<uuid:patch_id>")
    @reader
    @guarded
    def get_patch(patch_id):
        row = service.repo.get(str(patch_id))
        if row["status"] == "AI_NEEDS_HUMAN_REVIEW":
            row["review_hash"] = human_review_digest(row)
        if row["status"] in ("AWAITING_FINAL_APPROVAL", "FINAL_APPROVED"):
            row["approval_hash"] = approval_digest(row)
        return row

    @app.post("/api/ai-actions/mapping-preview")
    @admin
    @guarded
    def preview_patch_mapping():
        return service.preview_mapping(body())

    @app.post("/api/ai-actions/patches")
    @admin
    @guarded
    def create_patch():
        return service.create(body(), actor())

    @app.post("/api/ai-actions/terraform-fix")
    @admin
    @guarded
    def ai_action_terraform_fix():
        data = body()
        patch_id = data.get("patch_id")
        if not isinstance(patch_id, str) or len(patch_id) != 36:
            raise PatchError("PATCH_REQUIRED", "GitHub 원본을 조회하여 생성한 patch_id가 필요합니다.")
        return service.generate_proposal(patch_id, actor())

    @app.post("/api/ai-actions/patches/<uuid:patch_id>/first-approval")
    @admin
    @guarded
    def approve_patch(patch_id):
        return service.decide(str(patch_id), body(), actor())

    @app.post("/api/ai-actions/patches/<uuid:patch_id>/ai-review")
    @admin
    @guarded
    def review_patch(patch_id):
        return service.start_review(str(patch_id), actor())

    @app.post("/api/ai-actions/patches/<uuid:patch_id>/human-review")
    @admin
    @guarded
    def decide_human_review(patch_id):
        return service.decide_human_review(str(patch_id), body(), actor())

    @app.post("/api/ai-actions/patches/<uuid:patch_id>/publish")
    @admin
    @guarded
    def publish_patch(patch_id):
        return service.publish(str(patch_id), actor())

    @app.post("/api/ai-actions/patches/<uuid:patch_id>/checks/refresh")
    @reader
    @guarded
    def refresh_patch_checks(patch_id):
        return service.refresh_checks(str(patch_id), actor())

    @app.post("/api/ai-actions/patches/<uuid:patch_id>/final-approval")
    @approver
    @guarded
    def final_approval(patch_id):
        return service.decide_final(str(patch_id), body(), actor())

    @app.post("/api/ai-actions/patches/<uuid:patch_id>/deployment/refresh")
    @reader
    @guarded
    def refresh_patch_deployment(patch_id):
        return service.refresh_deploy(str(patch_id), actor())

    @app.get("/api/ai-actions/patches/<uuid:patch_id>/download/<kind>")
    @reader
    @guarded
    def download_patch(patch_id, kind):
        row = service.repo.get(str(patch_id))
        if kind == "patch":
            diffs = [f.get("diff") or "" for f in row["payload"].get("files", [])]
            if not any(diffs):
                raise PatchError("PATCH_UNAVAILABLE", "저장된 Diff가 없습니다.", 404)
            return send_file(io.BytesIO("\n".join(diffs).encode()),
                mimetype="text/x-diff", as_attachment=True, download_name=f"{patch_id}.patch")
        if kind not in ("first", "final", "results"):
            raise PatchError("INVALID_REPORT", "지원하지 않는 보고서입니다.", 404)
        pdf = render_pdf(row, kind)
        return send_file(io.BytesIO(pdf), mimetype="application/pdf", as_attachment=True,
                         download_name=f"{patch_id}-{kind}.pdf")
