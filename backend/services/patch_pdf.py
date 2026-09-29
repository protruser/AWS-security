"""Readable, versioned patch PDFs from encrypted history records."""
import io
import textwrap
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle

from services.patch_security import PatchError
from services.patch_reports import change_details_from_diff


def render_pdf(patch, kind):
    payload = patch["payload"]
    if kind == "first" and not payload.get("report"):
        raise PatchError("REPORT_UNAVAILABLE", "First report is unavailable.", 404)
    if kind == "final" and not payload.get("final_report"):
        raise PatchError("REPORT_UNAVAILABLE", "Final report is unavailable.", 404)
    if kind == "results" and not (payload.get("deployment") or payload.get("rediagnosis")):
        raise PatchError("REPORT_UNAVAILABLE", "Deployment results are unavailable.", 404)
    if kind not in ("first", "final", "results"):
        raise PatchError("INVALID_REPORT", "Unsupported report.", 404)

    from app import _PDF_FONT, _PDF_FONT_BOLD
    title = ParagraphStyle("patch-title", fontName=_PDF_FONT_BOLD, fontSize=16, leading=21, spaceAfter=5*mm)
    heading = ParagraphStyle("patch-heading", fontName=_PDF_FONT_BOLD, fontSize=11, leading=15,
                             spaceBefore=6*mm, spaceAfter=2*mm)
    body = ParagraphStyle("patch-body", fontName=_PDF_FONT, fontSize=8.5, leading=12, spaceAfter=2*mm)
    code = ParagraphStyle("patch-code", fontName=_PDF_FONT, fontSize=7, leading=9)
    small = ParagraphStyle("patch-small", fontName=_PDF_FONT, fontSize=7.5, leading=10)
    story = []

    def para(value):
        story.append(Paragraph(escape(str(value or "확인된 내용 없음")).replace("\n", "<br/>"), body))

    def section(label):
        story.append(Paragraph(escape(label), heading))

    def bullets(values):
        if not values:
            para("기록 없음")
        for value in values or []:
            para("• " + str(value))

    def code_block(value):
        for line in str(value or "").splitlines() or [""]:
            for part in textwrap.wrap(line, 95, replace_whitespace=False,
                                      drop_whitespace=False, break_long_words=True) or [""]:
                story.append(Preformatted(part or " ", code))
        story.append(Spacer(1, 2*mm))

    def rows_table(rows):
        table = Table([[Paragraph(escape(str(cell)), small) for cell in row] for row in rows],
                      hAlign="LEFT", repeatRows=1, colWidths=[43*mm, 129*mm])
        table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EAF0F8")),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#D0D5DD")),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(table)

    labels = {"first": "1차 AI 변경 보고서", "final": "AI 최종 변경 보고서",
              "results": "배포 및 재진단 결과"}
    story.append(Paragraph(labels[kind], title))
    rows_table([["항목", "값"], ["패치 ID", patch["id"]],
                ["상태", patch.get("status", "")],
                ["원본", f"{(payload.get('source') or {}).get('repository', '')} "
                 f"{(payload.get('source') or {}).get('ref', '')} "
                 f"{(payload.get('source') or {}).get('commit_sha', '')}"]])

    if kind in ("first", "final"):
        section("선택한 FAIL 항목")
        for finding in payload.get("findings", []):
            para(f"{finding.get('rule_id')}: {finding.get('reason', '')} "
                 f"(AWS 리소스: {', '.join(finding.get('resource_ids') or [])})")
        for file in payload.get("files", []):
            section(f"Terraform 파일: {file.get('file_path', '')}")
            para("기존 설정")
            code_block(file.get("original_content"))
            para("수정 설정")
            code_block(file.get("proposed_content"))
            para("실제 Diff")
            code_block(file.get("diff"))
        report = payload.get("report") or {}
        section("1차 AI 변경 평가")
        para(report.get("summary"))
        for change in report.get("changes", []):
            para(f"{change.get('file_path', '')}: {change.get('explanation', '')}")
        section("예상 영향 및 서비스 중단·리소스 교체 가능성")
        para(f"예상 영향: {report.get('impact', '미확인')}")
        para(f"서비스 중단: {report.get('service_disruption', '미확인')}")
        para(f"리소스 교체: {report.get('resource_replacement', '미확인')}")
        bullets(report.get("risks"))
        bullets(report.get("checks"))

    if kind == "final":
        final = payload["final_report"]
        assessment = final.get("ai_assessment") or {}
        first = payload.get("report") or {}
        section("한눈에 보기")
        para(final.get("report_notice") or "배포 전 예상입니다. 실제 변경과 보안 문제 해결 여부는 배포 후 재진단으로 확인합니다.")
        para(assessment.get("assessment"))
        section("무엇이 바뀌나요?")
        para(assessment.get("change_explanation") or first.get("summary"))
        change_details = final.get("change_details")
        if not isinstance(change_details, list):
            change_details = change_details_from_diff(payload.get("files"), first)
        for file_detail in change_details:
            section(f"변경 파일: {file_detail.get('file_path', '')}")
            for explanation in file_detail.get("explanations") or []:
                para(explanation.get("explanation"))
                para(f"보고서 근거: {explanation.get('evidence', '')}")
            for index, hunk in enumerate(file_detail.get("hunks") or [], start=1):
                para(f"변경 구간 {index}")
                before = hunk.get("before_lines") or []
                after = hunk.get("after_lines") or []
                para("변경 전" if before else "변경 전: 해당 설정 없음 (새로 추가)")
                if before:
                    code_block("\n".join(before))
                para("변경 후" if after else "변경 후: 해당 설정 없음 (삭제)")
                if after:
                    code_block("\n".join(after))
        counts = ((payload.get("checks") or {}).get("plan_summary") or {}).get("counts") or {}
        para(f"배포 계획: 새로 생성 {counts.get('create', '미확인')}개 · 설정 변경 {counts.get('update', '미확인')}개 · "
             f"삭제 {counts.get('delete', '미확인')}개 · 교체 {counts.get('replace', '미확인')}개")
        section("이용자와 서비스에 미칠 영향")
        para(assessment.get("user_impact") or first.get("impact"))
        para(f"서비스 중단 가능성: {assessment.get('service_disruption') or first.get('service_disruption') or '확인 필요'}")
        para(f"리소스 교체 가능성: {assessment.get('resource_replacement') or first.get('resource_replacement') or '확인 필요'}")
        section("남은 위험")
        bullets(assessment.get("risks"))
        section("최종 승인 전에 확인할 것")
        bullets(assessment.get("decision_points") or first.get("checks"))
        section("배포 후 확인할 것")
        bullets(assessment.get("post_deploy_checks"))
        review = payload.get("ai_review") or {}
        section("2차 AI 검증")
        para(f"판정: {review.get('verdict', '미확인')} · {review.get('summary', '')}")
        bullets(review.get("concerns"))
        human_review = payload.get("human_review_approval") or {}
        if human_review.get("event") == "HUMAN_REVIEW_APPROVED":
            para(f"사람 검토 승인: {human_review.get('actor', '')} · {human_review.get('note', '')}")
        checks = payload.get("checks") or {}
        section("GitHub 자동 검사")
        for name, result in (checks.get("results") or {}).items():
            para(f"{name}: {result.get('status', 'NOT_RUN')} · {result.get('url') or checks.get('url') or '실행 링크 없음'}")
        section("검증 및 재검증 이력")
        for event in payload.get("audit", []):
            if event.get("event") in ("AI_REJECTED", "AI_APPROVED", "AI_NEEDS_HUMAN_REVIEW",
                                      "HUMAN_REVIEW_APPROVED", "HUMAN_REVIEW_REJECTED",
                                      "CHECKS_FAILED", "FINAL_REPORTING", "PR_CREATED"):
                para(f"{event.get('at', '')} · {event.get('event', '')}")
        section("Terraform Plan")
        counts = (checks.get("plan_summary") or {}).get("counts") or {}
        resources = (checks.get("plan_summary") or {}).get("labels") or (
            (checks.get("plan_summary") or {}).get("resources") or {})
        for key in ("create", "update", "delete", "replace"):
            para(f"{key}: {counts.get(key, '미확인')} · {', '.join(resources.get(key, [])) or '해당 없음'}")
        section("PR 및 검사 실행 링크")
        para((payload.get("github_pr") or {}).get("url"))
        para(checks.get("url"))

    if kind == "results":
        section("배포 작업")
        deployment = payload.get("deployment") or {}
        for label, key in (("상태", "status"), ("실행 링크", "url"),
                           ("적용 commit", "merge_sha"), ("오류", "error")):
            para(f"{label}: {deployment.get(key, '기록 없음')}")
        for stage, status in (deployment.get("stages") or {}).items():
            para(f"{stage}: {status}")
        section("재진단")
        diagnosis = payload.get("rediagnosis") or {}
        for result in diagnosis.get("results", []):
            para(f"{result.get('rule_id')}: {result.get('before')} → {result.get('after')}")
        if diagnosis.get("error"):
            para(diagnosis["error"])

    output = io.BytesIO()
    SimpleDocTemplate(output, pagesize=A4, leftMargin=18*mm, rightMargin=18*mm,
                      topMargin=18*mm, bottomMargin=18*mm).build(story)
    return output.getvalue()
