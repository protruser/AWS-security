"""AI 기반 보안 자동 조치 파이프라인의 4~7단계.

    4) Terraform 코드 분석      -> 호출하는 쪽(app.py)이 대상 파일을 골라 넘김
    5) AI Terraform 수정        -> generate_terraform_fix()
    6) GitHub 검증(fmt/validate/plan/lint) -> 이 모듈 밖(terraform CLI, 별도 단계)
    7) 2차 AI 재검증            -> review_terraform_fix()

이 모듈은 어떤 AWS 리소스도 직접 만들거나 바꾸지 않는다. 실제로 파일을
쓰거나 커밋/PR을 만드는 것도 하지 않는다 - 여기서는 "무엇을 어떻게
고치면 되는지"와 "그 수정이 안전한지 2차로 검토한 의견"만 만든다.
최종적으로 반영할지는 사람(승인자)의 몫이다.

두 단계를 서로 다른 모델 제공자(1차: OpenAI, 2차: Anthropic)로 나눈 건,
같은 모델이 자기가 만든 실수를 스스로 다시 통과시켜버릴 가능성을
줄이기 위해서다 - 독립적인 두 번째 시선이 목적이다.
"""

from __future__ import annotations

import difflib
import json
import os
from typing import Any, Dict, Optional

from anthropic import Anthropic
from openai import OpenAI


class RemediationError(RuntimeError):
    """Terraform 수정안 생성/재검증을 신뢰할 수 없을 때 발생시킨다."""


def _unified_diff(original_content: str, proposed_content: str, path: str) -> str:
    return "".join(
        difflib.unified_diff(
            original_content.splitlines(keepends=True),
            proposed_content.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        )
    )


def generate_terraform_fix(
    *,
    finding: Dict[str, Any],
    file_path: str,
    file_content: str,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
) -> Dict[str, str]:
    """진단 결과 하나(finding)와 그 원인이 있는 .tf 파일 하나를 받아,
    AI가 제안하는 수정된 파일 전체 내용을 돌려준다.

    파일 하나 단위로 동작하는 건 의도적인 제약이다 - 어떤 파일을 고쳐야
    하는지 자동으로 찾아내는 건 이 함수의 책임이 아니다(오탐 위험이 커서
    아직은 사람이 지정한다). "최소 변경, 기존 리소스 재사용, 무관한
    리소스는 건드리지 않는다"는 원칙은 시스템 프롬프트로 강제한다.
    """
    resolved_key = (api_key or os.getenv("OPENAI_API_KEY", "")).strip()
    if not resolved_key:
        raise RemediationError("OPENAI_API_KEY가 설정되어 있지 않습니다.")

    resolved_model = model or os.getenv("OPENAI_MODEL", "gpt-5.6-sol")
    client = OpenAI(api_key=resolved_key)

    try:
        response = client.responses.create(
            model=resolved_model,
            instructions=(
                "당신은 Terraform 코드를 수정하는 AI입니다. 주어진 .tf 파일 내용과 "
                "보안 진단 결과를 보고, 그 문제를 해결하기 위해 정확히 무엇을 바꿔야 "
                "하는지 판단하세요.\n"
                "요구사항:\n"
                "1) 문제 해결에 필요한 최소한의 변경만 하세요. 관련 없는 리소스는 "
                "절대 건드리지 마세요.\n"
                "2) 이미 존재하는 리소스(예: KMS 키, IAM 정책)를 활용할 수 있으면 "
                "새로 만들지 말고 그걸 참조하세요.\n"
                "3) 확신이 서지 않거나 파일 안의 정보만으로 안전하게 고칠 수 없다면 "
                "코드를 추측해서 만들어내지 말고 원본을 그대로 반환하세요.\n"
                "4) 최종 응답은 반드시 수정된 파일 전체 내용만 반환하세요 "
                "(설명 텍스트, 코드 블록 마크다운 없이 파일 내용 그 자체만)."
            ),
            input=[
                {
                    "role": "user",
                    "content": (
                        f"보안 진단 결과:\n{json.dumps(finding, ensure_ascii=False)}\n\n"
                        f"현재 파일({file_path}):\n{file_content}"
                    ),
                }
            ],
            store=False,
            max_output_tokens=4000,
        )
    except Exception as exc:
        raise RemediationError(f"OpenAI Terraform 수정안 생성 실패: {exc}") from exc

    proposed = (getattr(response, "output_text", None) or "").strip()
    if not proposed:
        raise RemediationError("OpenAI가 빈 Terraform 수정안을 반환했습니다.")

    return {
        "file_path": file_path,
        "original_content": file_content,
        "proposed_content": proposed,
        "diff": _unified_diff(file_content, proposed, file_path),
        "changed": proposed.strip() != file_content.strip(),
    }


REVIEW_TEXT_SCHEMA = {
    "verdict": "APPROVE | REJECT | NEEDS_HUMAN_REVIEW 중 하나",
    "summary": "한두 문장 요약",
    "concerns": "우려 사항 목록(문자열 배열, 없으면 빈 배열)",
}


def review_terraform_fix(
    *,
    finding: Dict[str, Any],
    diff_text: str,
    plan_output: Optional[str] = None,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
) -> Dict[str, Any]:
    """1차 AI(OpenAI)가 만든 Terraform diff를, 다른 모델(Anthropic Claude)로
    다시 검토시킨다. terraform plan 결과가 있으면 함께 준다 - "코드만 봤을 때
    그럴듯한 것"과 "실제로 적용됐을 때 무슨 일이 일어나는지"는 다르기
    때문에, plan의 add/change/destroy 요약이 있으면 판단 근거가 된다.

    반환값의 verdict:
      - APPROVE: 안전하고 진단 결과를 정확히 해결함
      - REJECT: 위험하거나(리소스 삭제/교체, 무관한 변경 등) 문제를 해결하지 못함
      - NEEDS_HUMAN_REVIEW: 코드만으로 확신할 수 없는 애매한 경우
    """
    resolved_key = (api_key or os.getenv("ANTHROPIC_API_KEY", "")).strip()
    if not resolved_key:
        raise RemediationError("ANTHROPIC_API_KEY가 설정되어 있지 않습니다.")

    resolved_model = model or os.getenv("ANTHROPIC_MODEL", "claude-opus-5")
    client = Anthropic(api_key=resolved_key)

    plan_section = f"\n\nterraform plan 결과:\n{plan_output}" if plan_output else ""

    prompt = (
        "다음은 보안 진단 결과와, 그걸 해결하겠다며 다른 AI가 제안한 Terraform "
        "diff입니다. 이 변경이 실제로 안전하고 정확한지 독립적으로 재검토하세요.\n\n"
        f"보안 진단 결과:\n{json.dumps(finding, ensure_ascii=False)}\n\n"
        f"제안된 diff:\n{diff_text}"
        f"{plan_section}\n\n"
        "다음 JSON 스키마로만 응답하세요(다른 텍스트 없이 JSON 하나만):\n"
        f"{json.dumps(REVIEW_TEXT_SCHEMA, ensure_ascii=False)}\n\n"
        "판단 기준: 진단 결과의 문제를 실제로 해결하는지, 변경 범위가 필요한 "
        "만큼으로 최소화되어 있는지(무관한 리소스 변경 없음), 리소스 삭제나 "
        "재생성처럼 위험한 부작용이 없는지, terraform plan 결과가 있다면 "
        "diff와 실제 실행 계획이 서로 모순되지 않는지를 확인하세요."
    )

    try:
        response = client.messages.create(
            model=resolved_model,
            max_tokens=1024,
            system=(
                "당신은 Terraform 변경 사항을 검토하는 보안 리뷰어입니다. "
                "다른 AI가 제안한 변경을 무비판적으로 승인하지 말고, 실제로 "
                "안전하고 정확한지 독립적으로 판단하세요. 확신이 없으면 "
                "NEEDS_HUMAN_REVIEW를 반환하세요."
            ),
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception as exc:
        raise RemediationError(f"Anthropic 재검증 요청 실패: {exc}") from exc

    text = "".join(
        block.text for block in response.content if getattr(block, "type", None) == "text"
    ).strip()
    if not text:
        raise RemediationError("Anthropic이 빈 재검증 결과를 반환했습니다.")

    try:
        result = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RemediationError(f"Anthropic 재검증 응답이 JSON이 아닙니다: {exc}") from exc

    verdict = str(result.get("verdict") or "").upper()
    if verdict not in {"APPROVE", "REJECT", "NEEDS_HUMAN_REVIEW"}:
        raise RemediationError(f"알 수 없는 verdict 값: {result.get('verdict')}")

    return {
        "verdict": verdict,
        "summary": result.get("summary") or "",
        "concerns": result.get("concerns") or [],
        "model": resolved_model,
    }
