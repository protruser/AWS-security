"""Fail closed on embedded credentials; encrypt persisted patch artifacts."""
import json
import os
import re

from cryptography.fernet import Fernet


class PatchError(Exception):
    def __init__(self, code, message, status=400):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def cipher():
    try:
        return Fernet(os.environ["PATCH_ENCRYPTION_KEY"].encode())
    except (KeyError, ValueError):
        raise PatchError("PATCH_CONFIG", "패치 이력 암호화 키 설정이 필요합니다.", 503) from None


def seal(payload):
    return cipher().encrypt(json.dumps(payload, ensure_ascii=False).encode()).decode()


def unseal(value):
    return json.loads(cipher().decrypt(value.encode()))


# 이름에 token/secret 등이 들어가지만 값이 비밀이 아닌 Terraform 속성과 그 허용값.
# http_tokens 는 EC2 IMDSv2 설정이다(required/optional). 다른 값이면 그대로 비밀값으로 본다.
NON_SECRET_VALUES = {"http_tokens": {"required", "optional"}}

# key = "literal" 형태의 비밀값. 속성 이름 전체와 값을 잡아서 NON_SECRET_VALUES 만 제외한다.
LITERAL_SECRET = re.compile(
    r"(?i)\b([\w-]*(?:password|passwd|secret|token|access_key|private_key|api_key)[\w-]*)"
    r"[\"']?\s*[:=]\s*[\"'](?!\$\{)([^\"'\r\n]+)[\"']")


def _is_literal_secret(match):
    return match.group(2) not in NON_SECRET_VALUES.get(match.group(1).lower(), ())


def check_sensitive(text):
    # Never mask and then offer the masked Terraform as deployable source. Reject
    # literal secrets before AI, storage or browser output; references stay intact.
    if any(_is_literal_secret(match) for match in LITERAL_SECRET.finditer(text)):
        raise PatchError("SENSITIVE_CONTENT", "민감한 값이 감지되었습니다. 비밀값을 변수 또는 Secret 참조로 분리한 후 다시 요청하세요.")
    patterns = [
        r"(?:AKIA|ASIA)[A-Z0-9]{16}",
        r"-----BEGIN [\w ]*PRIVATE KEY-----",
        r"(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]+|sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,})",
        r"(?is)variable\s+\"[^\"]+\"\s*\{[^}]*sensitive\s*=\s*true[^}]*default\s*=",
        r"(?is)variable\s+\"[^\"]+\"\s*\{[^}]*default\s*=[^}]*sensitive\s*=\s*true",
        r"(?i)(?:password|secret|token|private_key)[\w-]*\s*=\s*<<",
        r"(?is)variable\s+\"[^\"]*(?:password|secret|token|private_key|api_key)[^\"]*\"\s*\{[^}]*default\s*=\s*(?!null\b)",
        r"(?i)https?://[^\s/:]+:[^\s/@]+@",
    ]
    if any(re.search(pattern, text) for pattern in patterns):
        raise PatchError("SENSITIVE_CONTENT", "민감한 값이 감지되었습니다. 비밀값을 변수 또는 Secret 참조로 분리한 후 다시 요청하세요.")
    # Also catch configured credentials if repeated by a model or included in input.
    for name in ("GITHUB_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "DB_PASSWORD", "AWS_SECRET_ACCESS_KEY"):
        value = os.getenv(name, "")
        if len(value) >= 8 and value in text:
            raise PatchError("SENSITIVE_CONTENT", "인증정보가 포함된 내용을 처리할 수 없습니다.")


def safe_path(path):
    if (not isinstance(path, str) or len(path) > 240
            or not re.fullmatch(r"[A-Za-z0-9_./-]+\.tf", path)
            or any(part in ("", ".", "..", ".terraform", ".git") for part in path.split("/"))):
        raise PatchError("INVALID_FILE_PATH", "저장소 내부의 .tf 상대 경로를 입력하세요.")
    return path
