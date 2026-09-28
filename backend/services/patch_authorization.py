"""Short-lived, exact-plan deployment authorization for a separate CI runner."""
import base64
import hashlib
import hmac
import json
import os
import sys
import time

from services.patch_security import PatchError


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _decode(data):
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def issue(patch, binding):
    key = os.getenv("PATCH_APPROVAL_SIGNING_KEY", "").encode()
    if len(key) < 32:
        raise PatchError("SIGNING_CONFIG", "배포 승인 서명 키가 필요합니다.", 503)
    info, checks = patch["payload"]["github_pr"], patch["payload"]["checks"]
    claims = {"patch_id": patch["id"], "approval_hash": binding,
              "head_sha": info["head_sha"], "base_sha": info["base_sha"],
              "branch": info["branch"], "base_ref": info["base_ref"],
              "pr_number": info["number"], "check_run_id": checks["run_id"],
              "plan_sha256": checks["plan_sha256"], "plan_key": checks["plan_key"],
              "plan_version_id": checks["plan_version_id"], "state": checks["state"],
              "exp": int(time.time()) + 900}
    encoded = _b64(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
    signature = _b64(hmac.new(key, encoded.encode(), hashlib.sha256).digest())
    return f"{encoded}.{signature}"


def verify(token, key=None, now=None):
    secret = key or os.getenv("PATCH_APPROVAL_SIGNING_KEY", "").encode()
    if len(secret) < 32:
        raise PatchError("SIGNING_CONFIG", "배포 승인 서명 키가 필요합니다.", 503)
    try:
        encoded, signature = token.split(".", 1)
        expected = hmac.new(secret, encoded.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(_decode(signature), expected):
            raise ValueError("bad signature")
        claims = json.loads(_decode(encoded))
        if (type(claims["exp"]) is not int or claims["exp"] < (now or int(time.time()))
                or not claims["plan_key"].startswith(
                    f"terraform-patches/{claims['patch_id']}/{claims['head_sha']}/")
                or len(claims["plan_sha256"]) != 64):
            raise ValueError("bad claims")
        return claims
    except (KeyError, ValueError, TypeError):
        raise PatchError("INVALID_AUTHORIZATION", "배포 승인이 유효하지 않습니다.", 403) from None


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "verify":
        raise SystemExit("usage: python -m services.patch_authorization verify output.json")
    claims = verify(os.environ["PATCH_AUTHORIZATION"])
    with open(sys.argv[2], "w", encoding="utf-8") as output:
        json.dump(claims, output)
