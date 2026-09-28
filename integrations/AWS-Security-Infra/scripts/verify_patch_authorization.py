"""Verify dashboard-issued, short-lived HMAC approval in the infra runner."""
import base64
import hashlib
import hmac
import json
import os
import re
import sys
import time


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def verify(token, key, now=None):
    try:
        if len(key) < 32:
            raise ValueError("missing signing key")
        body, signature = token.split(".", 1)
        expected = hmac.new(key, body.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, decode(signature)):
            raise ValueError("signature mismatch")
        claims = json.loads(decode(body))
        if (type(claims["exp"]) is not int or claims["exp"] < (now or int(time.time()))
                or claims["base_ref"] != "gyu"
                or not re.fullmatch(r"[0-9a-f]{40}", claims["head_sha"])
                or not re.fullmatch(r"[0-9a-f]{40}", claims["base_sha"])
                or claims["branch"] != f"ai-patch/{claims['patch_id']}"
                or not re.fullmatch(r"[0-9a-f-]{36}", claims["patch_id"])
                or not re.fullmatch(r"[0-9a-f]{64}", claims["plan_sha256"])
                or not claims["plan_key"].startswith(
                    f"terraform-patches/{claims['patch_id']}/{claims['head_sha']}/")
                or not isinstance(claims["state"]["lineage"], str)
                or type(claims["state"]["serial"]) is not int):
            raise ValueError("invalid claims")
        return claims
    except (ValueError, TypeError, KeyError, UnicodeError, json.JSONDecodeError):
        raise SystemExit("Invalid or expired deployment approval") from None


if __name__ == "__main__":
    claims = verify(os.environ["PATCH_AUTHORIZATION"],
                    os.environ["PATCH_APPROVAL_SIGNING_KEY"].encode())
    if claims["patch_id"] != os.environ["PATCH_ID"]:
        raise SystemExit("Patch ID mismatch")
    with open(sys.argv[1], "w", encoding="utf-8") as output:
        json.dump(claims, output)
