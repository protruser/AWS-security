"""Separate, repeatable patch runner. Schedule this process outside Flask."""
import logging
import os
import time

from services.patch_security import PatchError
from services.patch_workflow import PatchWorkflow


STALE_CODES = {"CODE_CHANGED", "CHECKS_CHANGED", "STALE_APPROVAL", "BASE_CHANGED",
               "CHECKS_NOT_PASSED", "FIRST_APPROVAL_REQUIRED"}


def run_once(service=None):
    service = service or PatchWorkflow()
    for patch_id in service.repo.active_check_ids():
        try:
            service.refresh_checks(patch_id, "patch-worker")
        except PatchError as exc:
            logging.warning("Patch %s CI result pending: %s", patch_id, exc.code)
    pending = service.repo.pending_deploy_ids() if os.getenv("PATCH_ENABLE_TERRAFORM_APPLY") == "true" else []
    for patch_id in pending:
        try:
            service.start_deploy(patch_id, "deploy-worker")
        except PatchError as exc:
            if exc.code in STALE_CODES:
                service.block_stale_deploy(patch_id, exc.code)
            logging.warning("Patch %s deployment dispatch blocked: %s", patch_id, exc.code)
    for patch_id in service.repo.active_deploy_ids():
        try:
            service.refresh_deploy(patch_id, "deploy-worker")
        except PatchError as exc:
            logging.warning("Patch %s deployment result pending: %s", patch_id, exc.code)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    while True:
        # DB나 GitHub가 잠깐 안 될 때 프로세스가 죽지 않고 다음 주기에 다시 시도한다.
        # 배포 중복은 patch 상태 전이와 deploy lock이 막는다.
        try:
            run_once()
        except Exception:
            logging.exception("patch worker cycle failed")
        time.sleep(10)
