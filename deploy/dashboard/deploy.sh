#!/usr/bin/env bash
# dashboard EC2에서 SSM으로 실행되는 배포 스크립트.
# GitHub Actions가 ECR에 새 이미지를 올린 뒤 이 스크립트를 호출한다.
#
# service 레포의 deploy/shop-app/deploy.sh와 달리, DB/앱 비밀값을 Secrets
# Manager에서 새로 만들지 않는다 (관리자 비밀번호, OpenAI 키 등은 이미
# /opt/dashboard/app.env에 사람이 직접 넣어둔 값이라 그대로 재사용).
set -Eeuo pipefail

readonly CONTAINER_NAME="dashboard"
readonly ENV_FILE="/opt/dashboard/app.env"
readonly HEALTH_URL="http://127.0.0.1:8443/api/health"

log() {
  printf '[dashboard-deploy] %s\n' "$1"
}

fail() {
  printf '[dashboard-deploy] ERROR: %s\n' "$1" >&2
  exit 1
}

if [[ $# -ne 2 ]]; then
  fail "usage: deploy.sh <image-uri> <aws-region>"
fi

readonly IMAGE_URI="$1"
readonly AWS_REGION="$2"
readonly ECR_REGISTRY="${IMAGE_URI%%/*}"

for command_name in aws docker curl; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command is unavailable: $command_name"
done

[[ "$ECR_REGISTRY" != "$IMAGE_URI" ]] || fail "image URI must include an ECR registry and repository"
[[ -s "$ENV_FILE" ]] || fail "$ENV_FILE not found; set it up once via SSM before the first GitHub Actions deploy"
grep -Eq '^OPENAI_API_KEY=[^[:space:]]+' "$ENV_FILE" ||
  fail "OPENAI_API_KEY is missing from $ENV_FILE"

log "Logging in to Amazon ECR and pulling the requested image."
aws ecr get-login-password --region "$AWS_REGION" |
  docker login --username AWS --password-stdin "$ECR_REGISTRY" >/dev/null
docker pull "$IMAGE_URI"

# The new image contains the additive migration. Apply it while the previous
# dashboard remains available; a DB failure stops before container replacement.
log "Applying event AI analysis migration."
docker run --rm \
  --env-file "$ENV_FILE" \
  --entrypoint python \
  "$IMAGE_URI" -m migrate_event_ai

previous_image=""
if docker container inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
  previous_image="$(docker container inspect --format '{{.Config.Image}}' "$CONTAINER_NAME")"
  log "Stopping the existing container."
  docker stop --time 30 "$CONTAINER_NAME" >/dev/null
  docker rm "$CONTAINER_NAME" >/dev/null
fi

run_container() {
  local image="$1"
  docker run --detach \
    --name "$CONTAINER_NAME" \
    --restart unless-stopped \
    --env-file "$ENV_FILE" \
    -p 8443:8443 \
    "$image" >/dev/null
}

wait_until_healthy() {
  local attempt
  for attempt in $(seq 1 30); do
    if curl --fail --silent --show-error --output /dev/null "$HEALTH_URL"; then
      return 0
    fi
    sleep 5
  done
  return 1
}

log "Starting the new dashboard container."
if run_container "$IMAGE_URI" && wait_until_healthy; then
  log "Deployment passed the health check."
  exit 0
fi

log "New deployment failed health checks; removing the failed container."
docker rm --force "$CONTAINER_NAME" >/dev/null 2>&1 || true

if [[ -n "$previous_image" ]]; then
  log "Attempting rollback to the previous image."
  if run_container "$previous_image" && wait_until_healthy; then
    fail "deployment failed; rollback to the previous image succeeded"
  fi
  docker rm --force "$CONTAINER_NAME" >/dev/null 2>&1 || true
  fail "deployment failed and rollback did not become healthy"
fi

fail "deployment failed and no previous image was available for rollback"
