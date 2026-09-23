CREATE DATABASE IF NOT EXISTS security
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE security;

-- Lambda가 수집한 GuardDuty/WAF/Inspector/Access Analyzer 등의 보안 이벤트
CREATE TABLE IF NOT EXISTS security_events (
    id                VARCHAR(255) PRIMARY KEY,
    service           VARCHAR(80) NOT NULL,
    scenario_type     VARCHAR(80) NULL,
    severity          VARCHAR(20) NOT NULL,
    title             VARCHAR(255) NOT NULL,
    asset             VARCHAR(255) NULL,
    detected_at       DATETIME NOT NULL,
    status            VARCHAR(40) NOT NULL DEFAULT '검토 필요',
    recommendation    TEXT NULL,
    auto_remediation  BOOLEAN NOT NULL DEFAULT FALSE,

    -- ArchitectureMap의 자산 ID와 동일하게 저장
    highlight_assets  JSON NULL,
    attack_path       JSON NULL,

    attacker_ip       VARCHAR(45) NULL,
    request_url       TEXT NULL,
    rule_name         VARCHAR(255) NULL,
    blocked           BOOLEAN NULL,
    block_result      VARCHAR(20) NULL,
    logs              LONGTEXT NULL,

    created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                                      ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_security_events_detected_at (detected_at),
    INDEX idx_security_events_status (status),
    INDEX idx_security_events_severity (severity),
    INDEX idx_security_events_service (service),
    INDEX idx_security_events_scenario_type (scenario_type)
);

-- 조치 승인/자동조치 결과 이력
CREATE TABLE IF NOT EXISTS remediation_history (
    id            BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_id      VARCHAR(255) NOT NULL,
    action_type   VARCHAR(100) NULL,
    method        VARCHAR(20) NOT NULL DEFAULT '수동',
    approver      VARCHAR(100) NULL,
    status        VARCHAR(40) NULL,
    result        VARCHAR(100) NULL,
    result_detail TEXT NULL,
    requested_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at  DATETIME NULL,

    INDEX idx_remediation_event_id (event_id),
    INDEX idx_remediation_completed_at (completed_at),
    CONSTRAINT fk_remediation_event
      FOREIGN KEY (event_id) REFERENCES security_events(id)
      ON DELETE CASCADE
);

-- Lambda C(infra: modules/lambda_c)가 CloudWatch에서 5분마다 수집하는 운영 지표.
-- 보안 이벤트와 분리한다. 서버 1대의 같은 5분 구간은 한 행만 남고(재시도해도 중복 없음),
-- 그 뒤로는 이력으로 계속 쌓인다(스냅샷이 아님). Lambda C가 오래된 행을 주기적으로 정리한다.
CREATE TABLE IF NOT EXISTS service_metrics (
    id                 BIGINT AUTO_INCREMENT PRIMARY KEY,
    server             VARCHAR(40) NOT NULL,
    display_name       VARCHAR(80) NOT NULL,
    status             VARCHAR(20) NOT NULL DEFAULT 'unknown',
    cpu_percent        DECIMAL(5,2) NULL,
    memory_percent     DECIMAL(5,2) NULL,
    request_count      INT NULL,
    avg_latency_ms     DECIMAL(8,2) NULL,
    error_rate_percent DECIMAL(5,2) NULL,
    healthy_targets    INT NULL,
    unhealthy_targets  INT NULL,
    window_start       DATETIME NOT NULL,
    window_end         DATETIME NOT NULL,
    created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY uq_service_metrics_point (server, window_start),
    INDEX idx_service_metrics_window_end (window_end),
    INDEX idx_service_metrics_server_window (server, window_end)
);

-- SK쉴더스 33개 항목 AI 진단 실행 이력. gunicorn 워커가 여러 개라 진행 상태를
-- 프로세스 메모리에 두면 워커마다 따로 보여서 폴링이 어긋난다. DB에 상태를
-- 두면 어느 워커가 /status 요청을 받아도 같은 진행 상황을 보여줄 수 있다.
CREATE TABLE IF NOT EXISTS ai_diagnosis_runs (
    id            BIGINT AUTO_INCREMENT PRIMARY KEY,
    status        VARCHAR(20) NOT NULL DEFAULT 'collecting',
    message       VARCHAR(255) NULL,
    requested_by  VARCHAR(80) NULL,
    result        JSON NULL,
    error         TEXT NULL,
    started_at    DATETIME NOT NULL,
    finished_at   DATETIME NULL,
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_ai_diagnosis_runs_started_at (started_at)
);
