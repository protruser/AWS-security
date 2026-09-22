CREATE DATABASE IF NOT EXISTS security
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE security;

-- Lambda가 수집한 GuardDuty/WAF/Inspector/Access Analyzer 등의 보안 이벤트
CREATE TABLE IF NOT EXISTS security_events (
    id                VARCHAR(255) PRIMARY KEY,
    service           VARCHAR(80) NOT NULL,
    -- Lambda가 판단한 시나리오 키 (sqli/xss/dir/brute/brute_admin/port/cred/vuln/s3/generic 등)
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

-- Lambda C가 5분마다 CloudWatch에서 모은 인프라 현재 상태 (보안 이벤트 아님, 서버당 1행만 유지)
CREATE TABLE IF NOT EXISTS service_metrics (
    server              VARCHAR(40) PRIMARY KEY,
    display_name        VARCHAR(80) NOT NULL,
    status              VARCHAR(20) NOT NULL DEFAULT 'unknown',
    cpu_percent         DECIMAL(5,2) NULL,
    memory_percent      DECIMAL(5,2) NULL,
    request_count       INT NULL,
    avg_latency_ms      DECIMAL(8,2) NULL,
    error_rate_percent  DECIMAL(5,2) NULL,
    healthy_targets     INT NULL,
    unhealthy_targets   INT NULL,
    window_start        DATETIME NULL,
    window_end          DATETIME NULL,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                                        ON UPDATE CURRENT_TIMESTAMP
);
