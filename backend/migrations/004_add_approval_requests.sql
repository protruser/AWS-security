USE security;

CREATE TABLE IF NOT EXISTS approval_requests (
    id               BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_id         VARCHAR(255) NOT NULL,
    action_type      VARCHAR(100) NULL,
    request_type     VARCHAR(20) NOT NULL,
    status           VARCHAR(20) NOT NULL DEFAULT '대기',
    previous_status  VARCHAR(40) NULL,
    requested_by     VARCHAR(80) NULL,
    reviewed_by      VARCHAR(80) NULL,
    reject_reason    TEXT NULL,
    requested_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewed_at      DATETIME NULL,

    INDEX idx_approval_requests_event_id (event_id),
    INDEX idx_approval_requests_status (status),
    CONSTRAINT fk_approval_requests_event
      FOREIGN KEY (event_id) REFERENCES security_events(id)
      ON DELETE CASCADE
);
