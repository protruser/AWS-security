USE security;

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
