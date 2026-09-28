-- Additive, rerunnable; existing diagnoses and approval_requests are preserved.
-- Artifact JSON (source, proposals, diff, report and audit) is Fernet encrypted.
CREATE TABLE IF NOT EXISTS terraform_patches (
    id CHAR(36) PRIMARY KEY,
    diagnosis_run_id BIGINT NOT NULL,
    status VARCHAR(32) NOT NULL,
    requested_by VARCHAR(80) NOT NULL,
    content_hash CHAR(64) NULL,
    payload_encrypted LONGTEXT NOT NULL,
    revision INT NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_terraform_patch_created (created_at, id),
    INDEX idx_terraform_patch_status (status),
    INDEX idx_terraform_patch_diagnosis (diagnosis_run_id)
);
