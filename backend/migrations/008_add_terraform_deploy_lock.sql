-- One global deployment lease. A crash leaves it held, so an operator must
-- inspect the run before manual recovery; no timed auto-unlock can allow overlap.
CREATE TABLE IF NOT EXISTS terraform_patch_deploy_lock (
    id TINYINT PRIMARY KEY,
    patch_id CHAR(36) NULL,
    acquired_at DATETIME NULL
);
INSERT IGNORE INTO terraform_patch_deploy_lock (id, patch_id) VALUES (1, NULL);
