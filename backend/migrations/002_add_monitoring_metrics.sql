USE security;

CREATE TABLE IF NOT EXISTS monitoring_metrics (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    service         VARCHAR(40) NOT NULL,
    resource_id     VARCHAR(255) NOT NULL,
    metric_name     VARCHAR(100) NOT NULL,
    metric_value    DECIMAL(20, 6) NOT NULL,
    unit            VARCHAR(32) NOT NULL,
    period_seconds  SMALLINT UNSIGNED NOT NULL,
    collected_at    DATETIME NOT NULL,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY uq_monitoring_metric_point
      (service, resource_id, metric_name, collected_at),
    INDEX idx_monitoring_metric_lookup (metric_name, collected_at),
    INDEX idx_monitoring_resource_lookup (resource_id, collected_at)
);
