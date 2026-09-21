USE security;

ALTER TABLE security_events
    ADD COLUMN scenario_type VARCHAR(80) NULL AFTER service,
    ADD INDEX idx_security_events_scenario_type (scenario_type);
