USE security;

ALTER TABLE approval_requests
    ADD COLUMN note TEXT NULL AFTER action_type;
