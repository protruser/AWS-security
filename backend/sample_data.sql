USE security;

INSERT INTO security_events (
    id, service, scenario_type, severity, title, asset, detected_at, status,
    recommendation, auto_remediation, highlight_assets, attack_path,
    attacker_ip, request_url, rule_name, blocked, block_result, logs
) VALUES (
    'sql-db-test',
    'AWS WAF',
    'sqli',
    'Critical',
    'DB 연동 테스트 - SQL Injection',
    'Flask App Server',
    NOW(),
    '승인 대기',
    'WAF 차단 규칙 강화 및 Flask 입력값 검증 점검',
    TRUE,
    JSON_ARRAY('attacker', 'igw', 'shopWAF', 'shopALB', 'k3s', 'flaskApp', 'cwLogs'),
    JSON_ARRAY('attacker', 'igw', 'shopWAF', 'shopALB', 'k3s', 'flaskApp'),
    '203.0.113.45',
    'POST /api/products?id=1%27+OR+%271%27%3D%271',
    'AWSManagedRulesSQLiRuleSet / SQLi_BODY',
    FALSE,
    '부분',
    '{"source":"sample_data.sql","message":"DB 연동 확인용 샘플 이벤트"}'
)
ON DUPLICATE KEY UPDATE
    scenario_type = VALUES(scenario_type),
    detected_at = NOW(),
    updated_at = CURRENT_TIMESTAMP;

INSERT INTO remediation_history (
    event_id, action_type, method, approver, status, result, requested_at, completed_at
) VALUES (
    'sql-db-test',
    'WAF_RULE_UPDATE',
    '수동',
    '테스트 관리자',
    '완료',
    '성공',
    NOW(),
    NOW()
);
