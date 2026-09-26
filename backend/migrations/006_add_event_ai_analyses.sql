-- 이벤트 원본과 분리된 검증 완료 AI 분석. 운영 DB 적용은 별도 수행한다.
CREATE TABLE IF NOT EXISTS event_ai_analyses (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_id VARCHAR(255) NOT NULL,
    input_hash CHAR(64) NOT NULL,
    result JSON NOT NULL,
    model VARCHAR(100) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_event_ai_analysis (event_id),
    CONSTRAINT fk_event_ai_analysis_event FOREIGN KEY (event_id)
      REFERENCES security_events(id) ON DELETE CASCADE
);
