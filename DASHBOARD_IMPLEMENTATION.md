# Dashboard 구현 메모

## 담당 범위

이 프로젝트에서 대시보드 영역은 아래 흐름을 담당합니다.

```text
Security DB
  ↓
Flask API
  ↓ GET /api/events
React Dashboard
```

Lambda의 AWS 보안 서비스 수집 로직은 대시보드 코드에 포함하지 않습니다.

## 메인 화면 데이터 흐름

```text
/api/events
  ↓ fetchActionEvents()
actionEvents state
  ↓
filter / severity sort
  ↓
RightPanel / ActionCard
```

Flask가 내려가 있거나 API가 아직 준비되지 않았으면 `src/data/mock.ts`의 `ACTION_EVENTS`를 사용합니다.

## 주요 파일

- `src/App.tsx`: 메인 관제 UI, 시나리오 카드, 이벤트/챗봇 패널
- `src/components/ArchitectureMap.tsx`: 인프라 맵
- `src/components/AssetCard.tsx`: 탐지 위치 / 영향 대상 / 비상 상태 표시
- `src/components/Connections.tsx`: 요청·수집·공격 경로 연결선
- `src/data/architecture.ts`: 리소스 및 시나리오 매핑
- `src/data/architectureLayout.ts`: 서브넷, 좌표, 데이터 수집/조치 흐름
- `src/services/dashboardApi.ts`: Flask API 호출 + mock fallback

## API 계약

`GET /api/events`는 아래 필드를 포함한 배열을 반환해야 합니다.

```json
[
  {
    "id": "sql",
    "severity": "Critical",
    "title": "SQL Injection 반복 요청 탐지",
    "service": "AWS WAF",
    "asset": "Flask App Server",
    "detectedAt": "2026.09.20 14:28",
    "elapsed": "4분",
    "status": "승인 대기",
    "recommendation": "WAF 규칙 강화",
    "autoRemediation": true,
    "highlightAssets": ["shopWAF", "shopALB", "flaskApp"],
    "attackPath": ["attacker", "igw", "shopWAF", "shopALB", "k3s", "flaskApp"],
    "details": {
      "attackerIP": "203.0.113.45",
      "logs": "..."
    }
  }
]
```
