# 원본 대시보드 + Security DB 연동

이번 수정은 **원본 UI/아키텍처 디자인을 유지**하고 데이터 공급원만 DB로 바꾸기 위한 코드입니다.

## 변경된 파일

- `src/App.tsx`
  - 원본 mock 데이터를 초기값으로 유지
  - `/api/dashboard` 호출 성공 시 DB 데이터로 교체
  - 자동 갱신 ON이면 1분마다 DB 데이터 재조회
  - 기존 ActionCard / ArchitectureMap / 탐지 이력 / 조치 이력 UI 그대로 사용
- `src/data/types.ts`
  - DB API 응답용 타입 3개 추가
- `vite.config.ts`
  - 개발 중 `/api` 요청을 Flask `127.0.0.1:5000`으로 전달하는 proxy 추가
- `backend/`
  - Flask + MySQL 조회 API 추가

## 최종 흐름

```text
Lambda (다른 팀원 담당)
    ↓ INSERT
Security MySQL
    ↓ SELECT
Flask /api/dashboard
    ↓ fetch
React
    ↓
원본 대시보드 UI
```

## 아키텍처 맵 공격 경로 표시

DB의 아래 두 JSON 컬럼이 중요합니다.

- `highlight_assets`
- `attack_path`

값은 `src/data/architecture.ts`의 `id`와 같아야 합니다.

예:

```json
{
  "highlight_assets": ["attacker", "igw", "shopWAF", "shopALB", "k3s", "flaskApp", "cwLogs"],
  "attack_path": ["attacker", "igw", "shopWAF", "shopALB", "k3s", "flaskApp"]
}
```

이 이벤트를 우측 카드에서 선택하면 **원본 ArchitectureMap의 기존 강조 로직**이 그대로 동작합니다.

## 개발 실행 순서

### Flask

```powershell
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
Copy-Item .env.example .env
python app.py
```

### React

다른 터미널에서 `frontend/` 폴더:

```powershell
cd frontend
npm install
npm run dev
```

### 확인

- DB 연결: `http://127.0.0.1:5000/api/health`
- DB 데이터: `http://127.0.0.1:5000/api/dashboard`

## 아직 하지 않은 것

이번 작업은 **DB → 대시보드 읽기**만 구현합니다.

- 조치 승인 DB UPDATE
- 예외 처리 DB UPDATE
- Lambda 호출
- AWS 보안 서비스 API 수집

은 포함하지 않았습니다.
