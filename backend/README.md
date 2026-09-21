# Dashboard DB Backend

원본 React UI는 유지하고, Security MySQL의 데이터를 Flask API로 전달하는 백엔드입니다.

## 데이터 흐름

```text
Lambda(팀원 담당)
  → Security MySQL
  → Flask /api/dashboard
  → React fetch()
  → 기존 ActionCard / 탐지 이력 / 조치 이력 UI
```

## 1. DB 스키마

Security MySQL에서 `schema.sql`을 실행합니다.

Lambda 담당자는 `security_events`에 이벤트를 저장할 때 특히 아래 필드를 맞춰야 합니다.

- `id`, `service`, `severity`, `title`, `asset`, `detected_at`, `status`
- `highlight_assets`: ArchitectureMap 자산 ID의 JSON 배열
- `attack_path`: 공격 경로 자산 ID의 JSON 배열
- 필요 시 `attacker_ip`, `request_url`, `rule_name`, `blocked`, `logs`

예:

```json
["attacker", "igw", "shopWAF", "shopALB", "k3s", "flaskApp"]
```

`highlight_assets`, `attack_path`의 값은 `src/data/architecture.ts`의 자산 ID와 같아야 맵 강조가 동작합니다.

## 2. 로컬 실행

```powershell
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
Copy-Item .env.example .env
```

`.env`의 DB 정보를 실제 환경에 맞게 수정한 뒤:

```powershell
python app.py
```

DB 확인:

```text
http://127.0.0.1:5000/api/health
```

대시보드 데이터 확인:

```text
http://127.0.0.1:5000/api/dashboard
```

## 3. 운영 EC2

Terraform의 Dashboard EC2 IAM Role은 Security DB Secret 읽기 권한을 갖도록 구성되어 있습니다.
운영에서는 `.env`에 직접 DB 비밀번호를 넣는 대신 다음처럼 설정할 수 있습니다.

```text
DB_SECRET_ID=wonny-sec/security-db
AWS_REGION=ap-northeast-2
```

Flask의 `db.py`가 Secrets Manager에서 `host/port/username/password/database`를 읽습니다.

## 4. React

React는 `/api/dashboard`를 조회합니다. Vite 개발 서버에서는 `/api`를 `127.0.0.1:5000`으로 프록시합니다.

DB/API 연결에 실패하면 원본 mock 데이터를 그대로 유지하므로 UI가 깨지지 않습니다.

## 5. 로그인

`backend/.env`에서 관리자 계정을 설정합니다.

```text
ADMIN_USERNAME=admin
ADMIN_PASSWORD=원하는비밀번호
FLASK_SECRET_KEY=충분히긴랜덤문자열
```

React가 처음 열리면 `/api/auth/status`를 확인하고, 로그인되지 않았으면 로그인 화면을 표시합니다.
로그인 성공 후 Flask 세션 쿠키를 사용하며 `/api/dashboard`, `/api/events`, `/api/chat`은 로그인된 세션만 접근할 수 있습니다.

## 6. 실제 AI 챗봇 연결

OpenAI API 키는 프론트엔드에 넣지 않고 Flask의 `.env`에만 넣습니다.

```text
OPENAI_API_KEY=여기에_본인_API_KEY
OPENAI_MODEL=gpt-5.6-luna
```

`/api/chat`이 OpenAI Responses API를 호출하며, 대시보드에서 선택한 이벤트의 제목·심각도·서비스·자산·공격 경로·로그 일부를 컨텍스트로 전달합니다.
API 키가 없으면 챗봇 영역에 설정 필요 오류가 표시됩니다.
