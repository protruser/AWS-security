# 기본 기능 추가 — 로그인 / 실시간 시계 / 실제 AI 챗봇

원본 대시보드 레이아웃을 유지하면서 다음 3가지만 추가했다.

## 1. 로그인

- 새 파일: `src/components/LoginPage.tsx`
- Flask API:
  - `GET /api/auth/status`
  - `POST /api/auth/login`
  - `POST /api/auth/logout`
- 로그인 정보는 `backend/.env`의 `ADMIN_USERNAME`, `ADMIN_PASSWORD`로 설정
- Flask 세션 쿠키 사용
- `/api/dashboard`, `/api/events`, `/api/chat`은 로그인 필요

## 2. 메인 시계 실제 시간 동기화

기존 고정 날짜에서 시작해서 1분씩 더하던 로직을 제거했다.
브라우저가 실제 현재 시간을 1초마다 읽고, 화면에는 `Asia/Seoul` 기준으로 표시한다.

`자동 갱신 ON/OFF`는 시계와 분리했으며 DB 재조회 주기만 제어한다.

## 3. 보안 분석 챗봇 실제 API 연결

기존 `mock.ts`의 `getBotResponse()` 대신 React가 `POST /api/chat`을 호출한다.
Flask 서버에서 OpenAI Responses API를 호출한다.

API 키는 절대 React에 넣지 않는다.

```text
backend/.env
OPENAI_API_KEY=...
OPENAI_MODEL=gpt-5.6-luna
```

선택된 이벤트가 있으면 이벤트 정보와 로그 일부도 AI 컨텍스트로 전달한다.
