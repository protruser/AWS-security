# AWS Security Monitoring Dashboard

React 19 + Vite 8 + TypeScript + Tailwind CSS 4 기반 보안관제 데모입니다. 실제 API 없이 기존 공격 탐지·조치 목록·탐지 이력·시나리오·챗봇·리소스 상태 더미데이터를 사용합니다. 기본 Critical 배너는 표시하지 않습니다.

## 로컬 실행

Node.js 22.12 이상을 설치한 뒤 프로젝트 루트에서 실행합니다.

```sh
npm ci
npm run dev
```

접속 주소: **http://localhost:8443/**. Windows PowerShell에서 실행 정책 오류가 발생하면 `npm` 대신 `npm.cmd`를 사용하세요. 기존 pnpm 환경에서는 `pnpm install --frozen-lockfile`, `pnpm dev`도 사용할 수 있습니다.

포트는 기존 8443을 유지하며, 충돌 시 자동 변경하지 않고 오류를 표시합니다. 다른 포트는 `npm run dev -- --port 8444`로 지정하세요. `PORT`와 Figma의 `FIGMA_DEV_SERVER_HOST`, `FIGMA_PUBLIC_URL` 환경변수도 지원합니다. 기본 호스트는 localhost입니다.

```sh
npm run lint
npm run typecheck
npm run build
npm run preview
```

`preview`도 http://localhost:8443/을 사용하므로 먼저 개발 서버를 종료하세요. `lint`는 추가 라이브러리 없이 TypeScript의 엄격한 검사와 미사용 변수·매개변수 검사를 실행합니다. `build`는 `dist/`를 생성합니다. Google Fonts를 불러올 수 없는 환경에서는 시스템 sans-serif 글꼴로 표시하며, 데이터와 기능은 외부 서버에 의존하지 않습니다.

## 코드 구조

```text
src/
├─ App.tsx                     메인 화면(상태·라우팅·레이아웃)
├─ main.tsx, index.css         진입점·전역 스타일
├─ components/
│   ├─ architecture/           아키텍처 맵 (ArchitectureMap, AssetCard, Connections, AwsIcon)
│   ├─ events/                 조치 필요 목록 (ActionCard, RightPanel)
│   ├─ chatbot/                보안 분석 챗봇 (SecurityChatbot)
│   ├─ scenario-cards/         시나리오 카드 (ScenarioCardWrapper)
│   ├─ scenario/               시나리오 상세 화면 (ScenarioPage)
│   ├─ attack-lab/             공격 실습 화면 (AttackLabPage)
│   ├─ auth/                   로그인 (LoginPage)
│   └─ shared/                 공통 UI (common.tsx)
├─ data/                       타입·자산 정의·시나리오·mock 데이터
├─ services/                   백엔드 API 호출 (dashboardApi.ts)
└─ assets/aws-icons/           AWS 아이콘
backend/                       Flask + MySQL 조회·조치 API, schema.sql
docs/                          구현 메모
```

- `src/data/architecture.ts`: 리소스 정보·상태·Grid 좌표
- `src/data/architectureLayout.ts`: 서브넷과 외부 Anchor·연결 경로
- `src/data/mock.ts`: 원본 이벤트·탐지/조치 이력·시나리오·챗봇 예시 (DB 연결 실패 시 이 데이터를 그대로 사용)
- `src/data/types.ts`, `src/index.css`: 공통 타입·스타일

박스는 연결선 위의 독립 레이어에 표시됩니다. 선은 박스 경계에서 6 단위 떨어진 Anchor를 사용하며, 행·열 사이와 VPC 바깥 통로를 따라갑니다. 낮은 창에서는 글자 크기를 유지하고 아키텍처 내부를 스크롤합니다. 기존 데모의 예외 처리·일부 챗봇 액션 등 미구현 버튼은 실제 API 작업을 실행하지 않습니다.

## 브라우저 검증

개발 서버와 원격 디버깅 포트 9222를 연 별도 Chrome을 실행한 뒤:

```sh
node scripts/browser-check.mjs
```

이 스크립트는 Node 내장 WebSocket으로 Chrome DevTools Protocol에 연결합니다. 1440×1080·1920×1080에서 박스·텍스트·연결선·라벨의 겹침, 필수 연결 관계, 더미데이터와 주요 상호작용 및 콘솔 오류를 검사합니다. 1440×900의 내부 스크롤도 확인합니다. 스크린샷과 오류 기록은 Git에서 제외한 `artifacts/`에 저장합니다. Chrome 프로필을 프로젝트에 두는 경우 `.browser-check/`를 사용하세요. 해당 경로는 Vite 감시와 소스 검색에서 제외됩니다.
