# AWS Security Monitoring Dashboard

React 19 + Vite 8 + TypeScript + Tailwind CSS 4 프론트엔드와 Flask + MySQL 백엔드로 구성된 AWS 보안관제 대시보드입니다. 운영 요약 카드는 CloudWatch → Monitoring Lambda → MySQL → Flask API 흐름의 실제 지표만 표시합니다.

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

- `src/App.tsx`: 기존 대시보드·탭·시나리오 카드·승인·챗봇 UI 및 상태
- `src/components/ArchitectureMap.tsx`: 서브넷 배치·레이어·반응형 캔버스
- `src/components/AssetCard.tsx`: 리소스 박스와 상태 표시
- `src/components/Connections.tsx`: 직각 SVG 연결선·화살표·흰색 라벨
- `src/data/architecture.ts`: 리소스 정보·상태·Grid 좌표
- `src/data/architectureLayout.ts`: 서브넷과 외부 Anchor·연결 경로
- `src/services/dashboardApi.ts`: Flask의 보안 이벤트 및 운영 지표 API 호출
- `src/data/mock.ts`: 현재 운영 지표 카드에서 사용하지 않는 이전 UI 예시 데이터 보존
- `src/data/types.ts`, `src/index.css`: 공통 타입·스타일

박스는 연결선 위의 독립 레이어에 표시됩니다. 선은 박스 경계에서 6 단위 떨어진 Anchor를 사용하며, 행·열 사이와 VPC 바깥 통로를 따라갑니다. 낮은 창에서는 글자 크기를 유지하고 아키텍처 내부를 스크롤합니다. 기존 데모의 예외 처리·일부 챗봇 액션 등 미구현 버튼은 실제 API 작업을 실행하지 않습니다.

## 브라우저 검증

개발 서버와 원격 디버깅 포트 9222를 연 별도 Chrome을 실행한 뒤:

```sh
node scripts/browser-check.mjs
```

이 스크립트는 Node 내장 WebSocket으로 Chrome DevTools Protocol에 연결합니다. 1440×1080·1920×1080에서 박스·텍스트·연결선·라벨의 겹침, 필수 연결 관계, 더미데이터와 주요 상호작용 및 콘솔 오류를 검사합니다. 1440×900의 내부 스크롤도 확인합니다. 스크린샷과 오류 기록은 Git에서 제외한 `artifacts/`에 저장합니다. Chrome 프로필을 프로젝트에 두는 경우 `.browser-check/`를 사용하세요. 해당 경로는 Vite 감시와 소스 검색에서 제외됩니다.
