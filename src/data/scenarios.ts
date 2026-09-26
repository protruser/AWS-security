import type { Severity } from "./types"

export type Tone = "danger" | "warn" | "ok" | "neutral"

export interface ScenarioAction {
  id: string
  title: string
  desc: string
  target: string
  executor: string
  risk: Severity
  rollback: string
  // 조치 후 "현재 설정"이 어떻게 바뀌는지 보여주기 위한 값
  policyKey?: string
  policyAfter?: string
}

export interface ScenarioDetail {
  id: string
  title: string
  source: string
  severity: Severity
  statusLabel: string
  tone: Tone
  summary: string
  kpis: { label: string; value: string; sub?: string; tone?: Tone }[]
  policy: { key: string; label: string; value: string }[]
  eventColumns: string[]
  events: { cells: string[]; tone?: Tone }[]
  logSample: string
  relatedAssets: string[]
  actions: ScenarioAction[]
  // traffic 형: 게이지 값 / vuln 형: CVE 목록
  gauge?: { pct: number; value: number; max: number; unit: string }
  cves?: {
    id: string
    sev: Severity
    pkg: string
    installed: string
    fixed: string
  }[]
}

export const SCENARIO_DETAILS: Record<string, ScenarioDetail> = {
  sql: {
    id: "sql",
    title: "SQL Injection",
    source: "AWS WAF · SQLi 관리형 규칙",
    severity: "Critical",
    statusLabel: "공격 탐지·차단됨",
    tone: "danger",
    summary:
      "203.0.113.45 에서 /api/products 로 SQL Injection 패턴 요청이 반복되고 있습니다. 1건은 COUNT 모드라 차단되지 않고 통과했습니다.",
    kpis: [
      { label: "최근 24시간 탐지", value: "4건", tone: "danger" },
      { label: "WAF 차단", value: "3건", tone: "ok" },
      { label: "백엔드 도달", value: "1건", tone: "danger" },
      { label: "공격 IP", value: "1개", sub: "203.0.113.45 (CN)" },
    ],
    policy: [
      {
        key: "mode",
        label: "SQLi 규칙 모드",
        value: "COUNT (탐지만, 차단 안 함)",
      },
      { key: "ip", label: "공격 IP 차단 목록", value: "미등록" },
      { key: "input", label: "Flask 입력값 검증", value: "파라미터 바인딩 점검 필요" },
    ],
    eventColumns: ["시각", "공격 IP", "요청", "결과"],
    events: [
      {
        cells: ["14:32:07", "203.0.113.45", "GET /product?id=1' OR '1'='1", "차단"],
        tone: "ok",
      },
      {
        cells: ["14:30:41", "203.0.113.45", "GET /product?id=1 UNION SELECT", "차단"],
        tone: "ok",
      },
      {
        cells: ["14:29:12", "203.0.113.45", "POST /api/products (body)", "차단"],
        tone: "ok",
      },
      {
        cells: ["14:28:03", "203.0.113.45", "POST /api/products?id=1' OR '1'='1", "통과"],
        tone: "danger",
      },
    ],
    logSample: `{
  "timestamp": "2026-09-18T14:28:03Z",
  "action": "ALLOW",
  "httpRequest": {
    "clientIp": "203.0.113.45",
    "uri": "/api/products",
    "method": "POST",
    "args": "id=1' OR '1'='1"
  },
  "nonTerminatingMatchingRules": [{ "ruleId": "SQLi_BODY", "action": "COUNT" }]
}`,
    relatedAssets: [
      "AWS WAF · 쇼핑몰",
      "ALB · 쇼핑몰",
      "K3s Cluster",
      "Flask App Server",
    ],
    actions: [
      {
        id: "sql-block",
        title: "SQLi 규칙을 BLOCK 모드로 전환",
        desc: "COUNT 로 동작 중인 SQLi_BODY 규칙을 BLOCK 으로 바꿔 통과 요청을 막습니다.",
        target: "AWS WAF · 쇼핑몰",
        executor: "Lambda Remediation → AWS API",
        risk: "Critical",
        rollback: "예 — 30분 이내 자동 롤백 가능",
        policyKey: "mode",
        policyAfter: "BLOCK (차단 적용 중)",
      },
      {
        id: "sql-ip",
        title: "공격 IP 203.0.113.45 차단",
        desc: "WAF IP Set 에 공격 IP 를 추가해 이후 모든 요청을 차단합니다.",
        target: "AWS WAF · 쇼핑몰",
        executor: "Lambda Remediation → AWS API",
        risk: "High",
        rollback: "예 — IP Set 에서 즉시 제거 가능",
        policyKey: "ip",
        policyAfter: "203.0.113.45 차단 중",
      },
      {
        id: "sql-input",
        title: "Flask 입력값 검증 점검 요청",
        desc: "개발팀에 /api/products 파라미터 바인딩 점검 티켓을 생성합니다.",
        target: "Flask App Server",
        executor: "티켓 발행 (실행 영향 없음)",
        risk: "Low",
        rollback: "해당 없음",
        policyKey: "input",
        policyAfter: "점검 티켓 발행됨",
      },
    ],
  },

  xss: {
    id: "xss",
    title: "XSS",
    source: "AWS WAF · XSS 관리형 규칙",
    severity: "Low",
    statusLabel: "정상 방어 중",
    tone: "ok",
    summary:
      "최근 24시간 동안 탐지된 XSS 요청이 없습니다. 규칙은 BLOCK 모드로 정상 동작 중입니다.",
    kpis: [
      { label: "최근 24시간 탐지", value: "0건", tone: "ok" },
      { label: "WAF 차단", value: "0건" },
      { label: "지난 7일 탐지", value: "2건", sub: "모두 차단" },
      { label: "규칙 상태", value: "BLOCK", tone: "ok" },
    ],
    policy: [
      { key: "mode", label: "XSS 규칙 모드", value: "BLOCK" },
      { key: "ip", label: "최근 차단 IP", value: "104.21.0.98 (13:20)" },
      { key: "csp", label: "Content-Security-Policy", value: "적용됨" },
    ],
    eventColumns: ["시각", "공격 IP", "요청", "결과"],
    events: [
      {
        cells: [
          "09.17 13:20",
          "104.21.0.98",
          "GET /search?q=<script>alert(1)</script>",
          "차단",
        ],
        tone: "ok",
      },
      {
        cells: ["09.15 22:04", "185.220.101.7", "POST /review (onerror=)", "차단"],
        tone: "ok",
      },
    ],
    logSample: `{
  "timestamp": "2026-09-17T13:20:11Z",
  "action": "BLOCK",
  "httpRequest": { "clientIp": "104.21.0.98", "uri": "/search" },
  "terminatingRuleId": "CrossSiteScripting_QUERYARGUMENTS"
}`,
    relatedAssets: ["AWS WAF · 쇼핑몰"],
    actions: [
      {
        id: "xss-csp",
        title: "CSP 헤더 강화 검토 요청",
        desc: "차단이 없어도 방어 계층을 늘리도록 CSP 정책 점검 티켓을 생성합니다.",
        target: "K3s nginx",
        executor: "티켓 발행 (실행 영향 없음)",
        risk: "Low",
        rollback: "해당 없음",
        policyKey: "csp",
        policyAfter: "강화 검토 티켓 발행됨",
      },
    ],
  },

  dir: {
    id: "dir",
    title: "디렉터리 서치",
    source: "AWS WAF Rate-based Rule + 자체 분석",
    severity: "Medium",
    statusLabel: "주의",
    tone: "warn",
    summary:
      "5분간 120건의 요청이 서로 다른 경로 47개로 발생했고 404 비율이 82% 입니다. 임계치(150) 의 80% 에 도달했습니다.",
    kpis: [
      { label: "5분간 요청", value: "120건", tone: "warn" },
      { label: "임계치", value: "150건" },
      { label: "고유 경로", value: "47개" },
      { label: "404 비율", value: "82%", tone: "warn" },
    ],
    gauge: { pct: 80, value: 120, max: 150, unit: "5분당 요청" },
    policy: [
      { key: "limit", label: "Rate Rule 임계치", value: "150건 / 5분" },
      { key: "action", label: "초과 시 정책", value: "BLOCK (5분 후 자동 해제)" },
      { key: "ip", label: "주요 출발지", value: "198.51.100.23" },
    ],
    eventColumns: ["시각", "출발지 IP", "요청 경로", "결과"],
    events: [
      { cells: ["14:31:50", "198.51.100.23", "/admin/.env", "404"], tone: "warn" },
      { cells: ["14:31:48", "198.51.100.23", "/backup.zip", "404"], tone: "warn" },
      { cells: ["14:31:44", "198.51.100.23", "/phpmyadmin/", "404"], tone: "warn" },
      { cells: ["14:31:41", "198.51.100.23", "/.git/config", "404"], tone: "warn" },
    ],
    logSample: `{
  "rateBasedRule": "DirScan-RateLimit",
  "limit": 150,
  "windowSec": 300,
  "currentCount": 120,
  "topClientIp": "198.51.100.23"
}`,
    relatedAssets: ["AWS WAF · 쇼핑몰", "K3s Cluster"],
    actions: [
      {
        id: "dir-limit",
        title: "임계치를 100건/5분으로 하향",
        desc: "차단 기준을 낮춰 스캔이 더 일찍 차단되도록 합니다. 정상 사용자 영향에 유의하세요.",
        target: "AWS WAF · 쇼핑몰",
        executor: "Lambda Remediation → AWS API",
        risk: "Medium",
        rollback: "예 — 이전 임계치로 즉시 복원",
        policyKey: "limit",
        policyAfter: "100건 / 5분",
      },
      {
        id: "dir-ip",
        title: "출발지 IP 198.51.100.23 차단",
        desc: "스캔 출발지를 WAF IP Set 에 등록해 차단합니다.",
        target: "AWS WAF · 쇼핑몰",
        executor: "Lambda Remediation → AWS API",
        risk: "Low",
        rollback: "예 — IP Set 에서 즉시 제거 가능",
        policyKey: "ip",
        policyAfter: "198.51.100.23 (차단 중)",
      },
    ],
  },

  brute: {
    id: "brute",
    title: "로그인 무차별대입",
    source: "AWS WAF Rate-based Rule + Flask 인증 로그",
    severity: "High",
    statusLabel: "WAF BLOCK 적용 중",
    tone: "danger",
    summary:
      "관리자 로그인에서 5분간 실패 50건이 발생해 임계치를 초과했고 WAF 가 출발지를 차단 중입니다. 공격 대상 계정은 4개입니다.",
    kpis: [
      { label: "5분간 로그인 실패", value: "50건", tone: "danger" },
      { label: "임계치", value: "50건" },
      { label: "공격 대상 계정", value: "4개", tone: "warn" },
      { label: "차단 중인 IP", value: "1개", sub: "45.33.32.156" },
    ],
    gauge: { pct: 100, value: 50, max: 50, unit: "임계치 초과" },
    policy: [
      { key: "limit", label: "Rate Rule 임계치", value: "50건 / 5분" },
      { key: "action", label: "초과 시 정책", value: "BLOCK 적용 중" },
      { key: "mfa", label: "관리자 MFA", value: "선택 사항" },
    ],
    eventColumns: ["시각", "출발지 IP", "대상 계정", "결과"],
    events: [
      { cells: ["14:31:58", "45.33.32.156", "admin", "실패"], tone: "danger" },
      { cells: ["14:31:57", "45.33.32.156", "root", "실패"], tone: "danger" },
      { cells: ["14:31:55", "45.33.32.156", "manager", "실패"], tone: "danger" },
      { cells: ["14:31:52", "45.33.32.156", "admin", "WAF 차단"], tone: "ok" },
    ],
    logSample: `{
  "rateBasedRule": "AdminLogin-RateLimit",
  "limit": 50,
  "windowSec": 300,
  "currentCount": 50,
  "action": "BLOCK",
  "clientIp": "45.33.32.156"
}`,
    relatedAssets: ["AWS WAF · 관리자", "ALB · 관리자", "Dashboard EC2"],
    actions: [
      {
        id: "brute-mfa",
        title: "관리자 로그인 MFA 필수화",
        desc: "관리자 콘솔 로그인에 MFA 를 강제해 비밀번호 대입을 무력화합니다.",
        target: "Dashboard EC2",
        executor: "Lambda Remediation → SSM",
        risk: "High",
        rollback: "예 — 설정 되돌리기 가능",
        policyKey: "mfa",
        policyAfter: "필수 (전체 관리자)",
      },
      {
        id: "brute-extend",
        title: "차단 시간 30분으로 연장",
        desc: "기본 5분인 차단 유지 시간을 30분으로 늘려 재시도를 막습니다.",
        target: "AWS WAF · 관리자",
        executor: "Lambda Remediation → AWS API",
        risk: "Medium",
        rollback: "예 — 이전 값으로 복원",
        policyKey: "action",
        policyAfter: "BLOCK 30분 유지",
      },
    ],
  },

  port: {
    id: "port",
    title: "포트 스캔",
    source: "GuardDuty · VPC Flow Logs",
    severity: "High",
    statusLabel: "이상행위 탐지",
    tone: "danger",
    summary:
      "203.0.113.45 에서 K3s 노드로 23개 포트 프로브가 감지되었습니다 (Recon:EC2/Portscan).",
    kpis: [
      { label: "탐지된 프로브", value: "23포트", tone: "danger" },
      { label: "Source IP", value: "1개", sub: "203.0.113.45" },
      { label: "대상 인스턴스", value: "1개", sub: "K3s 노드" },
      { label: "마지막 탐지", value: "14:20" },
    ],
    policy: [
      { key: "finding", label: "GuardDuty Finding", value: "Recon:EC2/Portscan" },
      { key: "sg", label: "Security Group 인바운드", value: "22, 80, 443, 6443 허용" },
      { key: "ip", label: "출발지 IP 차단", value: "미등록" },
    ],
    eventColumns: ["시각", "Source IP", "대상 포트", "결과"],
    events: [
      { cells: ["14:20:31", "203.0.113.45", "22, 23, 80, 443", "탐지"], tone: "danger" },
      { cells: ["14:20:29", "203.0.113.45", "3306, 5432, 6379", "탐지"], tone: "danger" },
      { cells: ["14:20:26", "203.0.113.45", "6443, 8080, 8443", "탐지"], tone: "danger" },
    ],
    logSample: `{
  "type": "Recon:EC2/Portscan",
  "severity": 5.0,
  "service": { "action": { "networkConnectionAction": {
    "remoteIpDetails": { "ipAddressV4": "203.0.113.45" },
    "remotePortDetails": { "port": 22 } } } }
}`,
    relatedAssets: ["VPC Flow Logs", "GuardDuty", "K3s Cluster"],
    actions: [
      {
        id: "port-sg",
        title: "Security Group 에서 불필요한 포트 제거",
        desc: "6443(K8s API) 등 외부에 열려 있을 필요 없는 인바운드 규칙을 닫습니다.",
        target: "K3s Cluster",
        executor: "Lambda Remediation → AWS API",
        risk: "High",
        rollback: "예 — 규칙 복원 가능",
        policyKey: "sg",
        policyAfter: "80, 443 만 허용",
      },
      {
        id: "port-ip",
        title: "출발지 IP 203.0.113.45 차단",
        desc: "Network ACL 로 출발지 IP 의 접근을 차단합니다.",
        target: "VPC Network ACL",
        executor: "Lambda Remediation → AWS API",
        risk: "Medium",
        rollback: "예 — NACL 규칙 삭제",
        policyKey: "ip",
        policyAfter: "203.0.113.45 차단 중",
      },
    ],
  },

  cred: {
    id: "cred",
    title: "탈취 자격증명 (퇴사자)",
    source: "GuardDuty · CloudTrail · Access Analyzer",
    severity: "Critical",
    statusLabel: "이상행위 탐지",
    tone: "danger",
    summary:
      "퇴사자 IAM 키가 평소 쓰지 않는 리전에서 AWS API 를 호출했습니다 (s3:ListBuckets 외 3건). 키의 마지막 정상 사용은 92일 전입니다.",
    kpis: [
      { label: "이상 API 호출", value: "4건", tone: "danger" },
      { label: "호출 리전", value: "sa-east-1", sub: "평소 미사용" },
      { label: "키 마지막 정상 사용", value: "92일 전", tone: "warn" },
      { label: "영향 IAM 사용자", value: "1명", sub: "former-dev01" },
    ],
    policy: [
      { key: "finding", label: "GuardDuty Finding", value: "CredentialAccess:IAMUser" },
      { key: "key", label: "Access Key 상태", value: "Active" },
      { key: "user", label: "IAM 사용자", value: "former-dev01 (콘솔 로그인 가능)" },
    ],
    eventColumns: ["시각", "IAM 사용자", "API 호출", "리전"],
    events: [
      { cells: ["14:05:12", "former-dev01", "s3:ListBuckets", "sa-east-1"], tone: "danger" },
      { cells: ["14:05:15", "former-dev01", "iam:ListUsers", "sa-east-1"], tone: "danger" },
      { cells: ["14:05:19", "former-dev01", "ec2:DescribeInstances", "sa-east-1"], tone: "danger" },
      { cells: ["14:05:24", "former-dev01", "s3:GetObject", "sa-east-1"], tone: "danger" },
    ],
    logSample: `{
  "eventName": "ListBuckets",
  "awsRegion": "sa-east-1",
  "userIdentity": { "type": "IAMUser", "userName": "former-dev01" },
  "sourceIPAddress": "198.51.100.77"
}`,
    relatedAssets: ["Access Analyzer", "CloudTrail", "GuardDuty", "Security Result MySQL"],
    actions: [
      {
        id: "cred-key",
        title: "Access Key 즉시 비활성화",
        desc: "탈취된 키를 비활성화해 추가 API 호출을 막습니다. 키는 삭제되지 않습니다.",
        target: "IAM · former-dev01",
        executor: "Lambda Remediation → AWS API",
        risk: "Critical",
        rollback: "예 — 키 재활성화 가능",
        policyKey: "key",
        policyAfter: "Inactive (비활성화됨)",
      },
      {
        id: "cred-user",
        title: "IAM 사용자 콘솔 접근 차단",
        desc: "로그인 프로필을 제거하고 세션을 무효화합니다.",
        target: "IAM · former-dev01",
        executor: "Lambda Remediation → AWS API",
        risk: "High",
        rollback: "아니오 — 로그인 프로필 재생성 필요",
        policyKey: "user",
        policyAfter: "콘솔 접근 차단됨",
      },
    ],
  },

  vuln: {
    id: "vuln",
    title: "취약 컨테이너 이미지",
    source: "Amazon Inspector",
    severity: "High",
    statusLabel: "취약점 발견",
    tone: "warn",
    summary:
      "shopping-flask:latest 이미지에서 Critical 1건, High 3건, Medium 2건의 취약점이 발견되었습니다.",
    kpis: [
      { label: "Critical", value: "1", tone: "danger" },
      { label: "High", value: "3", tone: "danger" },
      { label: "Medium", value: "2", tone: "warn" },
      { label: "마지막 스캔", value: "14:20", sub: "2026.09.18" },
    ],
    policy: [
      { key: "image", label: "대상 이미지", value: "shopping-flask:latest" },
      { key: "scan", label: "자동 스캔", value: "이미지 푸시 시 + 매일 1회" },
      { key: "deploy", label: "배포 상태", value: "K3s 에서 운영 중" },
    ],
    eventColumns: ["CVE", "패키지", "설치 버전", "수정 버전"],
    events: [],
    cves: [
      { id: "CVE-2023-49083", sev: "Critical", pkg: "cryptography", installed: "41.0.0", fixed: "41.0.7" },
      { id: "CVE-2023-5678", sev: "High", pkg: "openssl", installed: "3.0.11", fixed: "3.0.12" },
      { id: "CVE-2023-38545", sev: "High", pkg: "curl", installed: "7.88.1", fixed: "8.4.0" },
      { id: "CVE-2023-44487", sev: "High", pkg: "nghttp2", installed: "1.52.0", fixed: "1.57.0" },
      { id: "CVE-2023-4863", sev: "Medium", pkg: "libwebp", installed: "1.2.4", fixed: "1.3.2" },
      { id: "CVE-2023-46218", sev: "Medium", pkg: "curl", installed: "7.88.1", fixed: "8.5.0" },
    ],
    logSample: `{
  "findingType": "PACKAGE_VULNERABILITY",
  "severity": "CRITICAL",
  "resource": { "type": "AWS_ECR_CONTAINER_IMAGE", "id": "shopping-flask:latest" },
  "packageVulnerabilityDetails": { "vulnerabilityId": "CVE-2023-49083" }
}`,
    relatedAssets: ["Inspector", "K3s Cluster"],
    actions: [
      {
        id: "vuln-rebuild",
        title: "취약 패키지 업그레이드 후 이미지 재빌드",
        desc: "6개 패키지를 수정 버전으로 올려 이미지를 다시 빌드하고 ECR 에 푸시합니다.",
        target: "Amazon ECR",
        executor: "CI 파이프라인 트리거 (빌드 후 스캔 자동 재실행)",
        risk: "Medium",
        rollback: "예 — 이전 이미지 태그로 되돌리기",
        policyKey: "image",
        policyAfter: "shopping-flask:latest (재빌드 진행 중)",
      },
      {
        id: "vuln-deploy",
        title: "K3s 롤링 배포",
        desc: "재빌드된 이미지를 K3s 클러스터에 무중단으로 배포합니다.",
        target: "K3s Cluster",
        executor: "Lambda Remediation → SSM",
        risk: "High",
        rollback: "예 — 이전 리비전으로 롤백",
        policyKey: "deploy",
        policyAfter: "새 이미지로 배포 완료",
      },
    ],
  },
}
