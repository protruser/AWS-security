// 공격 시뮬레이션(모의) 데이터. 실제 트래픽은 보내지 않는다.
// 탐지 지점은 wonny-sec-terraform/ 의 WAF 규칙과 보안 서비스 구성을 따른다.

export interface LabScenario {
  id: string
  // 실제 재현할 때 쓸 도구 (이름만)
  tools: string[]
  // 탐지를 기대하는 AWS 서비스와 근거
  detector: string
  signal: string
  // 모의 실행 단계
  steps: string[]
}

export const LAB_SCENARIOS: LabScenario[] = [
  {
    id: "sql",
    tools: ["curl", "sqlmap"],
    detector: "AWS WAF · SQLi 규칙",
    signal: "AWSManagedRulesSQLiRuleSet 매칭 → 차단, WAF 로그(CloudWatch)에 기록",
    steps: [
      "공격자 → 쇼핑몰 WAF 로 SQLi 패턴 요청 전송",
      "WAF SQLi 규칙 평가",
      "요청 차단 · WAF 로그 기록",
      "대시보드에 SQL Injection 탐지 반영",
    ],
  },
  {
    id: "xss",
    tools: ["curl"],
    detector: "AWS WAF · Common 규칙",
    signal: "AWSManagedRulesCommonRuleSet 의 XSS 항목 매칭 → 차단",
    steps: [
      "공격자 → 쇼핑몰 WAF 로 스크립트 삽입 요청 전송",
      "WAF Common 규칙 평가",
      "요청 차단 · WAF 로그 기록",
      "대시보드에 XSS 탐지 반영",
    ],
  },
  {
    id: "dir",
    tools: ["gobuster", "ffuf"],
    detector: "AWS WAF · Rate Limit",
    signal: "IP당 5분 1000건 초과 시 Block (shop_rate_limit)",
    steps: [
      "공격자 → 쇼핑몰 WAF 로 존재하지 않는 경로를 연속 요청",
      "404 응답 급증 · 요청 수 누적",
      "Rate Limit 임계치 도달 시 차단",
      "대시보드에 디렉터리 서치 탐지 반영",
    ],
  },
  {
    id: "brute",
    tools: ["hydra"],
    detector: "AWS WAF · Admin Rate Limit",
    signal: "IP당 5분 300건 초과 시 Block (admin_rate_limit)",
    steps: [
      "허용 IP 에서 관리자 로그인 반복 시도",
      "실패 응답 급증 · 요청 수 누적",
      "Admin Rate Limit 도달 시 차단",
      "대시보드에 로그인 무차별대입 탐지 반영",
    ],
  },
  {
    id: "port",
    tools: ["nmap"],
    detector: "GuardDuty · VPC Flow Logs",
    signal: "Recon:EC2/Portscan finding → Security Hub → EventBridge → SNS",
    steps: [
      "대상 EC2 를 향해 다수 포트 접속 시도",
      "VPC Flow Logs 에 거절된 접속 기록",
      "GuardDuty 가 Portscan finding 생성 (최대 15분)",
      "Security Hub 집계 후 대시보드 반영",
    ],
  },
  {
    id: "cred",
    tools: ["aws cli"],
    detector: "GuardDuty · CloudTrail",
    signal: "평소 쓰지 않는 리전에서의 IAM 호출 → CredentialAccess 계열 finding",
    steps: [
      "퇴사자 IAM 키로 미사용 리전에서 API 호출",
      "CloudTrail 이 호출 이력 기록",
      "GuardDuty 가 비정상 자격증명 사용 finding 생성",
      "Security Hub 집계 후 대시보드 반영",
    ],
  },
  {
    id: "vuln",
    tools: ["docker", "trivy"],
    detector: "Amazon Inspector · ECR",
    signal: "ECR push 시 스캔(scan_on_push) → CVE finding",
    steps: [
      "취약 패키지가 든 이미지를 ECR 에 push",
      "ECR 이 이미지 스캔 시작 (scan_on_push)",
      "Inspector 가 CVE finding 생성",
      "Security Hub 집계 후 대시보드 반영",
    ],
  },
]
