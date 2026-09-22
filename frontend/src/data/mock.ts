import type { ActionEvent, Severity, ScenarioCard, ServiceMetric } from "./types"

export const ACTION_EVENTS: ActionEvent[] = [
  {
    id: "sql",
    severity: "Critical",

    title: "SQL Injection 반복 요청 탐지",

    service: "AWS WAF / GuardDuty",
    asset: "Flask App Server",

    detectedAt: "2026.09.18 14:28",
    elapsed: "4분",

    status: "승인 대기",
    recommendation: "WAF 차단 규칙 강화 및 Flask 입력값 검증 점검",

    autoRemediation: true,

    highlightAssets: ["attacker", "igw", "shopWAF", "shopALB", "k3s", "flaskApp", "cwLogs"],

    attackPath: ["attacker", "igw", "shopWAF", "shopALB", "k3s", "flaskApp"],

    details: {
      attackerIP: "203.0.113.45",

      requestURL: "POST /api/products?id=1%27+OR+%271%27%3D%271",

      rule: "AWSManagedRulesSQLiRuleSet / SQLi_BODY",

      blocked: false,

      logs: `{
  "timestamp": "2026-09-18T14:28:03Z",
  "webaclId": "arn:aws:wafv2:ap-northeast-2:...:webacl/ShoppingWAF",
  "action": "ALLOW",
  "httpRequest": {
    "clientIp": "203.0.113.45",
    "country": "CN",
    "uri": "/api/products",
    "method": "POST",
    "args": "id=1' OR '1'='1"
  },
  "ruleGroupList": [{
    "ruleGroupId": "AWSManagedRulesSQLiRuleSet",
    "terminatingRule": null,
    "nonTerminatingMatchingRules": [{
      "ruleId": "SQLi_BODY",
      "action": "COUNT"
    }]
  }]
}`,
    },
  },

  {
    id: "vuln",
    severity: "High",

    title: "ECR 이미지 취약 패키지 발견",

    service: "Inspector",
    asset: "Amazon ECR / K3s",

    detectedAt: "2026.09.18 14:10",
    elapsed: "22분",

    status: "검토 필요",
    recommendation: "취약 패키지 업그레이드 후 이미지 재빌드 및 배포",

    autoRemediation: false,

    highlightAssets: ["ecr", "inspector", "securityHub", "k3s"],

    attackPath: [],

    details: {
      rule: "CVE-2023-49083 (cryptography 41.0.0, CVSS 9.1)",

      logs: `{
  "findingType": "PACKAGE_VULNERABILITY",
  "severity": "HIGH",
  "resource": {
    "type": "AWS_ECR_CONTAINER_IMAGE",
    "id": "arn:aws:ecr:ap-northeast-2:...:repository/shopping-app"
  },
  "packageVulnerabilityDetails": {
    "vulnerabilityId": "CVE-2023-49083",
    "vulnerablePackages": [{
      "name": "cryptography",
      "installedVersion": "41.0.0",
      "fixedInVersion": "41.0.7"
    }]
  }
}`,
    },
  },

  {
    id: "s3",
    severity: "High",

    title: "S3 버킷 외부 공개 설정 탐지",

    service: "Access Analyzer",
    asset: "S3 security-logs",

    detectedAt: "2026.09.18 13:55",
    elapsed: "37분",

    status: "검토 필요",
    recommendation: "Block Public Access 활성화 및 ACL 정책 즉시 수정",

    autoRemediation: true,

    highlightAssets: ["accessAnalyzer", "securityHub", "s3Logs"],

    attackPath: [],

    details: {
      rule: "Access Analyzer: ExternallyShared",

      logs: `{
  "findingType": "ExternalAccess",
  "resourceType": "AWS::S3::Bucket",
  "resource": "arn:aws:s3:::security-results-prod",
  "condition": {
    "aws:PrincipalOrgID": null
  },
  "isPublic": true,
  "action": ["s3:GetObject", "s3:ListBucket"]
}`,
    },
  },
]

export const DETECT_HISTORY = [
  {
    id: 1,
    time: "14:28",
    sev: "Critical" as Severity,
    event: "SQL Injection 반복 요청",
    service: "AWS WAF",
    asset: "Flask App",
    ip: "203.0.113.45",
    blocked: "부분",
    status: "조치 대기",
  },

  {
    id: 2,
    time: "14:22",
    sev: "Medium" as Severity,
    event: "디렉터리 스캔 탐지",
    service: "AWS WAF",
    asset: "K3s nginx",
    ip: "198.51.100.23",
    blocked: "차단",
    status: "자동 완료",
  },

  {
    id: 3,
    time: "14:10",
    sev: "High" as Severity,
    event: "ECR 취약 패키지",
    service: "Inspector",
    asset: "ECR / K3s",
    ip: "-",
    blocked: "-",
    status: "검토 필요",
  },

  {
    id: 4,
    time: "13:55",
    sev: "High" as Severity,
    event: "S3 외부 공개 설정",
    service: "Access Analyzer",
    asset: "S3 Bucket",
    ip: "-",
    blocked: "-",
    status: "검토 필요",
  },

  {
    id: 5,
    time: "13:40",
    sev: "Medium" as Severity,
    event: "로그인 무차별 대입",
    service: "AWS WAF",
    asset: "Dashboard EC2",
    ip: "45.33.32.156",
    blocked: "차단",
    status: "자동 완료",
  },

  {
    id: 6,
    time: "13:20",
    sev: "Low" as Severity,
    event: "XSS 요청 탐지",
    service: "AWS WAF",
    asset: "Shopping ALB",
    ip: "104.21.0.98",
    blocked: "차단",
    status: "자동 완료",
  },

  {
    id: 7,
    time: "12:45",
    sev: "Medium" as Severity,
    event: "포트 스캔 탐지",
    service: "GuardDuty",
    asset: "K3s EC2",
    ip: "5.188.210.45",
    blocked: "차단",
    status: "자동 완료",
  },
]

export const REMEDIATION_HISTORY = [
  {
    id: 1,
    time: "14:22",
    event: "디렉터리 스캔 자동 차단",
    asset: "WAF / K3s",
    method: "자동",
    approver: "시스템",
    result: "성공",
    completedAt: "14:22:08",
  },

  {
    id: 2,
    time: "13:45",
    event: "무차별 대입 IP 차단",
    asset: "Dashboard EC2",
    method: "자동",
    approver: "시스템",
    result: "성공",
    completedAt: "13:45:12",
  },

  {
    id: 3,
    time: "13:20",
    event: "XSS 요청 WAF 차단",
    asset: "Shopping ALB",
    method: "자동",
    approver: "시스템",
    result: "성공",
    completedAt: "13:20:05",
  },

  {
    id: 4,
    time: "12:45",
    event: "포트 스캔 SG 강화",
    asset: "K3s EC2",
    method: "수동",
    approver: "김민준",
    result: "성공",
    completedAt: "13:02:30",
  },
]

export const SCENARIO_CARDS: ScenarioCard[] = [
  {
    id: "sql",
    type: "event",
    title: "SQL Injection",
    service: "WAF",
    highlightAssets: ["attacker", "igw", "shopWAF", "shopALB", "k3s", "flaskApp", "cwLogs"],
    attackPath: ["attacker", "igw", "shopWAF", "shopALB", "k3s", "flaskApp"],
    actionEventId: "sql",
  },

  {
    id: "xss",
    type: "event",
    title: "XSS",
    service: "WAF",
    highlightAssets: ["attacker", "igw", "shopWAF", "cwLogs"],
    attackPath: ["attacker", "igw", "shopWAF"],
  },

  {
    id: "dir",
    type: "traffic",
    title: "디렉터리 서치",
    service: "WAF Rate Rule",
    highlightAssets: ["attacker", "igw", "shopWAF", "shopALB", "k3s", "cwLogs"],
    attackPath: ["attacker", "igw", "shopWAF"],
  },

  {
    id: "brute",
    type: "traffic",
    title: "로그인 무차별대입",
    service: "WAF Rate Rule",
    highlightAssets: ["igw", "adminWAF", "dashALB", "dashEC2", "cwLogs"],
    attackPath: ["adminWAF"],
  },

  {
    id: "port",
    type: "anomaly",
    title: "Port Scan",
    service: "GuardDuty",
    highlightAssets: ["vpcFlow", "cwLogs", "guardDuty", "securityHub", "k3s"],
    attackPath: ["k3s"],
  },

  {
    id: "cred",
    type: "anomaly",
    title: "탈취 자격증명",
    service: "GuardDuty",
    highlightAssets: ["cloudTrail", "s3Logs", "guardDuty", "accessAnalyzer", "securityHub"],
    attackPath: [],
  },

  {
    id: "vuln",
    type: "vuln",
    title: "취약 컨테이너 이미지",
    service: "Inspector",
    highlightAssets: ["ecr", "inspector", "securityHub", "k3s"],
    attackPath: [],
    actionEventId: "vuln",
  },
]

export const SUGGESTED_QUESTIONS = [
  "이 이벤트를 요약해 줘",

  "왜 Critical인가요?",

  "관련 로그를 설명해 줘",

  "권장 조치가 무엇인가요?",

  "서비스 영향이 있나요?",

  "비슷한 탐지 이력을 찾아줘",
]

interface ChatResponse {
  text: string
  actions: string[]
}

export function getBotResponse(
  q: string,
  ev: ActionEvent | null,
): ChatResponse {
  if (!ev) {
    return {
      text: "분석할 이벤트를 먼저 선택해 주세요. 왼쪽 아키텍처 맵에서 자산을 클릭하거나 조치 필요 목록에서 이벤트를 선택하면 해당 컨텍스트로 질문에 답할 수 있습니다.",

      actions: [],
    }
  }

  if (q.includes("요약")) {
    if (ev.id === "sql")
      return {
        text: `203.0.113.45에서 /api/products 경로로 SQL Injection 패턴이 포함된 요청이 반복 발생했습니다. AWS WAF의 SQLi_BODY 규칙이 COUNT 모드로 탐지했으나 차단이 적용되지 않아 일부 요청이 Flask App Server까지 도달한 것으로 확인됩니다. 동일 IP의 추가 공격 가능성이 높으므로 즉각적인 차단 조치가 필요합니다.`,
        actions: [
          "관련 로그 보기",
          "공격 경로 강조",
          "권장 조치 보기",
          "조치 요청에 추가",
        ],
      }

    if (ev.id === "vuln")
      return {
        text: `ECR 리포지터리 shopping-app의 컨테이너 이미지에서 cryptography 41.0.0 패키지의 CVE-2023-49083 취약점이 발견됐습니다. CVSS 점수 9.1의 고위험 취약점으로, 수정 버전(41.0.7)으로 업그레이드 후 이미지를 재빌드하고 K3s 클러스터에 재배포해야 합니다.`,
        actions: ["관련 로그 보기", "권장 조치 보기", "조치 요청에 추가"],
      }

    return {
      text: `${ev.title} 이벤트가 ${ev.detectedAt}에 탐지됐습니다. 탐지 서비스: ${ev.service}, 영향 자산: ${ev.asset}. 현재 상태: ${ev.status}. 권장 조치를 확인하고 즉시 대응해 주세요.`,
      actions: ["관련 로그 보기", "권장 조치 보기"],
    }
  }

  if (q.includes("Critical") || q.includes("critical")) {
    return {
      text: `${ev.severity} 등급으로 분류된 이유는 실시간 공격 트래픽이 탐지됐고, 차단 규칙이 COUNT 모드로만 동작하여 실제 요청이 백엔드까지 전달됐기 때문입니다. 즉각적인 서비스 영향 가능성이 있어 최우선 대응이 필요합니다.`,
      actions: ["공격 경로 강조", "권장 조치 보기"],
    }
  }

  if (q.includes("로그")) {
    return {
      text: `WAF 로그에서 clientIp: ${ev.details.attackerIP ?? "N/A"}, action: ALLOW, 매칭 규칙: ${ev.details.rule ?? "N/A"}가 확인됩니다. 요청이 차단되지 않고 통과된 기록이 있어 즉각 WAF 규칙을 BLOCK 모드로 전환할 것을 권장합니다.`,
      actions: ["관련 로그 보기", "권장 조치 보기"],
    }
  }

  if (q.includes("권장") || q.includes("조치")) {
    return {
      text: `권장 조치: ${ev.recommendation}. Lambda Remediation을 통해 자동 조치가 가능하며, 고위험 조치의 경우 승인 후 실행됩니다. 조치 요청에 추가하면 담당자에게 알림이 전송됩니다.`,
      actions: ["권장 조치 보기", "조치 요청에 추가"],
    }
  }

  if (q.includes("서비스") || q.includes("영향")) {
    return {
      text: `현재 Flask App Server가 영향을 받고 있으며, 쇼핑몰 API(/api/products) 요청이 지연될 수 있습니다. WAF 차단 규칙 강화 시 일부 정상 요청도 임시 차단될 수 있어 사전 화이트리스트 검토가 필요합니다.`,
      actions: ["공격 경로 강조", "조치 요청에 추가"],
    }
  }

  if (q.includes("이력")) {
    return {
      text: `최근 7일간 동일 유형의 탐지 이력을 확인한 결과, 오늘 포함 3건의 유사 패턴이 탐지됐습니다. 탐지 이력 탭에서 전체 목록을 확인할 수 있습니다.`,
      actions: ["관련 로그 보기"],
    }
  }

  return {
    text: `선택된 이벤트(${ev.title})에 대한 분석입니다. 더 구체적인 질문을 입력하거나 위 추천 질문을 활용해 보세요.`,
    actions: [],
  }
}

export const SERVICE_METRICS: ServiceMetric[] = [
  {
    server: "k3s",
    displayName: "K3s / nginx",
    status: "healthy",
    cpuPercent: 18.4,
    memoryPercent: 41.2,
    requestCount: 842,
    avgLatencyMs: 63,
    errorRatePercent: 0.1,
    healthyTargets: 1,
    unhealthyTargets: 0,
    updatedAt: "-",
  },
  {
    server: "dashboard",
    displayName: "Dashboard",
    status: "healthy",
    cpuPercent: 12.7,
    memoryPercent: 38.6,
    requestCount: 96,
    avgLatencyMs: 41,
    errorRatePercent: 0,
    healthyTargets: 1,
    unhealthyTargets: 0,
    updatedAt: "-",
  },
  {
    server: "shop_app",
    displayName: "Shop App",
    status: "healthy",
    cpuPercent: 24.9,
    memoryPercent: 52.0,
    requestCount: null,
    avgLatencyMs: null,
    errorRatePercent: null,
    healthyTargets: null,
    unhealthyTargets: null,
    updatedAt: "-",
  },
  {
    server: "shop_db",
    displayName: "Shop MySQL",
    status: "healthy",
    cpuPercent: 9.3,
    memoryPercent: 61.5,
    requestCount: null,
    avgLatencyMs: null,
    errorRatePercent: null,
    healthyTargets: null,
    unhealthyTargets: null,
    updatedAt: "-",
  },
  {
    server: "security_db",
    displayName: "Security MySQL",
    status: "healthy",
    cpuPercent: 11.8,
    memoryPercent: 58.3,
    requestCount: null,
    avgLatencyMs: null,
    errorRatePercent: null,
    healthyTargets: null,
    unhealthyTargets: null,
    updatedAt: "-",
  },
]
