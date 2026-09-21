import type { ScenarioCard } from "./types"

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
