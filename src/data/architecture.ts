import type { AssetStatus } from "./types"
import { SCENARIO_CARDS } from "./staticContent"

// 이 파일의 구성은 wonny-sec-terraform/ 의 코드를 그대로 따른다.
// (Lambda · Macie 는 테라폼에 없으므로 그리지 않는다.)

export type IconName =
  | "attacker"
  | "user"
  | "igw"
  | "waf"
  | "alb"
  | "nat"
  | "ec2"
  | "k3s"
  | "app"
  | "db"
  | "ecr"
  | "secrets"
  | "kms"
  | "cwlogs"
  | "flowlogs"
  | "cloudtrail"
  | "bucket"
  | "guardduty"
  | "inspector"
  | "analyzer"
  | "securityhub"
  | "eventbridge"
  | "sns"

// 아이콘 타일은 항상 ICON x ICON. 라벨은 타일 아래에 붙는다.
export const ICON = 52

export interface AssetDef {
  id: string

  // 아이콘 타일의 좌상단
  x: number
  y: number
  w: number
  h: number

  label: string

  // 라벨 아래 회색 한 줄 (짧게)
  sub?: string

  // 마우스를 올렸을 때 보이는 설명
  detail?: string

  icon: IconName

  defaultStatus: AssetStatus
}

function node(
  id: string,
  x: number,
  y: number,
  icon: IconName,
  label: string,
  sub?: string,
  detail?: string,
): AssetDef {
  return {
    id,
    x,
    y,
    w: ICON,
    h: ICON,
    label,
    sub,
    detail,
    icon,
    defaultStatus: "normal",
  }
}

export const ASSETS: AssetDef[] = [
  // 인터넷 쪽
  node("attacker", 8, 64, "attacker", "공격자 서버", undefined, "외부 공격 출발지"),
  node("user", 8, 164, "user", "일반 사용자", undefined, "쇼핑몰 이용 고객"),
  node("igw", 96, 108, "igw", "Internet", "Gateway", "aws_internet_gateway.main"),

  // Public Subnet ×2 (ALB 는 두 AZ 에 걸쳐 있음)
  node("shopWAF", 196, 108, "waf", "AWS WAF", "쇼핑몰", "shop-waf · Common · SQLi · Rate Limit(IP당 5분 1000건, Block)"),
  node("shopALB", 316, 108, "alb", "ALB", "쇼핑몰", "shop-alb · 0.0.0.0/0 허용 · → 30443"),
  node("adminWAF", 540, 108, "waf", "AWS WAF", "관리자", "admin-waf · Common · Admin Rate Limit(IP당 5분 300건, Block)"),
  node("dashALB", 690, 108, "alb", "ALB", "관리자", "admin-alb · admin_cidrs 만 허용 · → 8443"),
  node("nat", 810, 108, "nat", "NAT", "Gateway", "public_a 에 위치 · Private 서브넷의 아웃바운드"),

  // 01-service / 03-shop-db
  node("k3s", 316, 258, "k3s", "K3s EC2", undefined, "01-k3s-nginx · nginx Reverse Proxy · NodePort 30443 수신"),
  node("flaskApp", 316, 392, "app", "Flask App", "EC2", "03-shop-app · nginx 에서 8443 수신"),
  node("shopMySQL", 416, 392, "db", "MySQL", "EC2 · 쇼핑몰", "03-shop-mysql · 3306 (Flask 만 허용)"),

  // 02-dashboard / 04-security-db
  node("dashEC2", 690, 258, "ec2", "Dashboard EC2", undefined, "02-dashboard · admin ALB 에서 8443 수신"),
  node("secMySQL", 690, 392, "db", "MySQL", "EC2 · 보안 결과", "04-security-mysql · 3306 (Dashboard · Lambda SG 허용)"),

  // 이미지 · 암호화
  node("ecr", 250, 556, "ecr", "ECR", "repo 3개", "nginx · shop-app · dashboard (push 시 스캔)"),
  node("secrets", 450, 556, "secrets", "Secrets", "Manager", "shop-db · security-db 계정 정보"),
  node("kms", 650, 556, "kms", "KMS", "키 2개", "shop 키 · security 키 (자동 회전)"),

  // 로그
  node("cwLogs", 980, 80, "cwlogs", "CloudWatch", "Logs", "WAF 로그(shop·admin) · VPC Flow 로그, 30일 보관"),
  node("vpcFlow", 980, 190, "flowlogs", "VPC Flow", "Logs", "traffic_type ALL → CloudWatch Logs"),
  node("cloudTrail", 980, 300, "cloudtrail", "CloudTrail", undefined, "wonny-sec-trail · 로그 파일 검증"),
  node("s3Logs", 980, 410, "bucket", "S3", "security-logs", "KMS 암호화 · 버전관리 · 퍼블릭 차단"),

  // 탐지 · 알림
  node("guardDuty", 1100, 80, "guardduty", "GuardDuty"),
  node("inspector", 1100, 190, "inspector", "Inspector", "EC2 · ECR"),
  node("accessAnalyzer", 1100, 300, "analyzer", "Access", "Analyzer"),
  node("securityHub", 1210, 190, "securityhub", "Security Hub"),
  node("eventBridge", 1210, 310, "eventbridge", "EventBridge", "Findings 규칙"),
  node("sns", 1210, 420, "sns", "SNS", "보안 알림", "KMS 암호화 · 이메일 구독"),
]

export const SCENARIO_SHORT: Record<string, string> = {
  sql: "SQLi",
  xss: "XSS",
  dir: "디렉터리",
  brute: "무차별",
  port: "포트스캔",
  cred: "자격증명",
  vuln: "취약이미지",
}

// 공격 시나리오 7개 중 이 자산이 등장하는 것들
export function scenariosForAsset(assetId: string): string[] {
  return SCENARIO_CARDS.filter((c) => c.highlightAssets.includes(assetId)).map(
    (c) => c.id,
  )
}

// 지금 "비상"인 자산. 연결된 이벤트를 승인하거나 시나리오 조치를 모두 마치면 해제된다.
export interface AlertRule {
  assetId: string
  level: "critical" | "warning"
  reason: string
  clearedByEvent?: string
  clearedByScenario?: string
}

export const ALERT_RULES: AlertRule[] = [
  {
    assetId: "flaskApp",
    level: "critical",
    reason: "SQL Injection 요청 1건이 WAF 를 통과해 도달",
    clearedByEvent: "sql",
    clearedByScenario: "sql",
  },
  {
    assetId: "guardDuty",
    level: "critical",
    reason: "퇴사자 IAM 키가 미사용 리전에서 호출됨",
    clearedByScenario: "cred",
  },
  {
    assetId: "k3s",
    level: "warning",
    reason: "취약 컨테이너 이미지 운영 중 · 포트 스캔 대상",
    clearedByEvent: "vuln",
  },
  {
    assetId: "s3Logs",
    level: "warning",
    reason: "S3 버킷 외부 공개 설정 탐지",
    clearedByEvent: "s3",
  },
  {
    assetId: "adminWAF",
    level: "warning",
    reason: "로그인 무차별대입 임계치 초과 · 차단 적용 중",
    clearedByScenario: "brute",
  },
]
