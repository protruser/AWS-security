import { ASSETS } from "./architecture"

// 리소스 배치와 영역 박스는 모두 이 고정 좌표계를 쓴다.
// 뷰는 이 좌표계를 균일하게 확대·축소해 아이콘과 선이 항상 맞물린다.
export const CANVAS = { width: 1310, height: 656 }

export interface Zone {
  id: string
  label: string
  badges?: string[]
  x: number
  y: number
  w: number
  h: number
  border: string
  ink: string
  fill: string
  dashed?: boolean
  // 라벨을 놓을 위치 (선이 지나가는 곳을 피하기 위해 나눠 둔다)
  labelAt?: "top-left" | "top-right" | "bottom-left"
}

// wonny-sec-terraform/network.tf · locals.tf 의 서브넷 구성 그대로.
export const ZONES: Zone[] = [
  {
    id: "cloud",
    label: "AWS Cloud",
    badges: ["ap-northeast-2"],
    x: 84,
    y: 14,
    w: 1214,
    h: 634,
    border: "#D0D5DD",
    ink: "#344054",
    fill: "#FFFFFF",
    labelAt: "bottom-left",
  },
  {
    id: "vpc",
    label: "VPC",
    badges: ["10.0.0.0/16", "wonny-sec-vpc"],
    x: 124,
    y: 44,
    w: 816,
    h: 474,
    border: "#667085",
    ink: "#344054",
    fill: "#FFFFFF",
    dashed: true,
    labelAt: "bottom-left",
  },
  {
    id: "public",
    label: "Public Subnet ×2",
    badges: ["10.0.10.0/24 · AZ-a", "10.0.20.0/24 · AZ-b"],
    x: 150,
    y: 72,
    w: 780,
    h: 134,
    border: "#86CFA0",
    ink: "#1E7A45",
    fill: "#F3FBF6",
    labelAt: "top-right",
  },
  {
    id: "service",
    label: "01-service",
    badges: ["10.0.1.0/24", "AZ-a", "Private"],
    x: 150,
    y: 224,
    w: 350,
    h: 118,
    border: "#A9C3F0",
    ink: "#2450A6",
    fill: "#F5F8FE",
  },
  {
    id: "shopdb",
    label: "03-shop-db",
    badges: ["10.0.3.0/24", "AZ-a", "Private"],
    x: 150,
    y: 356,
    w: 350,
    h: 134,
    border: "#A9C3F0",
    ink: "#2450A6",
    fill: "#F5F8FE",
  },
  {
    id: "dashboard",
    label: "02-dashboard",
    badges: ["10.0.2.0/24", "AZ-b", "Private"],
    x: 520,
    y: 224,
    w: 410,
    h: 118,
    border: "#A9C3F0",
    ink: "#2450A6",
    fill: "#F5F8FE",
  },
  {
    id: "secdb",
    label: "04-security-db",
    badges: ["10.0.4.0/24", "AZ-b", "Private"],
    x: 520,
    y: 356,
    w: 410,
    h: 134,
    border: "#A9C3F0",
    ink: "#2450A6",
    fill: "#F5F8FE",
  },
  {
    id: "storage",
    label: "이미지 · 암호화",
    x: 124,
    y: 530,
    w: 816,
    h: 106,
    border: "#98A2B3",
    ink: "#475467",
    fill: "#FAFAFA",
    dashed: true,
    labelAt: "top-left",
  },
  {
    id: "managed",
    label: "AWS 보안·모니터링 서비스",
    badges: ["Regional"],
    x: 960,
    y: 44,
    w: 338,
    h: 474,
    border: "#98A2B3",
    ink: "#344054",
    fill: "#FFFFFF",
    dashed: true,
    labelAt: "bottom-left",
  },
]

interface Point {
  x: number
  y: number
}
type Side = "top" | "right" | "bottom" | "left"
type Anchor = [string, Side, number?]

export type ConnectionKind = "shop" | "admin" | "security" | "log" | "attack"

export interface Connection {
  id: string
  kind: ConnectionKind
  assets: [string, string]
  points: Point[]
  color: string
  label?: string
  labelPos?: Point
}

// 흐름 선은 한 색으로 통일하고, 공격 경로만 빨간 점선으로 구분한다.
const REQUEST = "#2F6FEB"
const QUIET = "#98A2B3"
const colors: Record<ConnectionKind, string> = {
  shop: REQUEST,
  admin: REQUEST,
  security: QUIET,
  log: QUIET,
  attack: "#D92D20",
}

export const LEGEND: { kind: ConnectionKind; color: string; label: string }[] = [
  { kind: "shop", color: REQUEST, label: "요청 흐름" },
  { kind: "log", color: QUIET, label: "탐지·로그" },
  { kind: "attack", color: colors.attack, label: "공격 경로" },
]

// 선 끝과 아이콘 사이에 6 단위를 둬서 화살촉이 테두리를 침범하지 않게 한다.
function anchor([id, side, offset = 0.5]: Anchor): Point {
  const a = ASSETS.find((asset) => asset.id === id)
  if (!a) throw new Error(`Unknown architecture resource: ${id}`)
  if (side === "top") return { x: a.x + a.w * offset, y: a.y - 6 }
  if (side === "bottom") return { x: a.x + a.w * offset, y: a.y + a.h + 6 }
  if (side === "left") return { x: a.x - 6, y: a.y + a.h * offset }
  return { x: a.x + a.w + 6, y: a.y + a.h * offset }
}

function connect(
  id: string,
  from: Anchor,
  to: Anchor,
  kind: ConnectionKind,
  via: [number, number][] = [],
  label?: string,
  labelAt?: [number, number],
): Connection {
  return {
    id,
    kind,
    assets: [from[0], to[0]],
    color: colors[kind],
    points: [anchor(from), ...via.map(([x, y]) => ({ x, y })), anchor(to)],
    label,
    labelPos: labelAt ? { x: labelAt[0], y: labelAt[1] } : undefined,
  }
}

// 연결은 wonny-sec-terraform/security_groups.tf · alb_waf.tf · security_services.tf 를 따른다.
export const CONNECTIONS: Connection[] = [
  // 인터넷 → IGW
  connect("attacker-igw", ["attacker", "right"], ["igw", "left"], "attack", [
    [78, 90],
    [78, 134],
  ]),
  connect("user-igw", ["user", "right"], ["igw", "left"], "shop", [
    [78, 190],
    [78, 134],
  ]),
  connect("igw-shopwaf", ["igw", "right"], ["shopWAF", "left"], "shop"),
  connect(
    "igw-adminwaf",
    ["igw", "bottom", 0.35],
    ["adminWAF", "left"],
    "admin",
    [
      [114, 214],
      [516, 214],
      [516, 134],
    ],
  ),

  // WAF → ALB
  connect("shopwaf-alb", ["shopWAF", "right"], ["shopALB", "left"], "shop"),
  connect(
    "adminwaf-alb",
    ["adminWAF", "right"],
    ["dashALB", "left"],
    "admin",
    [],
    "허용 IP만",
    [641, 134],
  ),

  // ALB → EC2 (security_groups.tf)
  connect(
    "shopalb-k3s",
    ["shopALB", "bottom"],
    ["k3s", "top"],
    "shop",
    [],
    "NodePort 30443",
    [342, 215],
  ),
  connect(
    "dashalb-dash",
    ["dashALB", "bottom"],
    ["dashEC2", "top"],
    "admin",
    [],
    "HTTPS 8443",
    [716, 215],
  ),

  // 쇼핑몰 서비스 내부
  connect(
    "k3s-flask",
    ["k3s", "bottom"],
    ["flaskApp", "top"],
    "shop",
    [],
    "HTTPS 8443",
    [342, 349],
  ),
  connect("flask-mysql", ["flaskApp", "right"], ["shopMySQL", "left"], "shop"),

  // 대시보드 → 보안 결과 DB
  connect(
    "dash-secdb",
    ["dashEC2", "bottom"],
    ["secMySQL", "top"],
    "security",
    [],
    "TCP 3306",
    [716, 349],
  ),

  // 로그 수집
  connect("vpcflow-cw", ["vpcFlow", "top"], ["cwLogs", "bottom"], "log"),
  connect("cloudtrail-s3", ["cloudTrail", "bottom"], ["s3Logs", "top"], "log"),
  connect(
    "shopwaf-cw",
    ["shopWAF", "top"],
    ["cwLogs", "top"],
    "log",
    [
      [222, 58],
      [1006, 58],
    ],
  ),
  connect(
    "adminwaf-cw",
    ["adminWAF", "top"],
    ["cwLogs", "top"],
    "log",
    [
      [566, 58],
      [1006, 58],
    ],
  ),

  // 탐지 → Security Hub → EventBridge → SNS
  connect(
    "gd-hub",
    ["guardDuty", "right"],
    ["securityHub", "left"],
    "security",
    [
      [1181, 106],
      [1181, 216],
    ],
  ),
  connect("insp-hub", ["inspector", "right"], ["securityHub", "left"], "security"),
  connect(
    "aa-hub",
    ["accessAnalyzer", "right"],
    ["securityHub", "left"],
    "security",
    [
      [1181, 326],
      [1181, 216],
    ],
  ),
  connect("hub-eb", ["securityHub", "bottom"], ["eventBridge", "top"], "security"),
  connect("eb-sns", ["eventBridge", "bottom"], ["sns", "top"], "security"),
]
