export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info"

export type AssetStatus = "normal" | "warning" | "danger" | "critical" | "acting" | "disconnected"

export type RightTab = "detect" | "action" | "requests" | "history"

export interface ActionEvent {
  id: string

  severity: Severity

  title: string

  service: string

  scenarioType?: string

  asset: string

  detectedAt: string

  elapsed: string

  // 같은 종류로 반복 감지된 것들을 서버가 최신 1건으로 합쳐서 내려준 것.
  // 2 이상이면 "N번 반복 감지됨"이라는 뜻 - 실제로는 이만큼의 이벤트가 있다.
  occurrenceCount?: number

  status: string

  recommendation: string

  autoRemediation: boolean
  remediationType?: "AUTO" | "MANUAL"

  highlightAssets: string[]

  attackPath: string[]

  // 실제 도달 판정(백엔드 services/attack_reach). 있으면 맵은 attackPath 대신 이것을 쓴다.
  reach?: EventReach | null

  details: {
    attackerIP?: string

    requestURL?: string

    rule?: string

    blocked?: boolean

    logs: string
  }
}

export interface ScenarioCard {
  id: string

  type: "event" | "traffic" | "anomaly" | "vuln"

  title: string

  service: string

  highlightAssets: string[]

  attackPath: string[]

  actionEventId?: string
}


export interface EventReach {
  stage: "S1" | "S2" | "S3" | "S4" | "C"
  confidence: "confirmed" | "fallback" | "uncertain"
  requests: number | null
  passed: number | null
  target: string | null
  // 로그로 확인된 도달 자산 / ALB 이후 추정 도달 자산
  confirmed: string[]
  estimated: string[]
  // 같은 (유형, IP) 묶음에서 판정에 쓴 이벤트 수
  grouped: number
}

export interface DetectHistoryItem {
  id: string | number
  time: string
  sev: Severity
  event: string
  scenarioType?: string
  service: string
  asset: string
  ip: string
  blocked: string
  status: string
  reach?: EventReach | null
}

export interface RemediationHistoryItem {
  id: string | number
  time: string
  event: string
  scenarioType?: string
  asset: string
  ip?: string | null
  method: string
  approver: string
  result: string
  completedAt: string
  occurrenceCount?: number
}

export interface DashboardApiResponse {
  events: ActionEvent[]
  detectHistory: DetectHistoryItem[]
  remediationHistory: RemediationHistoryItem[]
}

export interface NumericOverviewMetric {
  current: number | null
  series: number[]
  collectedAt: string | null
}

export interface HealthOverviewMetric {
  status: "NORMAL" | "WARNING" | "CRITICAL" | null
  healthy: number | null
  unhealthy: number | null
  collectedAt: string | null
}

export interface OverviewMetricsResponse {
  cpu: NumericOverviewMetric
  memory: NumericOverviewMetric
  latency: NumericOverviewMetric
  rps: NumericOverviewMetric
  errorRate: NumericOverviewMetric
  health: HealthOverviewMetric
}
