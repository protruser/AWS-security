export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info"

export type AssetStatus = "normal" | "warning" | "danger" | "critical" | "acting" | "disconnected"

export type RightTab = "action" | "detect" | "history"

export interface ActionEvent {
  id: string

  severity: Severity

  title: string

  service: string

  asset: string

  detectedAt: string

  elapsed: string

  status: string

  recommendation: string

  autoRemediation: boolean

  highlightAssets: string[]

  attackPath: string[]

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


export interface DetectHistoryItem {
  id: string | number
  time: string
  sev: Severity
  event: string
  service: string
  asset: string
  ip: string
  blocked: string
  status: string
}

export interface RemediationHistoryItem {
  id: string | number
  time: string
  event: string
  asset: string
  method: string
  approver: string
  result: string
  completedAt: string
}

export type ServiceStatus = "healthy" | "degraded" | "unhealthy" | "unknown"

// 보안 시나리오가 아니라 인프라 상태(CPU/메모리/지연시간/처리량/에러율/서비스 상태).
// Lambda C가 CloudWatch에서 5분마다 모아 서버 1대당 최신 값 1행으로 저장한다.
export interface ServiceMetric {
  server: string
  displayName: string
  status: ServiceStatus
  cpuPercent: number | null
  memoryPercent: number | null
  requestCount: number | null
  avgLatencyMs: number | null
  errorRatePercent: number | null
  healthyTargets: number | null
  unhealthyTargets: number | null
  updatedAt: string
}

export interface DashboardApiResponse {
  events: ActionEvent[]
  detectHistory: DetectHistoryItem[]
  remediationHistory: RemediationHistoryItem[]
  serviceMetrics: ServiceMetric[]
}

export interface AuthUser {
  username: string
  role: string
  team: string
}
