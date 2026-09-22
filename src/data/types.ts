export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info"

export type AssetStatus = "normal" | "warning" | "danger" | "critical" | "acting" | "disconnected"

export type RightTab = "action" | "detect" | "history"

export interface ActionEvent {
  id: string

  severity: Severity

  title: string

  service: string

  scenarioType?: string

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
