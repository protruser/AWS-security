import { useState } from "react"
import type { Severity } from "../data/types"
import { SeverityBadge } from "./common"
import { OperationalMetricsPanel } from "./OperationalMetricsPanel"

type LogSource = "waf" | "guardduty" | "inspector"
type RangePreset = "15m" | "1h" | "6h" | "24h" | "7d" | "custom"
type QueryState = "idle" | "loading" | "success" | "error"

interface SecurityLog {
  id: string
  service: string
  scenarioType: string
  severity: Severity
  title: string
  asset: string | null
  detectedAt: string
  status: string
  attackerIp: string | null
  requestUrl: string | null
  ruleName: string | null
  blocked: boolean | null
  blockResult: string | null
  recommendation: string | null
  autoRemediation: boolean
  highlightAssets: string[]
  attackPath: string[]
  logs: string | null
}

interface SearchFilters {
  scenarioType: string
  severity: string
  attackerIp: string
  asset: string
  action: string
  cve: string
}

interface QueryWindow {
  start: Date
  end: Date
}

interface ChartDatum {
  label: string
  value: number
  color?: string
}

const EMPTY_FILTERS: SearchFilters = {
  scenarioType: "",
  severity: "",
  attackerIp: "",
  asset: "",
  action: "",
  cve: "",
}

const SOURCES: { value: LogSource, label: string, description: string }[] = [
  { value: "waf", label: "WAF", description: "웹 공격 및 차단 로그" },
  { value: "guardduty", label: "GuardDuty", description: "위협 탐지 Finding" },
  { value: "inspector", label: "Inspector", description: "취약점 스캔 결과" },
]

const RANGES: { value: RangePreset, label: string }[] = [
  { value: "15m", label: "최근 15분" },
  { value: "1h", label: "최근 1시간" },
  { value: "6h", label: "최근 6시간" },
  { value: "24h", label: "최근 24시간" },
  { value: "7d", label: "최근 7일" },
  { value: "custom", label: "직접 설정" },
]

const SEVERITIES = ["Critical", "High", "Medium", "Low"]
const PRESET_MS: Record<Exclude<RangePreset, "custom">, number> = {
  "15m": 15 * 60 * 1000,
  "1h": 60 * 60 * 1000,
  "6h": 6 * 60 * 60 * 1000,
  "24h": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
}
const SCENARIO_LABELS: Record<string, string> = {
  sqli: "SQL Injection",
  xss: "XSS",
  dir: "Directory Scan",
  brute: "Brute Force",
  port: "Port Scan",
  cred: "Credential",
  vuln: "Vulnerability",
}
const SEVERITY_COLORS: Record<string, string> = {
  Critical: "#D92D20",
  High: "#F79009",
  Medium: "#EAB308",
  Low: "#1677FF",
}

function toDatetimeLocal(date: Date) {
  const pad = (value: number) => String(value).padStart(2, "0")
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`
}

function formatDetectedAt(value: string) {
  if (!value) return "-"
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return new Intl.DateTimeFormat("ko-KR", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date)
}

function parseLogJson(value: string | null): Record<string, unknown> | null {
  if (!value) return null
  try {
    const parsed: unknown = JSON.parse(value)
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : null
  } catch {
    return null
  }
}

function nestedUnknown(value: unknown, ...path: (string | number)[]) {
  let current: unknown = value
  for (const key of path) {
    if (typeof key === "number") {
      if (!Array.isArray(current)) return null
      current = current[key]
    } else {
      if (!current || typeof current !== "object" || Array.isArray(current))
        return null
      current = (current as Record<string, unknown>)[key]
    }
  }
  return current
}

function nestedValue(value: unknown, ...path: (string | number)[]) {
  const current = nestedUnknown(value, ...path)
  return typeof current === "string" || typeof current === "number"
    ? String(current)
    : null
}

function nestedRecord(value: unknown, ...path: (string | number)[]) {
  const current = nestedUnknown(value, ...path)
  return current && typeof current === "object" && !Array.isArray(current)
    ? current as Record<string, unknown>
    : null
}

function findingPayload(value: Record<string, unknown> | null) {
  return nestedRecord(value, "detail", "findings", 0) ??
    nestedRecord(value, "findings", 0) ?? value
}

function prettyLogs(value: string | null) {
  if (!value) return "-"
  try {
    return JSON.stringify(JSON.parse(value), null, 2)
  } catch {
    return value
  }
}

function findCve(log: SecurityLog) {
  const text = `${log.ruleName ?? ""} ${log.title} ${log.logs ?? ""}`
  return text.match(/CVE-\d{4}-\d{4,}/i)?.[0]?.toUpperCase() ?? "-"
}

function scenarioLabel(value: string) {
  return SCENARIO_LABELS[value.toLowerCase()] ?? value ?? "-"
}

function countMatching(logs: SecurityLog[], predicate: (log: SecurityLog) => boolean) {
  return logs.reduce((count, log) => count + (predicate(log) ? 1 : 0), 0)
}

function countBy(logs: SecurityLog[], getKey: (log: SecurityLog) => string) {
  const counts = new Map<string, number>()
  logs.forEach((log) => {
    const key = getKey(log) || "-"
    counts.set(key, (counts.get(key) ?? 0) + 1)
  })
  return counts
}

function bucketMilliseconds(range: RangePreset, window: QueryWindow) {
  if (range === "15m") return 60 * 1000
  if (range === "1h") return 5 * 60 * 1000
  if (range === "6h") return 30 * 60 * 1000
  if (range === "24h") return 60 * 60 * 1000
  if (range === "7d") return 24 * 60 * 60 * 1000

  const target = (window.end.getTime() - window.start.getTime()) / 24
  const candidates = [
    60 * 1000,
    5 * 60 * 1000,
    15 * 60 * 1000,
    30 * 60 * 1000,
    60 * 60 * 1000,
    3 * 60 * 60 * 1000,
    6 * 60 * 60 * 1000,
    12 * 60 * 60 * 1000,
    24 * 60 * 60 * 1000,
    7 * 24 * 60 * 60 * 1000,
  ]
  const matched = candidates.find((candidate) => candidate >= target)
  if (matched) return matched
  const week = 7 * 24 * 60 * 60 * 1000
  return Math.ceil(target / week) * week
}

function timeSeries(logs: SecurityLog[], range: RangePreset, window: QueryWindow) {
  const bucketMs = bucketMilliseconds(range, window)
  const startMs = window.start.getTime()
  const endMs = window.end.getTime()
  const bucketCount = Math.max(1, Math.ceil((endMs - startMs) / bucketMs))
  const counts = Array.from({ length: bucketCount }, () => 0)

  logs.forEach((log) => {
    const detectedMs = new Date(log.detectedAt).getTime()
    if (Number.isNaN(detectedMs) || detectedMs < startMs || detectedMs > endMs) return
    const index = Math.min(bucketCount - 1, Math.floor((detectedMs - startMs) / bucketMs))
    counts[index] += 1
  })

  return counts.map((value, index) => {
    const date = new Date(startMs + index * bucketMs)
    const label = bucketMs >= 24 * 60 * 60 * 1000
      ? `${date.getMonth() + 1}/${date.getDate()}`
      : `${String(date.getHours()).padStart(2, "0")}:${String(date.getMinutes()).padStart(2, "0")}`
    return { label, value }
  })
}

function SummaryCards({ source, logs }: { source: LogSource, logs: SecurityLog[] }) {
  const items = source === "waf"
    ? [
        { label: "총 탐지", value: logs.length, color: "#101828" },
        { label: "BLOCK", value: countMatching(logs, (log) => log.blocked === true), color: "#16A34A" },
        { label: "ALLOW", value: countMatching(logs, (log) => log.blocked === false), color: "#D92D20" },
      ]
    : [
        { label: source === "inspector" ? "총 Finding" : "총 탐지", value: logs.length, color: "#101828" },
        { label: "Critical", value: countMatching(logs, (log) => log.severity === "Critical"), color: "#D92D20" },
        { label: "High", value: countMatching(logs, (log) => log.severity === "High"), color: "#F79009" },
        { label: "Medium", value: countMatching(logs, (log) => log.severity === "Medium"), color: "#EAB308" },
      ]

  return (
    <div className={`grid gap-2 ${items.length === 3 ? "grid-cols-3" : "grid-cols-2 lg:grid-cols-4"}`}>
      {items.map((item) => (
        <div key={item.label} className="rounded-xl border border-[#EAECF0] bg-[#FAFAFA] px-4 py-3">
          <p className="text-[10px] text-[#667085]">{item.label}</p>
          <p className="text-[22px] font-bold leading-tight mt-1" style={{ color: item.color }}>{item.value}</p>
        </div>
      ))}
    </div>
  )
}

function LineChart({ title, data }: { title: string, data: ChartDatum[] }) {
  const width = 720
  const height = 180
  const padding = { left: 34, right: 16, top: 16, bottom: 28 }
  const chartWidth = width - padding.left - padding.right
  const chartHeight = height - padding.top - padding.bottom
  const maxValue = Math.max(1, ...data.map((item) => item.value))
  const points = data.map((item, index) => {
    const x = padding.left + (data.length === 1 ? chartWidth / 2 : index * chartWidth / (data.length - 1))
    const y = padding.top + chartHeight - item.value / maxValue * chartHeight
    return { ...item, x, y }
  })
  const labelIndexes = Array.from(new Set([0, Math.floor((data.length - 1) / 2), data.length - 1]))

  return (
    <div className="rounded-xl border border-[#EAECF0] p-4">
      <p className="text-xs font-bold text-[#101828] mb-2">{title}</p>
      <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-[180px]" role="img" aria-label={title}>
        {[0, 0.5, 1].map((ratio) => {
          const y = padding.top + chartHeight * ratio
          return <line key={ratio} x1={padding.left} x2={width - padding.right} y1={y} y2={y} stroke="#EAECF0" strokeWidth="1" />
        })}
        <polyline fill="none" stroke="#101828" strokeWidth="2.5" strokeLinejoin="round" strokeLinecap="round" points={points.map((point) => `${point.x},${point.y}`).join(" ")} />
        {points.map((point, index) => (
          <circle key={`${point.label}-${index}`} cx={point.x} cy={point.y} r="3" fill="#101828"><title>{`${point.label}: ${point.value}건`}</title></circle>
        ))}
        <text x="4" y={padding.top + 4} fontSize="9" fill="#667085">{maxValue}</text>
        <text x="12" y={padding.top + chartHeight + 3} fontSize="9" fill="#667085">0</text>
        {labelIndexes.map((index) => points[index] && (
          <text key={index} x={points[index].x} y={height - 7} textAnchor="middle" fontSize="9" fill="#667085">{points[index].label}</text>
        ))}
      </svg>
    </div>
  )
}

function BarChart({ title, data }: { title: string, data: ChartDatum[] }) {
  const maxValue = Math.max(1, ...data.map((item) => item.value))
  return (
    <div className="rounded-xl border border-[#EAECF0] p-4">
      <p className="text-xs font-bold text-[#101828] mb-3">{title}</p>
      <div className="space-y-3">
        {data.map((item) => (
          <div key={item.label}>
            <div className="flex items-center justify-between gap-3 text-[10px] mb-1">
              <span className="font-medium text-[#475467] truncate">{item.label}</span>
              <span className="font-bold text-[#101828]">{item.value}</span>
            </div>
            <div className="h-2 rounded-full bg-[#F2F4F7] overflow-hidden">
              <div className="h-full rounded-full transition-[width] duration-300" style={{ width: `${item.value / maxValue * 100}%`, backgroundColor: item.color ?? "#475467" }} />
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function MonitoringAnalytics({ source, range, window, logs }: { source: LogSource, range: RangePreset, window: QueryWindow, logs: SecurityLog[] }) {
  const trend = timeSeries(logs, range, window)
  const scenarioCounts = countBy(logs, (log) => scenarioLabel(log.scenarioType))
  const severityCounts = countBy(logs, (log) => log.severity)
  const resourceCounts = [...countBy(logs, (log) => log.asset ?? "-").entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([label, value]) => ({ label, value }))
  const scenarioData = [...scenarioCounts.entries()].map(([label, value]) => ({ label, value }))
  const severityData = SEVERITIES.map((label) => ({ label, value: severityCounts.get(label) ?? 0, color: SEVERITY_COLORS[label] }))

  return (
    <div className="p-4 space-y-3 border-b border-[#EAECF0]">
      <SummaryCards source={source} logs={logs} />
      <LineChart title={source === "waf" ? "시간대별 공격 탐지 건수" : "시간대별 Finding 발생 건수"} data={trend} />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        {source === "waf" ? (
          <>
            <BarChart title="공격 유형별 탐지 건수" data={scenarioData} />
            <BarChart title="BLOCK / ALLOW 비교" data={[
              { label: "BLOCK", value: countMatching(logs, (log) => log.blocked === true), color: "#16A34A" },
              { label: "ALLOW", value: countMatching(logs, (log) => log.blocked === false), color: "#D92D20" },
            ]} />
          </>
        ) : source === "guardduty" ? (
          <>
            <BarChart title="Severity별 Finding 수" data={severityData} />
            <BarChart title="Finding 유형별 발생 건수" data={scenarioData} />
          </>
        ) : (
          <>
            <BarChart title="Severity별 취약점 수" data={severityData} />
            <BarChart title="리소스별 취약점 수" data={resourceCounts} />
          </>
        )}
      </div>
    </div>
  )
}

function DetailField({ label, value }: { label: string, value: unknown }) {
  if (value === null || value === undefined || value === "") return null
  return (
    <div className="min-w-0">
      <dt className="text-[9px] font-semibold text-[#98A2B3] uppercase tracking-wide">
        {label}
      </dt>
      <dd className="text-[11px] text-[#344054] mt-0.5 break-words">
        {String(value)}
      </dd>
    </div>
  )
}

function LogDetail({ log, source }: { log: SecurityLog, source: LogSource }) {
  const parsedLogs = parseLogJson(log.logs)
  const finding = findingPayload(parsedLogs)
  const method =
    nestedValue(parsedLogs, "httpRequest", "method") ??
    nestedValue(parsedLogs, "method")
  const uri =
    log.requestUrl ??
    nestedValue(parsedLogs, "httpRequest", "uri") ??
    nestedValue(parsedLogs, "uri")
  const action =
    nestedValue(parsedLogs, "action") ??
    (log.blocked === null
      ? log.blockResult ?? "-"
      : log.blocked
        ? "BLOCK"
        : "ALLOW")
  const findingType =
    nestedValue(finding, "Types", 0) ??
    nestedValue(finding, "Type") ??
    scenarioLabel(log.scenarioType)
  const findingDescription = nestedValue(finding, "Description") ?? log.title
  const findingResource =
    nestedValue(finding, "Resources", 0, "Id") ?? log.asset ?? "-"
  const inspectorImage =
    nestedValue(finding, "Resources", 0, "Details", "AwsEcrContainerImage", "RepositoryName") ??
    nestedValue(finding, "Resources", 0, "Details", "AwsEcrContainerImage", "ImageHash")
  const vulnerablePackage =
    nestedValue(finding, "Vulnerabilities", 0, "VulnerablePackages", 0, "Name")
  const currentVersion =
    nestedValue(finding, "Vulnerabilities", 0, "VulnerablePackages", 0, "Version") ??
    nestedValue(finding, "Vulnerabilities", 0, "VulnerablePackages", 0, "VersionInUse")
  const fixedVersion =
    nestedValue(finding, "Vulnerabilities", 0, "VulnerablePackages", 0, "FixedInVersion")

  return (
    <div className="bg-[#F8F9FB] border-t border-[#EAECF0] px-4 py-4 space-y-4">
      <dl className="grid grid-cols-2 lg:grid-cols-4 gap-x-5 gap-y-3">
        {source === "waf" && (
          <>
            <DetailField
              label="탐지 시간"
              value={formatDetectedAt(log.detectedAt)}
            />
            <DetailField label="공격 유형" value={log.scenarioType} />
            <DetailField label="공격 IP" value={log.attackerIp ?? "-"} />
            <DetailField label="Method" value={method ?? "-"} />
            <DetailField label="URI" value={uri ?? "-"} />
            <DetailField label="Rule" value={log.ruleName ?? "-"} />
            <DetailField label="Action" value={action} />
            <DetailField
              label="BLOCK 여부"
              value={log.blocked === null ? "-" : log.blocked ? "예" : "아니요"}
            />
            <DetailField label="차단 결과" value={log.blockResult} />
          </>
        )}
        {source === "guardduty" && (
          <>
            <DetailField label="Finding Type" value={findingType} />
            <DetailField label="Severity" value={log.severity} />
            <DetailField
              label="공격 IP"
              value={
                log.attackerIp ??
                nestedValue(finding, "Network", "SourceIpV4") ??
                "-"
              }
            />
            <DetailField label="대상 자산" value={log.asset ?? findingResource} />
            <DetailField label="설명" value={findingDescription} />
            <DetailField
              label="탐지 시간"
              value={formatDetectedAt(log.detectedAt)}
            />
          </>
        )}
        {source === "inspector" && (
          <>
            <DetailField label="CVE" value={findCve(log)} />
            <DetailField label="Severity" value={log.severity} />
            <DetailField label="Finding Type" value={findingType} />
            <DetailField label="대상 리소스" value={findingResource} />
            <DetailField label="대상 이미지" value={inspectorImage} />
            <DetailField label="취약 패키지" value={vulnerablePackage} />
            <DetailField label="현재 버전" value={currentVersion} />
            <DetailField label="수정 버전" value={fixedVersion} />
            <DetailField
              label="탐지 시간"
              value={formatDetectedAt(log.detectedAt)}
            />
          </>
        )}
      </dl>

      <div className="border-t border-[#EAECF0] pt-3">
        <dl className="grid grid-cols-2 lg:grid-cols-4 gap-x-5 gap-y-3">
          <DetailField label="Title" value={log.title} />
          <DetailField label="Attacker IP" value={log.attackerIp} />
          <DetailField label="Request URL" value={log.requestUrl} />
          <DetailField label="Rule Name" value={log.ruleName} />
          <DetailField
            label="Blocked"
            value={
              log.blocked === null ? null : log.blocked ? "BLOCK" : "ALLOW"
            }
          />
          <DetailField label="Recommendation" value={log.recommendation} />
        </dl>
        {log.attackPath.length > 0 && (
          <div className="mt-3">
            <p className="text-[9px] font-semibold text-[#98A2B3] uppercase tracking-wide">
              Attack Path
            </p>
            <div className="flex flex-wrap items-center gap-1 mt-1">
              {log.attackPath.map((asset, index) => (
                <span key={`${asset}-${index}`} className="contents">
                  {index > 0 && (
                    <span className="text-[10px] text-[#98A2B3]">→</span>
                  )}
                  <span className="text-[10px] font-mono text-[#344054] bg-white border border-[#D0D5DD] rounded px-1.5 py-0.5">
                    {asset}
                  </span>
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {log.logs && (
        <details>
          <summary className="w-fit cursor-pointer text-[10px] font-semibold text-[#475467] hover:text-[#101828]">
            원본 데이터 보기
          </summary>
          <pre className="mt-2 max-h-[320px] overflow-auto whitespace-pre-wrap break-words bg-[#101828] text-[#EAECF0] rounded-xl p-3 text-[10px] leading-relaxed font-mono">
            {prettyLogs(log.logs)}
          </pre>
        </details>
      )}
    </div>
  )
}

function SecurityDataMonitoringContent({
  onUnauthorized,
}: {
  onUnauthorized: () => void
}) {
  const [source, setSource] = useState<LogSource | "">("")
  const [range, setRange] = useState<RangePreset | "">("")
  const [startAt, setStartAt] = useState("")
  const [endAt, setEndAt] = useState("")
  const [filters, setFilters] = useState<SearchFilters>(EMPTY_FILTERS)
  const [queryState, setQueryState] = useState<QueryState>("idle")
  const [validationError, setValidationError] = useState<string | null>(null)
  const [logs, setLogs] = useState<SecurityLog[]>([])
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [lastWindow, setLastWindow] = useState<QueryWindow | null>(null)

  const resetResults = () => {
    setLogs([])
    setExpandedId(null)
    setLastWindow(null)
    setQueryState("idle")
    setValidationError(null)
  }

  const selectSource = (nextSource: LogSource) => {
    setSource(nextSource)
    setRange("")
    setStartAt("")
    setEndAt("")
    setFilters(EMPTY_FILTERS)
    resetResults()
  }

  const selectRange = (nextRange: RangePreset) => {
    setRange(nextRange)
    setValidationError(null)
    setLogs([])
    setExpandedId(null)
    setQueryState("idle")
    if (nextRange === "custom" && (!startAt || !endAt)) {
      const end = new Date()
      const start = new Date(end.getTime() - 60 * 60 * 1000)
      setStartAt(toDatetimeLocal(start))
      setEndAt(toDatetimeLocal(end))
    }
  }

  const setFilter = (key: keyof SearchFilters, value: string) => {
    setFilters((current) => ({ ...current, [key]: value }))
  }

  const search = async () => {
    if (!source || !range) return
    setValidationError(null)

    const params = new URLSearchParams({ source })
    let queryWindow: QueryWindow
    if (range === "custom") {
      if (!startAt || !endAt) {
        setValidationError(
          "시작 날짜/시간과 종료 날짜/시간을 모두 입력해주세요.",
        )
        return
      }
      const start = new Date(startAt)
      const end = new Date(endAt)
      if (
        Number.isNaN(start.getTime()) ||
        Number.isNaN(end.getTime()) ||
        start.getTime() >= end.getTime()
      ) {
        setValidationError("시작 시간은 종료 시간보다 빨라야 합니다.")
        return
      }
      queryWindow = { start, end }
      params.set("start", startAt.length === 16 ? `${startAt}:00` : startAt)
      params.set("end", endAt.length === 16 ? `${endAt}:00` : endAt)
    } else {
      const end = new Date()
      queryWindow = {
        start: new Date(end.getTime() - PRESET_MS[range]),
        end,
      }
      params.set("range", range)
    }

    if (source === "waf") {
      if (filters.scenarioType)
        params.set("scenario_type", filters.scenarioType)
      if (filters.attackerIp)
        params.set("attacker_ip", filters.attackerIp.trim())
      if (filters.action) params.set("action", filters.action)
    } else if (source === "guardduty") {
      if (filters.scenarioType) params.set("finding_type", filters.scenarioType)
      if (filters.severity) params.set("severity", filters.severity)
      if (filters.attackerIp)
        params.set("attacker_ip", filters.attackerIp.trim())
      if (filters.asset) params.set("asset", filters.asset.trim())
    } else {
      if (filters.severity) params.set("severity", filters.severity)
      if (filters.cve) params.set("cve", filters.cve.trim())
      if (filters.asset) params.set("asset", filters.asset.trim())
    }

    setQueryState("loading")
    setExpandedId(null)
    try {
      const response = await fetch(`/api/logs?${params.toString()}`, {
        credentials: "include",
        headers: { Accept: "application/json" },
      })
      if (response.status === 401) {
        onUnauthorized()
        return
      }
      const data = (await response.json()) as {
        logs?: SecurityLog[]
        message?: string
      }
      if (!response.ok || !Array.isArray(data.logs)) {
        throw new Error(data.message || `Logs API ${response.status}`)
      }
      setLogs(data.logs)
      setLastWindow(queryWindow)
      setQueryState("success")
    } catch (error) {
      console.error("보안 로그를 불러오지 못했습니다.", error)
      setLogs([])
      setLastWindow(null)
      setQueryState("error")
    }
  }

  return (
    <div className="space-y-3">
      <section className="bg-white border border-[#EAECF0] rounded-2xl p-4">
        <div className="flex items-center gap-2 mb-3">
          <span className="w-5 h-5 rounded-full bg-[#101828] text-white text-[10px] font-bold flex items-center justify-center">
            1
          </span>
          <p className="text-xs font-bold text-[#101828]">조회 대상</p>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
          {SOURCES.map((item) => (
            <button
              key={item.value}
              onClick={() => selectSource(item.value)}
              className={`rounded-xl border px-4 py-3 text-left transition-all ${
                source === item.value
                  ? "border-[#101828] ring-2 ring-[#101828]/10 bg-[#F8F9FB]"
                  : "border-[#EAECF0] hover:border-[#D0D5DD]"
              }`}
            >
              <span className="text-xs font-bold text-[#101828]">
                {item.label}
              </span>
              <span className="block text-[10px] text-[#667085] mt-0.5">
                {item.description}
              </span>
            </button>
          ))}
        </div>
      </section>

      {source && (
        <section className="bg-white border border-[#EAECF0] rounded-2xl p-4">
          <div className="flex items-center gap-2 mb-3">
            <span className="w-5 h-5 rounded-full bg-[#101828] text-white text-[10px] font-bold flex items-center justify-center">
              2
            </span>
            <p className="text-xs font-bold text-[#101828]">기간 선택</p>
          </div>
          <div className="flex flex-wrap gap-2">
            {RANGES.map((item) => (
              <button
                key={item.value}
                onClick={() => selectRange(item.value)}
                className={`text-[11px] font-semibold px-3 py-2 rounded-lg border transition-colors ${
                  range === item.value
                    ? "bg-[#101828] border-[#101828] text-white"
                    : "bg-white border-[#D0D5DD] text-[#475467] hover:bg-[#F9FAFB]"
                }`}
              >
                {item.label}
              </button>
            ))}
          </div>
          {range === "custom" && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-3 max-w-2xl">
              <label className="text-[10px] font-semibold text-[#475467]">
                시작 날짜/시간
                <input
                  type="datetime-local"
                  value={startAt}
                  onChange={(event) => setStartAt(event.target.value)}
                  className="block w-full mt-1 text-[11px] font-normal text-[#101828] bg-white border border-[#D0D5DD] rounded-lg px-3 py-2 outline-none focus:border-[#101828]"
                />
              </label>
              <label className="text-[10px] font-semibold text-[#475467]">
                종료 날짜/시간
                <input
                  type="datetime-local"
                  value={endAt}
                  onChange={(event) => setEndAt(event.target.value)}
                  className="block w-full mt-1 text-[11px] font-normal text-[#101828] bg-white border border-[#D0D5DD] rounded-lg px-3 py-2 outline-none focus:border-[#101828]"
                />
              </label>
            </div>
          )}
          {validationError && (
            <p className="text-[10px] font-semibold text-[#D92D20] mt-2">
              {validationError}
            </p>
          )}
        </section>
      )}

      {source && range && (
        <section className="bg-white border border-[#EAECF0] rounded-2xl p-4">
          <div className="flex items-center gap-2 mb-3">
            <span className="w-5 h-5 rounded-full bg-[#101828] text-white text-[10px] font-bold flex items-center justify-center">
              3
            </span>
            <p className="text-xs font-bold text-[#101828]">추가 검색 조건</p>
            <span className="text-[10px] text-[#98A2B3]">선택 사항</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {source === "waf" && (
              <>
                <SelectField
                  label="공격 유형"
                  value={filters.scenarioType}
                  onChange={(value) => setFilter("scenarioType", value)}
                  options={[
                    ["sqli", "SQL Injection"],
                    ["xss", "XSS"],
                    ["dir", "Directory Scan"],
                    ["brute", "Brute Force"],
                  ]}
                />
                <InputField
                  label="공격 IP"
                  value={filters.attackerIp}
                  onChange={(value) => setFilter("attackerIp", value)}
                  placeholder="예: 203.0.113.45"
                />
                <SelectField
                  label="Action"
                  value={filters.action}
                  onChange={(value) => setFilter("action", value)}
                  options={[
                    ["BLOCK", "BLOCK"],
                    ["ALLOW", "ALLOW"],
                  ]}
                />
              </>
            )}
            {source === "guardduty" && (
              <>
                <SelectField
                  label="Finding 유형"
                  value={filters.scenarioType}
                  onChange={(value) => setFilter("scenarioType", value)}
                  options={[
                    ["port", "Port Scan"],
                    ["cred", "Credential 관련 이벤트"],
                  ]}
                />
                <SelectField
                  label="Severity"
                  value={filters.severity}
                  onChange={(value) => setFilter("severity", value)}
                  options={SEVERITIES.map((value) => [value, value])}
                />
                <InputField
                  label="공격 IP"
                  value={filters.attackerIp}
                  onChange={(value) => setFilter("attackerIp", value)}
                  placeholder="예: 203.0.113.45"
                />
                <InputField
                  label="대상 자산"
                  value={filters.asset}
                  onChange={(value) => setFilter("asset", value)}
                  placeholder="자산 이름 검색"
                />
              </>
            )}
            {source === "inspector" && (
              <>
                <SelectField
                  label="Severity"
                  value={filters.severity}
                  onChange={(value) => setFilter("severity", value)}
                  options={SEVERITIES.map((value) => [value, value])}
                />
                <InputField
                  label="CVE"
                  value={filters.cve}
                  onChange={(value) => setFilter("cve", value)}
                  placeholder="예: CVE-2023-49083"
                />
                <InputField
                  label="대상 리소스 / 이미지"
                  value={filters.asset}
                  onChange={(value) => setFilter("asset", value)}
                  placeholder="이미지 또는 리소스 검색"
                />
              </>
            )}
          </div>
        </section>
      )}

      {source && range && (
        <section className="bg-white border border-[#EAECF0] rounded-2xl p-4">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <span className="w-5 h-5 rounded-full bg-[#101828] text-white text-[10px] font-bold flex items-center justify-center">
                4
              </span>
              <div>
                <p className="text-xs font-bold text-[#101828]">보안 데이터 조회</p>
                <p className="text-[10px] text-[#667085] mt-0.5">
                  선택한 한 종류의 보안 데이터만 조회합니다.
                </p>
              </div>
            </div>
            <button
              onClick={() => void search()}
              disabled={queryState === "loading"}
              className="text-[11px] font-bold text-white bg-[#101828] hover:bg-[#1D2939] disabled:opacity-50 px-4 py-2 rounded-lg transition-colors"
            >
              {queryState === "loading" ? "조회 중..." : "조회"}
            </button>
          </div>
        </section>
      )}

      {queryState !== "idle" && (
        <section className="bg-white border border-[#EAECF0] rounded-2xl overflow-hidden">
          <div className="flex items-center justify-between gap-3 px-4 py-3 border-b border-[#EAECF0]">
            <div className="flex items-center gap-2">
              <span className="w-5 h-5 rounded-full bg-[#101828] text-white text-[10px] font-bold flex items-center justify-center">
                5
              </span>
              <p className="text-xs font-bold text-[#101828]">조회 결과</p>
            </div>
            {queryState === "success" && (
              <span className="text-[10px] text-[#667085]">
                최신순 · {logs.length}건
              </span>
            )}
          </div>

          {queryState === "loading" ? (
            <div className="h-32 flex items-center justify-center gap-2 text-[11px] text-[#667085]">
              <span className="w-4 h-4 rounded-full border-2 border-[#D0D5DD] border-t-[#101828] animate-spin" />
              실제 DB 로그를 조회하고 있습니다.
            </div>
          ) : queryState === "error" ? (
            <div className="h-40 flex flex-col items-center justify-center text-center px-4">
              <p className="text-xs font-bold text-[#101828]">
                데이터를 불러오지 못했습니다.
              </p>
              <p className="text-[10px] text-[#667085] mt-1">
                DB 또는 API 연결 상태를 확인해주세요.
              </p>
              <button
                onClick={() => void search()}
                className="mt-3 text-[10px] font-semibold text-white bg-[#101828] hover:bg-[#1D2939] px-3 py-1.5 rounded-lg transition-colors"
              >
                다시 시도
              </button>
            </div>
          ) : logs.length === 0 ? (
            <div className="h-32 flex items-center justify-center text-[11px] text-[#667085]">
              조건에 해당하는 보안 데이터가 없습니다.
            </div>
          ) : (
            <>
              {lastWindow && (
                <MonitoringAnalytics
                  source={source as LogSource}
                  range={range as RangePreset}
                  window={lastWindow}
                  logs={logs}
                />
              )}
              <div className="px-4 py-3 border-b border-[#EAECF0]">
                <p className="text-xs font-bold text-[#101828]">상세 데이터</p>
              </div>
              <div className="overflow-x-auto">
              <table className="w-full text-left min-w-[860px]">
                <thead>
                  <tr className="bg-[#F8F9FB] border-b border-[#EAECF0]">
                    {[
                      "탐지 시간",
                      "서비스",
                      "공격/Finding 유형",
                      "Severity",
                      "공격 IP",
                      "대상 자산",
                      "상태",
                    ].map((label) => (
                      <th
                        key={label}
                        className="px-3 py-2.5 text-[10px] font-semibold text-[#667085]"
                      >
                        {label}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {logs.map((log) => (
                    <LogRow
                      key={log.id}
                      log={log}
                      source={source as LogSource}
                      expanded={expandedId === log.id}
                      onToggle={() =>
                        setExpandedId((current) =>
                          current === log.id ? null : log.id,
                        )
                      }
                    />
                  ))}
                </tbody>
              </table>
              </div>
            </>
          )}
        </section>
      )}
    </div>
  )
}

export function ManualMonitoringPage({
  onUnauthorized,
}: {
  onUnauthorized: () => void
}) {
  const [activeView, setActiveView] = useState<"security" | "operations">("security")

  return (
    <div className="min-h-full p-4 space-y-3">
      <div>
        <p className="text-[18px] font-bold text-[#101828]">수동 모니터링</p>
        <p className="text-[11px] text-[#667085] mt-0.5">
          {activeView === "security"
            ? "WAF, GuardDuty, Inspector의 기간별 보안 데이터를 조회합니다."
            : "메인 대시보드와 동일한 운영 지표의 기간별 추이를 조회합니다."}
        </p>
      </div>

      <div className="inline-flex rounded-xl border border-[#D0D5DD] bg-white p-1">
        {[
          ["security", "보안 데이터 조회"],
          ["operations", "운영 지표 조회"],
        ].map(([value, label]) => (
          <button
            key={value}
            onClick={() => setActiveView(value as "security" | "operations")}
            className={`text-[11px] font-semibold px-4 py-2 rounded-lg transition-colors ${
              activeView === value
                ? "bg-[#101828] text-white shadow-sm"
                : "text-[#475467] hover:bg-[#F2F4F7]"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      <div className={activeView === "security" ? "" : "hidden"}>
        <SecurityDataMonitoringContent onUnauthorized={onUnauthorized} />
      </div>
      <div className={activeView === "operations" ? "" : "hidden"}>
        <OperationalMetricsPanel onUnauthorized={onUnauthorized} />
      </div>
    </div>
  )
}

function InputField({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string
  value: string
  onChange: (value: string) => void
  placeholder: string
}) {
  return (
    <label className="text-[10px] font-semibold text-[#475467]">
      {label}
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="block w-full mt-1 text-[11px] font-normal text-[#101828] placeholder:text-[#98A2B3] bg-white border border-[#D0D5DD] rounded-lg px-3 py-2 outline-none focus:border-[#101828]"
      />
    </label>
  )
}

function SelectField({
  label,
  value,
  onChange,
  options,
}: {
  label: string
  value: string
  onChange: (value: string) => void
  options: string[][]
}) {
  return (
    <label className="text-[10px] font-semibold text-[#475467]">
      {label}
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="block w-full mt-1 text-[11px] font-normal text-[#101828] bg-white border border-[#D0D5DD] rounded-lg px-3 py-2 outline-none focus:border-[#101828]"
      >
        <option value="">전체</option>
        {options.map(([optionValue, optionLabel]) => (
          <option key={optionValue} value={optionValue}>
            {optionLabel}
          </option>
        ))}
      </select>
    </label>
  )
}

function LogRow({
  log,
  source,
  expanded,
  onToggle,
}: {
  log: SecurityLog
  source: LogSource
  expanded: boolean
  onToggle: () => void
}) {
  return (
    <>
      <tr
        onClick={onToggle}
        className="border-b border-[#F2F4F7] hover:bg-[#FAFAFA] cursor-pointer"
      >
        <td className="px-3 py-2.5 text-[10px] font-mono text-[#475467] whitespace-nowrap">
          {formatDetectedAt(log.detectedAt)}
        </td>
        <td className="px-3 py-2.5 text-[10px] font-semibold text-[#344054]">
          {log.service}
        </td>
        <td className="px-3 py-2.5 text-[10px] text-[#344054]">
          {log.scenarioType || "-"}
        </td>
        <td className="px-3 py-2.5">
          <SeverityBadge sev={log.severity} small />
        </td>
        <td className="px-3 py-2.5 text-[10px] font-mono text-[#475467]">
          {log.attackerIp ?? "-"}
        </td>
        <td className="px-3 py-2.5 text-[10px] text-[#344054]">
          {log.asset ?? "-"}
        </td>
        <td className="px-3 py-2.5 text-[10px] text-[#475467]">
          <span className="inline-flex items-center gap-2">
            {log.status}
            <span
              className={`transition-transform ${expanded ? "rotate-180" : ""}`}
            >
              ⌄
            </span>
          </span>
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={7} className="p-0">
            <LogDetail log={log} source={source} />
          </td>
        </tr>
      )}
    </>
  )
}
