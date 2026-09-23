import { useState } from "react"

type MetricKey = "all" | "cpu" | "memory" | "latency" | "rps" | "errorRate" | "health"
type RangePreset = "15m" | "1h" | "6h" | "24h" | "7d" | "custom"
type QueryState = "idle" | "loading" | "success" | "error"
type HealthStatus = "NORMAL" | "WARNING" | "CRITICAL"

interface NumericSummary {
  current: number | null
  average: number | null
  max: number | null
  min: number | null
  unit: string
}

interface HealthSummary {
  current: HealthStatus | null
  healthy: number | null
  unhealthy: number | null
}

interface MetricRecord {
  timestamp: string
  value?: number
  cpu?: number | null
  memory?: number | null
  latency?: number | null
  rps?: number | null
  errorRate?: number | null
  health?: HealthStatus | null
  healthy?: number | null
  unhealthy?: number | null
}

interface MonitoringMetricsResponse {
  metric: MetricKey
  window: { start: string; end: string }
  summary?: NumericSummary | HealthSummary
  summaries?: Record<string, NumericSummary | HealthSummary>
  series: MetricRecord[]
}

const METRICS: { value: MetricKey; label: string; shortLabel: string }[] = [
  { value: "all", label: "전체 지표", shortLabel: "전체" },
  { value: "cpu", label: "CPU 사용률", shortLabel: "CPU" },
  { value: "memory", label: "메모리 사용률", shortLabel: "Memory" },
  { value: "latency", label: "요청 지연 시간", shortLabel: "Latency" },
  { value: "rps", label: "요청 처리량", shortLabel: "RPS" },
  { value: "errorRate", label: "에러율", shortLabel: "Error Rate" },
  { value: "health", label: "서비스 상태", shortLabel: "Service" },
]

const RANGES: { value: RangePreset; label: string }[] = [
  { value: "15m", label: "최근 15분" },
  { value: "1h", label: "최근 1시간" },
  { value: "6h", label: "최근 6시간" },
  { value: "24h", label: "최근 24시간" },
  { value: "7d", label: "최근 7일" },
  { value: "custom", label: "직접 설정" },
]

const UNITS: Record<Exclude<MetricKey, "all" | "health">, string> = {
  cpu: "%",
  memory: "%",
  latency: "ms",
  rps: "rps",
  errorRate: "%",
}

const HEALTH_LABELS: Record<HealthStatus, string> = {
  NORMAL: "정상",
  WARNING: "경고",
  CRITICAL: "장애",
}

const HEALTH_COLORS: Record<HealthStatus, string> = {
  NORMAL: "#16A34A",
  WARNING: "#F79009",
  CRITICAL: "#D92D20",
}

function toDatetimeLocal(date: Date) {
  const pad = (value: number) => String(value).padStart(2, "0")
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`
}

function formatTimestamp(value: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return new Intl.DateTimeFormat("ko-KR", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date)
}

function formatNumber(
  value: number | null | undefined,
  unit: string,
  compact = false,
) {
  if (value === null || value === undefined) return "데이터 없음"
  const decimals = unit === "ms" ? 0 : unit === "rps" ? 1 : 1
  const formatted = value.toFixed(decimals)
  return compact ? `${formatted}${unit}` : `${formatted} ${unit}`
}

function downsample<T>(items: T[], maximum = 120) {
  if (items.length <= maximum) return items
  const step = (items.length - 1) / (maximum - 1)
  return Array.from(
    { length: maximum },
    (_, index) => items[Math.round(index * step)],
  )
}

function NumericLineChart({
  title,
  records,
  unit,
  color = "#101828",
}: {
  title: string
  records: MetricRecord[]
  unit: string
  color?: string
}) {
  const data = downsample(
    records.filter((record) => record.value !== undefined),
  )
  if (data.length === 0) return null

  const width = 900
  const height = 220
  const padding = { left: 52, right: 18, top: 20, bottom: 32 }
  const values = data.map((record) => record.value as number)
  const minValue = Math.min(...values)
  const maxValue = Math.max(...values)
  const valueRange = maxValue - minValue || 1
  const chartWidth = width - padding.left - padding.right
  const chartHeight = height - padding.top - padding.bottom
  const points = data.map((record, index) => ({
    x:
      padding.left +
      (data.length === 1
        ? chartWidth / 2
        : (index * chartWidth) / (data.length - 1)),
    y:
      padding.top +
      chartHeight -
      ((record.value as number - minValue) / valueRange) * chartHeight,
    record,
  }))
  const labelIndexes = Array.from(
    new Set([0, Math.floor((points.length - 1) / 2), points.length - 1]),
  )

  return (
    <div className="rounded-xl border border-[#EAECF0] p-4">
      <p className="text-xs font-bold text-[#101828] mb-2">{title}</p>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="w-full h-[220px]"
        role="img"
        aria-label={title}
      >
        {[0, 0.5, 1].map((ratio) => {
          const y = padding.top + chartHeight * ratio
          return (
            <line
              key={ratio}
              x1={padding.left}
              x2={width - padding.right}
              y1={y}
              y2={y}
              stroke="#EAECF0"
            />
          )
        })}
        <polyline
          points={points.map((point) => `${point.x},${point.y}`).join(" ")}
          fill="none"
          stroke={color}
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <text x="4" y={padding.top + 4} fontSize="9" fill="#667085">
          {formatNumber(maxValue, unit)}
        </text>
        <text
          x="4"
          y={padding.top + chartHeight + 3}
          fontSize="9"
          fill="#667085"
        >
          {formatNumber(minValue, unit)}
        </text>
        {labelIndexes.map(
          (index) =>
            points[index] && (
              <text
                key={index}
                x={points[index].x}
                y={height - 8}
                textAnchor="middle"
                fontSize="9"
                fill="#667085"
              >
                {formatTimestamp(points[index].record.timestamp).slice(-8)}
              </text>
            ),
        )}
      </svg>
    </div>
  )
}

function CombinedPercentChart({ records }: { records: MetricRecord[] }) {
  const data = downsample(
    records.filter(
      (row) =>
        row.cpu !== null || row.memory !== null || row.errorRate !== null,
    ),
  )
  if (data.length === 0) return null

  const width = 900
  const height = 220
  const padding = { left: 42, right: 18, top: 20, bottom: 32 }
  const chartWidth = width - padding.left - padding.right
  const chartHeight = height - padding.top - padding.bottom
  const series = [
    { field: "cpu" as const, label: "CPU", color: "#2563EB" },
    { field: "memory" as const, label: "Memory", color: "#7C3AED" },
    { field: "errorRate" as const, label: "Error", color: "#D92D20" },
  ]
  // CPU/Memory/Error를 항상 0~100% 축에 놓으면, 지금처럼 실사용량이 낮을 때
  // 선이 다 바닥에 붙어서 변화가 안 보이고 "그래프가 이상하다"는 오해를 산다.
  // 실제 최댓값 기준으로 여유(25%)만 두고 축을 좁혀서 변화가 보이게 한다.
  const dataMax = Math.max(
    0,
    ...data.flatMap((row) => series.map((item) => row[item.field] ?? 0)),
  )
  const maxValue = dataMax <= 0 ? 100 : Math.min(100, dataMax * 1.25)

  return (
    <div className="rounded-xl border border-[#EAECF0] p-4">
      <div className="flex items-center justify-between gap-3 mb-2">
        <p className="text-xs font-bold text-[#101828]">
          사용률 및 에러율 통합 추이
        </p>
        <div className="flex gap-3">
          {series.map((item) => (
            <span
              key={item.field}
              className="flex items-center gap-1 text-[9px] text-[#667085]"
            >
              <span
                className="w-2 h-2 rounded-full"
                style={{ backgroundColor: item.color }}
              />
              {item.label}
            </span>
          ))}
        </div>
      </div>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="w-full h-[220px]"
        role="img"
        aria-label="사용률 및 에러율 통합 추이"
      >
        {[0, 0.5, 1].map((ratio) => {
          const y = padding.top + chartHeight * ratio
          return (
            <line
              key={ratio}
              x1={padding.left}
              x2={width - padding.right}
              y1={y}
              y2={y}
              stroke="#EAECF0"
            />
          )
        })}
        {series.map((item) => {
          const points = data
            .map((row, index) => {
              const value = row[item.field]
              if (value === null || value === undefined) return null
              const x =
                padding.left +
                (data.length === 1
                  ? chartWidth / 2
                  : (index * chartWidth) / (data.length - 1))
              const y =
                padding.top + chartHeight - (value / maxValue) * chartHeight
              return `${x},${y}`
            })
            .filter(Boolean)
          return points.length > 1 ? (
            <polyline
              key={item.field}
              points={points.join(" ")}
              fill="none"
              stroke={item.color}
              strokeWidth="2.2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          ) : null
        })}
        <text x="5" y={padding.top + 4} fontSize="9" fill="#667085">
          {maxValue.toFixed(0)}%
        </text>
        <text
          x="18"
          y={padding.top + chartHeight + 3}
          fontSize="9"
          fill="#667085"
        >
          0%
        </text>
        {[0, Math.floor((data.length - 1) / 2), data.length - 1].map(
          (index) =>
            data[index] && (
              <text
                key={index}
                x={
                  padding.left +
                  (data.length === 1
                    ? chartWidth / 2
                    : (index * chartWidth) / (data.length - 1))
                }
                y={height - 8}
                textAnchor="middle"
                fontSize="9"
                fill="#667085"
              >
                {formatTimestamp(data[index].timestamp).slice(-8)}
              </text>
            ),
        )}
      </svg>
    </div>
  )
}

function NumericSummaryCards({ summary }: { summary: NumericSummary }) {
  const cards = [
    ["현재값", summary.current],
    ["평균값", summary.average],
    ["최대값", summary.max],
    ["최소값", summary.min],
  ] as const
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-2">
      {cards.map(([label, value]) => (
        <div
          key={label}
          className="rounded-xl border border-[#EAECF0] bg-[#FAFAFA] px-4 py-3"
        >
          <p className="text-[10px] text-[#667085]">{label}</p>
          <p className="text-[20px] font-bold text-[#101828] mt-1">
            {formatNumber(value, summary.unit)}
          </p>
        </div>
      ))}
    </div>
  )
}

function HealthBadge({ status }: { status: HealthStatus | null | undefined }) {
  if (!status) return <span className="text-[#98A2B3]">데이터 없음</span>
  return (
    <span className="font-bold" style={{ color: HEALTH_COLORS[status] }}>
      {HEALTH_LABELS[status]}
    </span>
  )
}

export function OperationalMetricsPanel({
  onUnauthorized,
}: {
  onUnauthorized: () => void
}) {
  const [metric, setMetric] = useState<MetricKey>("all")
  const [range, setRange] = useState<RangePreset>("24h")
  const [startAt, setStartAt] = useState("")
  const [endAt, setEndAt] = useState("")
  const [queryState, setQueryState] = useState<QueryState>("idle")
  const [validationError, setValidationError] = useState<string | null>(null)
  const [data, setData] = useState<MonitoringMetricsResponse | null>(null)

  const selectRange = (nextRange: RangePreset) => {
    setRange(nextRange)
    setValidationError(null)
    setData(null)
    setQueryState("idle")
    if (nextRange === "custom" && (!startAt || !endAt)) {
      const end = new Date()
      const start = new Date(end.getTime() - 60 * 60 * 1000)
      setStartAt(toDatetimeLocal(start))
      setEndAt(toDatetimeLocal(end))
    }
  }

  const search = async () => {
    setValidationError(null)
    const params = new URLSearchParams({ metric })
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
        start >= end
      ) {
        setValidationError("시작 시간은 종료 시간보다 빨라야 합니다.")
        return
      }
      params.set("start", startAt.length === 16 ? `${startAt}:00` : startAt)
      params.set("end", endAt.length === 16 ? `${endAt}:00` : endAt)
    } else {
      params.set("range", range)
    }

    setQueryState("loading")
    setData(null)
    try {
      const response = await fetch(
        `/api/monitoring/metrics?${params.toString()}`,
        {
          credentials: "include",
          headers: { Accept: "application/json" },
        },
      )
      if (response.status === 401) {
        onUnauthorized()
        return
      }
      const result = (await response.json()) as MonitoringMetricsResponse & {
        message?: string
      }
      if (!response.ok || !Array.isArray(result.series)) {
        throw new Error(
          result.message || `Monitoring metrics API ${response.status}`,
        )
      }
      setData(result)
      setQueryState("success")
    } catch (error) {
      console.error("운영 지표 데이터를 불러오지 못했습니다.", error)
      setQueryState("error")
    }
  }

  const numericMetric = metric !== "all" && metric !== "health" ? metric : null
  const numericSummary =
    numericMetric && data?.summary ? data.summary as NumericSummary : null
  const healthSummary =
    metric === "health" && data?.summary ? data.summary as HealthSummary : null
  const allSummaries = metric === "all" ? data?.summaries : null
  const selectedConfig = METRICS.find((item) => item.value === metric)!

  return (
    <div className="space-y-3">
      <section className="bg-white border border-[#EAECF0] rounded-2xl p-4">
        <div className="flex items-center gap-2 mb-3">
          <span className="w-5 h-5 rounded-full bg-[#101828] text-white text-[10px] font-bold flex items-center justify-center">
            1
          </span>
          <p className="text-xs font-bold text-[#101828]">조회 지표</p>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2">
          {METRICS.map((item) => (
            <button
              key={item.value}
              onClick={() => {
                setMetric(item.value)
                setData(null)
                setQueryState("idle")
              }}
              className={`rounded-xl border px-3 py-3 text-[11px] font-semibold transition-all ${
                metric === item.value
                  ? "border-[#101828] ring-2 ring-[#101828]/10 bg-[#F8F9FB] text-[#101828]"
                  : "border-[#EAECF0] text-[#475467] hover:border-[#D0D5DD]"
              }`}
            >
              {item.label}
            </button>
          ))}
        </div>
      </section>

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

      <section className="bg-white border border-[#EAECF0] rounded-2xl p-4">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="w-5 h-5 rounded-full bg-[#101828] text-white text-[10px] font-bold flex items-center justify-center">
              3
            </span>
            <div>
              <p className="text-xs font-bold text-[#101828]">운영 지표 조회</p>
              <p className="text-[10px] text-[#667085] mt-0.5">
                {selectedConfig.label}의 실제 DB 이력을 조회합니다.
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

      {queryState !== "idle" && (
        <section className="bg-white border border-[#EAECF0] rounded-2xl overflow-hidden">
          <div className="flex items-center justify-between gap-3 px-4 py-3 border-b border-[#EAECF0]">
            <div className="flex items-center gap-2">
              <span className="w-5 h-5 rounded-full bg-[#101828] text-white text-[10px] font-bold flex items-center justify-center">
                4
              </span>
              <p className="text-xs font-bold text-[#101828]">조회 결과</p>
            </div>
            {queryState === "success" && data && (
              <span className="text-[10px] text-[#667085]">
                시간순 · {data.series.length}개 시점
              </span>
            )}
          </div>

          {queryState === "loading" ? (
            <div className="h-32 flex items-center justify-center gap-2 text-[11px] text-[#667085]">
              <span className="w-4 h-4 rounded-full border-2 border-[#D0D5DD] border-t-[#101828] animate-spin" />
              실제 운영 지표를 조회하고 있습니다.
            </div>
          ) : queryState === "error" ? (
            <div className="h-44 flex flex-col items-center justify-center text-center px-4">
              <p className="text-xs font-bold text-[#101828]">
                운영 지표 데이터를 불러오지 못했습니다.
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
          ) : !data || data.series.length === 0 ? (
            <div className="h-32 flex items-center justify-center text-[11px] text-[#667085]">
              선택한 기간에 운영 지표 데이터가 없습니다.
            </div>
          ) : metric === "all" && allSummaries ? (
            <div className="p-4 space-y-3">
              <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-2">
                {METRICS.filter((item) => item.value !== "all").map((item) => {
                  const summary = allSummaries[item.value]
                  const value =
                    item.value === "health" ? (
                      <HealthBadge
                        status={(summary as HealthSummary | undefined)?.current}
                      />
                    ) : (
                      formatNumber(
                        (summary as NumericSummary | undefined)?.current,
                        UNITS[(item.value as keyof typeof UNITS)],
                        true,
                      )
                    )
                  return (
                    <div
                      key={item.value}
                      className="rounded-xl border border-[#EAECF0] bg-[#FAFAFA] px-3 py-3"
                    >
                      <p className="text-[10px] text-[#667085]">
                        {item.shortLabel}
                      </p>
                      <p className="text-[17px] font-bold text-[#101828] mt-1">
                        {value}
                      </p>
                    </div>
                  )
                })}
              </div>
              <CombinedPercentChart records={data.series} />
              <div className="overflow-x-auto rounded-xl border border-[#EAECF0]">
                <table className="w-full min-w-[860px] text-left">
                  <thead>
                    <tr className="bg-[#F8F9FB] border-b border-[#EAECF0]">
                      {[
                        "시간",
                        "CPU",
                        "Memory",
                        "Latency",
                        "RPS",
                        "Error",
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
                    {[...data.series].reverse().map((row) => (
                      <tr
                        key={row.timestamp}
                        className="border-b border-[#F2F4F7] last:border-0"
                      >
                        <td className="px-3 py-2.5 text-[10px] font-mono text-[#475467] whitespace-nowrap">
                          {formatTimestamp(row.timestamp)}
                        </td>
                        <td className="px-3 py-2.5 text-[10px]">
                          {formatNumber(row.cpu, "%", true)}
                        </td>
                        <td className="px-3 py-2.5 text-[10px]">
                          {formatNumber(row.memory, "%", true)}
                        </td>
                        <td className="px-3 py-2.5 text-[10px]">
                          {formatNumber(row.latency, "ms", true)}
                        </td>
                        <td className="px-3 py-2.5 text-[10px]">
                          {formatNumber(row.rps, "rps", true)}
                        </td>
                        <td className="px-3 py-2.5 text-[10px]">
                          {formatNumber(row.errorRate, "%", true)}
                        </td>
                        <td className="px-3 py-2.5 text-[10px]">
                          <HealthBadge status={row.health} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : metric === "health" && healthSummary ? (
            <div className="p-4 space-y-3">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                <div className="rounded-xl border border-[#EAECF0] bg-[#FAFAFA] px-4 py-3">
                  <p className="text-[10px] text-[#667085]">현재 상태</p>
                  <p className="text-[20px] mt-1">
                    <HealthBadge status={healthSummary.current} />
                  </p>
                </div>
                <div className="rounded-xl border border-[#EAECF0] bg-[#FAFAFA] px-4 py-3">
                  <p className="text-[10px] text-[#667085]">HealthyHostCount</p>
                  <p className="text-[20px] font-bold text-[#16A34A] mt-1">
                    {healthSummary.healthy ?? "데이터 없음"}
                  </p>
                </div>
                <div className="rounded-xl border border-[#EAECF0] bg-[#FAFAFA] px-4 py-3">
                  <p className="text-[10px] text-[#667085]">
                    UnHealthyHostCount
                  </p>
                  <p className="text-[20px] font-bold text-[#D92D20] mt-1">
                    {healthSummary.unhealthy ?? "데이터 없음"}
                  </p>
                </div>
              </div>
              <div className="overflow-x-auto rounded-xl border border-[#EAECF0]">
                <table className="w-full text-left">
                  <thead>
                    <tr className="bg-[#F8F9FB] border-b border-[#EAECF0]">
                      {[
                        "시간",
                        "상태",
                        "HealthyHostCount",
                        "UnHealthyHostCount",
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
                    {[...data.series].reverse().map((row) => (
                      <tr
                        key={row.timestamp}
                        className="border-b border-[#F2F4F7] last:border-0"
                      >
                        <td className="px-3 py-2.5 text-[10px] font-mono text-[#475467]">
                          {formatTimestamp(row.timestamp)}
                        </td>
                        <td className="px-3 py-2.5 text-[10px]">
                          <HealthBadge status={row.health} />
                        </td>
                        <td className="px-3 py-2.5 text-[10px]">
                          {row.healthy ?? "-"}
                        </td>
                        <td className="px-3 py-2.5 text-[10px]">
                          {row.unhealthy ?? "-"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : numericMetric && numericSummary ? (
            <div className="p-4 space-y-3">
              <NumericSummaryCards summary={numericSummary} />
              <NumericLineChart
                title={`${selectedConfig.label} 시간별 추이`}
                records={data.series}
                unit={UNITS[numericMetric]}
                color={numericMetric === "errorRate" ? "#D92D20" : "#101828"}
              />
              <div className="overflow-x-auto rounded-xl border border-[#EAECF0]">
                <table className="w-full text-left">
                  <thead>
                    <tr className="bg-[#F8F9FB] border-b border-[#EAECF0]">
                      <th className="px-3 py-2.5 text-[10px] font-semibold text-[#667085]">
                        시간
                      </th>
                      <th className="px-3 py-2.5 text-[10px] font-semibold text-[#667085]">
                        값
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {[...data.series].reverse().map((row) => (
                      <tr
                        key={row.timestamp}
                        className="border-b border-[#F2F4F7] last:border-0"
                      >
                        <td className="px-3 py-2.5 text-[10px] font-mono text-[#475467]">
                          {formatTimestamp(row.timestamp)}
                        </td>
                        <td className="px-3 py-2.5 text-[10px] font-semibold text-[#101828]">
                          {formatNumber(row.value, UNITS[numericMetric])}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : null}
        </section>
      )}
    </div>
  )
}
