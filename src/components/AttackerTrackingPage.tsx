import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import type { AssetStatus } from "../data/types"
import { ArchitectureMap } from "./ArchitectureMap"

// 백엔드 services/attack_reach.py 의 판정 결과를 그대로 보여준다.
type Stage = "S1" | "S2" | "S3" | "S4" | "C"
type Confidence = "confirmed" | "fallback" | "uncertain"
type RangeKey = "24h" | "7d"

interface BlockState {
  state: "none" | "blocked" | "bypassed" | "excluded"
  at: string | null
  reason: string | null
}

interface AttackerSummary {
  ip: string
  isInternal: boolean
  firstSeen: string
  lastSeen: string
  eventCount: number
  requestCount: number | null
  passedCount: number | null
  scenarioTypes: string[]
  maxSeverity: string | null
  maxStage: Exclude<Stage, "C"> | null
  maxStageConfidence: Confidence | null
  cloudAccess: boolean
  openEvents: number
  block: BlockState
}

interface AttackerList {
  items: AttackerSummary[]
  summary: { ips: number; passedIps: number; bypassed: number; cloud: number }
  truncated: boolean
}

interface Reach {
  confirmed: string[]
  estimated: string[]
}

interface TimelineItem {
  eventId: string
  time: string
  scenarioType: string
  title: string
  severity: string
  status: string
  excluded: boolean
  stage: Stage
  confidence: Confidence
  source: "shop" | "admin" | null
  requests: number | null
  passed: number | null
  target: string | null
  reach: Reach
}

interface RemediationItem {
  eventId: string
  time: string | null
  action: string | null
  method: string | null
  result: string | null
  detail: string | null
}

interface AttackerDetail {
  ip: string
  summary: AttackerSummary
  timeline: TimelineItem[]
  remediations: RemediationItem[]
  reach: Reach
  truncated: boolean
}

export const STAGE_META: Record<Stage, { label: string; className: string }> = {
  S1: { label: "정찰", className: "bg-[#EFF8FF] text-[#175CD3]" },
  S2: { label: "경계 차단", className: "bg-[#ECFDF3] text-[#067647]" },
  S3: { label: "일부 통과", className: "bg-[#FFFAEB] text-[#B54708]" },
  S4: { label: "WAF 통과", className: "bg-[#FEF3F2] text-[#B42318]" },
  C: { label: "클라우드 권한", className: "bg-[#F4F3FF] text-[#5925DC]" },
}
const STAGE_STEPS: Exclude<Stage, "C">[] = ["S1", "S2", "S3", "S4"]
const STAGE_FILTERS: (Stage | "")[] = ["", "S4", "S3", "S2", "S1", "C"]

const CONFIDENCE_LABEL: Record<Confidence, string> = {
  confirmed: "로그 확인",
  fallback: "대체 판정",
  uncertain: "불확실",
}

const SCENARIO_LABEL: Record<string, string> = {
  sqli: "SQLi",
  xss: "XSS",
  dir: "디렉터리 스캔",
  brute: "무차별 대입",
  flood: "HTTP Flood",
  port: "포트 스캔",
  cred: "자격증명",
}

const ACTION_LABEL: Record<string, string> = {
  block_ip: "IP 차단",
  disable_access_key: "Access Key 비활성화",
  restart_service: "서비스 재시작",
}

function formatTime(iso: string | null) {
  if (!iso) return "-"
  return new Date(iso).toLocaleString("ko-KR", {
    timeZone: "Asia/Seoul",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  })
}

function formatCount(value: number | null) {
  return value === null ? "-" : value.toLocaleString("ko-KR")
}

async function fetchJson<T>(url: string, onUnauthorized: () => void): Promise<T> {
  const response = await fetch(url, { credentials: "include", headers: { Accept: "application/json" } })
  if (response.status === 401) {
    onUnauthorized()
    throw new Error("로그인이 필요합니다.")
  }
  const body = await response.json().catch(() => null)
  if (!response.ok) throw new Error(body?.message || `요청 실패 (HTTP ${response.status})`)
  return body as T
}

export function StageBadge({ stage, confidence }: { stage: Stage | null; confidence?: Confidence | null }) {
  if (!stage) return <span className="text-[11px] text-[#98A2B3]">-</span>
  const meta = STAGE_META[stage]
  return (
    <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10.5px] font-semibold ${meta.className}`}>
      {stage === "C" ? "C" : stage} {meta.label}
      {confidence && confidence !== "confirmed" && (
        <span className="font-medium opacity-75">· {CONFIDENCE_LABEL[confidence]}</span>
      )}
    </span>
  )
}

function BlockBadge({ block }: { block: BlockState }) {
  if (block.state === "bypassed")
    return (
      <span className="rounded-full bg-[#D92D20] px-2 py-0.5 text-[10.5px] font-bold text-white">
        차단 후 재시도
      </span>
    )
  if (block.state === "blocked")
    return (
      <span className="rounded-full bg-[#ECFDF3] px-2 py-0.5 text-[10.5px] font-semibold text-[#067647]">
        차단됨 {formatTime(block.at)}
      </span>
    )
  if (block.state === "excluded")
    return (
      <span
        title="Remediation Lambda 가 차단하지 않는 주소입니다."
        className="rounded-full bg-[#F2F4F7] px-2 py-0.5 text-[10.5px] font-semibold text-[#667085]"
      >
        차단 제외 · {block.reason}
      </span>
    )
  return (
    <span className="rounded-full bg-[#FFFAEB] px-2 py-0.5 text-[10.5px] font-semibold text-[#B54708]">
      미차단
    </span>
  )
}

function SummaryCard({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <div className="rounded-xl border border-[#E4E7EC] bg-white px-4 py-3">
      <p className="text-[11px] font-semibold text-[#667085]">{label}</p>
      <p className="mt-1 text-[22px] font-bold" style={{ color: tone }}>
        {value}
      </p>
    </div>
  )
}

function StageStepper({ summary }: { summary: AttackerSummary }) {
  const reached = summary.maxStage ? STAGE_STEPS.indexOf(summary.maxStage) : -1
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {STAGE_STEPS.map((stage, index) => {
        const on = index <= reached
        const isMax = index === reached
        return (
          <div key={stage} className="flex items-center gap-1.5">
            {index > 0 && <span className={`h-px w-4 ${on ? "bg-[#344054]" : "bg-[#D0D5DD]"}`} />}
            <span
              className={`rounded-md px-2 py-1 text-[11px] font-semibold ${
                isMax ? STAGE_META[stage].className + " ring-1 ring-current" : on ? "bg-[#F2F4F7] text-[#344054]" : "bg-white text-[#98A2B3] ring-1 ring-[#E4E7EC]"
              }`}
            >
              {stage} {STAGE_META[stage].label}
            </span>
          </div>
        )
      })}
      {summary.cloudAccess && (
        <span className={`ml-2 rounded-md px-2 py-1 text-[11px] font-semibold ring-1 ring-current ${STAGE_META.C.className}`}>
          C 클라우드 권한 도달
        </span>
      )}
    </div>
  )
}

function ReachMap({ reach }: { reach: Reach }) {
  const statuses: Record<string, AssetStatus> = {}
  reach.estimated.forEach((id) => (statuses[id] = "warning"))
  reach.confirmed.forEach((id) => (statuses[id] = "critical"))
  const lit = [...reach.confirmed, ...reach.estimated]
  return (
    <div className="relative h-[360px]">
      <ArchitectureMap
        assetStatuses={statuses}
        highlightedAssets={lit}
        attackPathAssets={reach.confirmed}
        estimatedAssets={reach.estimated}
        connectionAssetGroups={[lit]}
        alerts={{}}
        onAssetClick={() => undefined}
        onBackgroundClick={() => undefined}
        hasScenario={lit.length > 0}
      />
    </div>
  )
}

function Timeline({ detail }: { detail: AttackerDetail }) {
  type Row =
    | { kind: "event"; time: string; item: TimelineItem }
    | { kind: "remediation"; time: string; item: RemediationItem }
  const rows: Row[] = [
    ...detail.timeline.map((item) => ({ kind: "event" as const, time: item.time, item })),
    ...detail.remediations
      .filter((item) => item.time)
      .map((item) => ({ kind: "remediation" as const, time: item.time as string, item })),
  ].sort((a, b) => a.time.localeCompare(b.time))

  return (
    <ol className="space-y-1.5">
      {rows.map((row) =>
        row.kind === "remediation" ? (
          <li
            key={`rem-${row.item.eventId}-${row.time}`}
            className="flex items-center gap-2 py-1 text-[11px] font-semibold text-[#067647]"
          >
            <span className="h-px flex-1 bg-[#A6F4C5]" />
            {formatTime(row.time)} {ACTION_LABEL[row.item.action ?? ""] ?? row.item.action} · {row.item.result}
            <span className="h-px flex-1 bg-[#A6F4C5]" />
          </li>
        ) : (
          <li
            key={row.item.eventId}
            className={`grid grid-cols-[88px_1fr_auto] items-center gap-2 rounded-lg border border-[#EAECF0] px-3 py-2 ${
              row.item.excluded ? "opacity-50" : ""
            }`}
          >
            <span className="text-[11px] tabular-nums text-[#667085]">{formatTime(row.time)}</span>
            <div className="min-w-0">
              <p className="truncate text-[12px] font-semibold text-[#101828]">
                {SCENARIO_LABEL[row.item.scenarioType] ?? row.item.scenarioType}
                <span className="ml-1.5 font-normal text-[#667085]">{row.item.title}</span>
              </p>
              <p className="text-[10.5px] text-[#667085]">
                {row.item.requests !== null
                  ? `요청 ${formatCount(row.item.requests)}건 중 ${formatCount(row.item.passed)}건 통과`
                  : row.item.stage === "S1"
                    ? `대상 ${row.item.target ?? "미확인"}`
                    : row.item.stage === "C"
                      ? "AWS API 호출 (네트워크 경로 아님)"
                      : "요청 수 정보 없음"}
                {row.item.source === "admin" && " · 관리자 ALB"}
                {` · ${row.item.status}`}
                {row.item.excluded && " (최대 단계 계산에서 제외)"}
              </p>
            </div>
            <StageBadge stage={row.item.stage} confidence={row.item.confidence} />
          </li>
        ),
      )}
    </ol>
  )
}

function DetailPanel({
  ip,
  range,
  onUnauthorized,
}: {
  ip: string
  range: RangeKey
  onUnauthorized: () => void
}) {
  const [detail, setDetail] = useState<AttackerDetail | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    setDetail(null)
    setError(null)
    fetchJson<AttackerDetail>(`/api/attackers/${encodeURIComponent(ip)}?range=${range}`, onUnauthorized)
      .then((data) => !cancelled && setDetail(data))
      .catch((err: Error) => !cancelled && setError(err.message))
    return () => {
      cancelled = true
    }
  }, [ip, range, onUnauthorized])

  if (error) return <p className="p-6 text-[12px] text-[#B42318]">{error}</p>
  if (!detail) return <p className="p-6 text-[12px] text-[#667085]">불러오는 중...</p>

  const s = detail.summary
  return (
    <div className="space-y-3 p-4">
      <div className="flex flex-wrap items-center gap-2">
        <p className="font-mono text-[18px] font-bold text-[#101828]">{detail.ip}</p>
        <BlockBadge block={s.block} />
        {s.isInternal && (
          <span className="rounded-full bg-[#F2F4F7] px-2 py-0.5 text-[10.5px] font-semibold text-[#475467]">내부 발신</span>
        )}
        <span className="ml-auto text-[11px] text-[#667085]">
          {formatTime(s.firstSeen)} ~ {formatTime(s.lastSeen)} · 이벤트 {s.eventCount}건 · 요청 {formatCount(s.requestCount)}건 중{" "}
          {formatCount(s.passedCount)}건 통과
        </span>
      </div>
      <StageStepper summary={s} />
      {s.block.state === "bypassed" && (
        <p className="rounded-lg bg-[#FEF3F2] px-3 py-2 text-[11.5px] text-[#B42318]">
          IP 차단({formatTime(s.block.at)}) 이후에도 WAF 를 통과한 요청이 있습니다. 차단 목록 반영 여부와 WAF 규칙 순서를 확인하세요.
        </p>
      )}
      <ReachMap reach={detail.reach} />
      <div className="flex flex-wrap gap-3 text-[10.5px] text-[#667085]">
        <span className="flex items-center gap-1">
          <span className="inline-block h-3 w-3 rounded-sm ring-2 ring-[#D92D20]" /> 로그로 확인된 도달
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block h-3 w-3 rounded-sm outline-2 outline-dashed outline-[#F79009]" /> 추정 도달 (ALB 이후 앱 로그 미수집)
        </span>
      </div>
      <Timeline detail={detail} />
    </div>
  )
}

export function AttackerTrackingPage({
  selectedIp,
  onSelectIp,
  onUnauthorized,
}: {
  selectedIp: string | null
  onSelectIp: (ip: string | null) => void
  onUnauthorized: () => void
}) {
  const [range, setRange] = useState<RangeKey>("7d")
  const [stageFilter, setStageFilter] = useState<Stage | "">("")
  const [query, setQuery] = useState("")
  const [list, setList] = useState<AttackerList | null>(null)
  const [error, setError] = useState<string | null>(null)
  // App 은 시계 때문에 매초 다시 그려져 onUnauthorized 가 매번 새 함수로 들어온다.
  // effect 의존성에 그대로 넣으면 매초 다시 조회하므로 ref 로 고정한다.
  const onUnauthorizedRef = useRef(onUnauthorized)
  onUnauthorizedRef.current = onUnauthorized
  const handleUnauthorized = useCallback(() => onUnauthorizedRef.current(), [])

  useEffect(() => {
    let cancelled = false
    setError(null)
    fetchJson<AttackerList>(`/api/attackers?range=${range}`, handleUnauthorized)
      .then((data) => !cancelled && setList(data))
      .catch((err: Error) => !cancelled && setError(err.message))
    return () => {
      cancelled = true
    }
  }, [range, handleUnauthorized])

  const items = useMemo(() => {
    const all = list?.items ?? []
    return all.filter(
      (item) =>
        (!stageFilter || (stageFilter === "C" ? item.cloudAccess : item.maxStage === stageFilter)) &&
        (!query.trim() || item.ip.includes(query.trim())),
    )
  }, [list, stageFilter, query])

  return (
    <div className="min-h-full space-y-3 p-4">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <p className="text-[18px] font-bold text-[#101828]">공격 IP 추적</p>
          <p className="text-[11.5px] text-[#667085]">IP 별로 공격이 어디까지 들어왔는지 탐지 로그 기준으로 보여줍니다.</p>
        </div>
        <div className="flex rounded-lg border border-[#D0D5DD] bg-white p-0.5">
          {(["24h", "7d"] as RangeKey[]).map((key) => (
            <button
              key={key}
              type="button"
              onClick={() => setRange(key)}
              className={`rounded-md px-3 py-1 text-[11.5px] font-semibold ${
                range === key ? "bg-[#101828] text-white" : "text-[#475467] hover:bg-[#F2F4F7]"
              }`}
            >
              {key === "24h" ? "24시간" : "7일"}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2 lg:grid-cols-4">
        <SummaryCard label="추적 IP" value={list?.summary.ips ?? 0} tone="#101828" />
        <SummaryCard label="WAF 통과 (S3·S4)" value={list?.summary.passedIps ?? 0} tone="#B42318" />
        <SummaryCard label="차단 후 재시도" value={list?.summary.bypassed ?? 0} tone="#D92D20" />
        <SummaryCard label="클라우드 권한 도달" value={list?.summary.cloud ?? 0} tone="#5925DC" />
      </div>

      {list?.truncated && (
        <p className="rounded-lg bg-[#FFFAEB] px-3 py-2 text-[11.5px] text-[#B54708]">
          조회 기간의 이벤트가 많아 최근 5,000건만 집계했습니다. 기간을 줄여 보세요.
        </p>
      )}

      <div className="grid gap-3 lg:grid-cols-[minmax(340px,420px)_1fr]">
        <section className="rounded-2xl border border-[#E4E7EC] bg-white">
          <div className="space-y-2 border-b border-[#EAECF0] p-3">
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="IP 검색"
              className="w-full rounded-lg border border-[#D0D5DD] px-3 py-1.5 text-[12px] outline-none focus:border-[#101828]"
            />
            <div className="flex flex-wrap gap-1">
              {STAGE_FILTERS.map((stage) => (
                <button
                  key={stage || "all"}
                  type="button"
                  onClick={() => setStageFilter(stage)}
                  className={`rounded-full px-2.5 py-0.5 text-[10.5px] font-semibold ${
                    stageFilter === stage ? "bg-[#101828] text-white" : "bg-[#F2F4F7] text-[#475467] hover:bg-[#E4E7EC]"
                  }`}
                >
                  {stage ? `${stage} ${STAGE_META[stage].label}` : "전체"}
                </button>
              ))}
            </div>
          </div>
          {error ? (
            <p className="p-4 text-[12px] text-[#B42318]">{error}</p>
          ) : !list ? (
            <p className="p-4 text-[12px] text-[#667085]">불러오는 중...</p>
          ) : items.length === 0 ? (
            <p className="p-4 text-[12px] text-[#667085]">조건에 맞는 IP 가 없습니다.</p>
          ) : (
            <ul className="max-h-[640px] divide-y divide-[#F2F4F7] overflow-y-auto">
              {items.map((item) => (
                <li key={item.ip}>
                  <button
                    type="button"
                    onClick={() => onSelectIp(item.ip)}
                    className={`w-full space-y-1 px-3 py-2.5 text-left hover:bg-[#F9FAFB] ${
                      selectedIp === item.ip ? "bg-[#F2F4F7]" : ""
                    }`}
                  >
                    <div className="flex items-center gap-1.5">
                      <span className="font-mono text-[12.5px] font-semibold text-[#101828]">{item.ip}</span>
                      {item.block.state === "bypassed" && (
                        <span className="rounded-full bg-[#D92D20] px-1.5 text-[9.5px] font-bold text-white">재시도</span>
                      )}
                      {item.block.state === "blocked" && (
                        <span className="rounded-full bg-[#ECFDF3] px-1.5 text-[9.5px] font-semibold text-[#067647]">차단됨</span>
                      )}
                      {item.isInternal && (
                        <span className="rounded-full bg-[#F2F4F7] px-1.5 text-[9.5px] font-semibold text-[#475467]">내부</span>
                      )}
                      <span className="ml-auto text-[10.5px] text-[#98A2B3]">{formatTime(item.lastSeen)}</span>
                    </div>
                    <div className="flex flex-wrap items-center gap-1">
                      <StageBadge stage={item.maxStage} confidence={item.maxStageConfidence} />
                      {item.cloudAccess && <StageBadge stage="C" />}
                      <span className="text-[10.5px] text-[#667085]">
                        {item.scenarioTypes.map((t) => SCENARIO_LABEL[t] ?? t).join(", ")}
                        {item.requestCount !== null && ` · 통과 ${formatCount(item.passedCount)}/${formatCount(item.requestCount)}`}
                      </span>
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="min-h-[300px] rounded-2xl border border-[#E4E7EC] bg-white">
          {selectedIp ? (
            <DetailPanel key={selectedIp} ip={selectedIp} range={range} onUnauthorized={handleUnauthorized} />
          ) : (
            <p className="p-6 text-[12px] text-[#667085]">왼쪽 목록에서 IP 를 선택하세요.</p>
          )}
        </section>
      </div>

      <p className="text-[10.5px] text-[#98A2B3]">
        IP 기준 집계이며 같은 공격자임을 보장하지 않습니다. WAF 통과 이후(k3s·Flask 등) 도달은 앱·ALB 로그가 수집되지 않아 추정으로 표시합니다.
        '예외 처리'된 이벤트는 최대 단계 계산에서 제외합니다.
      </p>
    </div>
  )
}
