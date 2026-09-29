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

// S1~S4/C 는 "공격이 거쳐가는 단계"가 아니라, 탐지된 이벤트 하나하나를 그
// 자체 결과로 분류하는 서로 독립적인 범주다(services/attack_reach.py 참고).
// "S"+숫자 표기가 Step처럼 순서를 암시해서 혼동을 줬으므로 화면에는 숫자
// 없이 라벨만 노출한다(내부 키는 하위 호환을 위해 유지).
export const STAGE_META: Record<Stage, { label: string; className: string }> = {
  S1: { label: "정찰만 탐지", className: "bg-[#EFF8FF] text-[#175CD3]" },
  S2: { label: "전체 차단", className: "bg-[#ECFDF3] text-[#067647]" },
  S3: { label: "일부 통과", className: "bg-[#FFFAEB] text-[#B54708]" },
  S4: { label: "완전 통과", className: "bg-[#FEF3F2] text-[#B42318]" },
  C: { label: "클라우드 권한 접근", className: "bg-[#F4F3FF] text-[#5925DC]" },
}
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

// 공격 "유형"(scenarioType)은 공격자가 뭘 시도했는지라 MITRE ATT&CK 전술/기법과
// 자연스럽게 대응된다(WAF가 막았는지는 별개 차원 - STAGE_META가 담당).
// 업계 표준 용어로 한 번 더 확인할 수 있게 참고용으로 붙인다.
const SCENARIO_MITRE: Record<string, { tactic: string; technique: string }> = {
  sqli: { tactic: "Initial Access", technique: "T1190 Exploit Public-Facing Application" },
  xss: { tactic: "Initial Access", technique: "T1190 Exploit Public-Facing Application" },
  dir: { tactic: "Reconnaissance", technique: "T1595.003 Active Scanning: Wordlist Scanning" },
  brute: { tactic: "Credential Access", technique: "T1110 Brute Force" },
  flood: { tactic: "Impact", technique: "T1498 Network Denial of Service" },
  port: { tactic: "Reconnaissance", technique: "T1595.001 Active Scanning: Scanning IP Blocks" },
  cred: { tactic: "Credential Access", technique: "T1552 Unsecured Credentials" },
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
  if (!stage) return <span className="text-[13px] text-[#98A2B3]">-</span>
  const meta = STAGE_META[stage]
  return (
    <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[12.5px] font-semibold ${meta.className}`}>
      {meta.label}
      {confidence && confidence !== "confirmed" && (
        <span className="font-medium opacity-75">· {CONFIDENCE_LABEL[confidence]}</span>
      )}
    </span>
  )
}

function BlockBadge({ block }: { block: BlockState }) {
  if (block.state === "bypassed")
    return (
      <span className="rounded-full bg-[#D92D20] px-2 py-0.5 text-[12.5px] font-bold text-white">
        차단 후 재시도
      </span>
    )
  if (block.state === "blocked")
    return (
      <span className="rounded-full bg-[#ECFDF3] px-2 py-0.5 text-[12.5px] font-semibold text-[#067647]">
        차단됨 {formatTime(block.at)}
      </span>
    )
  if (block.state === "excluded")
    return (
      <span
        title="Remediation Lambda 가 차단하지 않는 주소입니다."
        className="rounded-full bg-[#F2F4F7] px-2 py-0.5 text-[12.5px] font-semibold text-[#667085]"
      >
        차단 제외 · {block.reason}
      </span>
    )
  return (
    <span className="rounded-full bg-[#FFFAEB] px-2 py-0.5 text-[12.5px] font-semibold text-[#B54708]">
      미차단
    </span>
  )
}

function SummaryCard({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <div className="rounded-xl border border-[#E4E7EC] bg-white px-4 py-3">
      <p className="text-[13px] font-semibold text-[#667085]">{label}</p>
      <p className="mt-1 text-[24px] font-bold" style={{ color: tone }}>
        {value}
      </p>
    </div>
  )
}

// 예전엔 "S1→S2→S3→S4를 순서대로 거쳤다"는 식의 퍼널로 그렸는데, 실제로는
// 이벤트마다 독립적으로 분류된 결과라 그 전제가 틀렸다(위 STAGE_META 주석
// 참고). 그래서 화살표로 잇지 않고, 이 IP가 실제로 겪은 결과들만 순서
//없이 나열한다 - 겪지 않은 건 아예 안 보여준다.
function OutcomeBadges({ detail }: { detail: AttackerDetail }) {
  const present = Array.from(new Set(detail.timeline.map((item) => item.stage)))
  if (present.length === 0) return null
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      <span className="text-[12px] font-semibold text-[#98A2B3]">이 IP 가 겪은 결과</span>
      {present.map((stage) => (
        <span
          key={stage}
          className={`rounded-md px-2 py-1 text-[13px] font-semibold ${STAGE_META[stage].className}`}
        >
          {STAGE_META[stage].label}
        </span>
      ))}
    </div>
  )
}

function ReachMap({ reach }: { reach: Reach }) {
  const statuses: Record<string, AssetStatus> = {}
  reach.estimated.forEach((id) => (statuses[id] = "warning"))
  reach.confirmed.forEach((id) => (statuses[id] = "critical"))
  const lit = [...reach.confirmed, ...reach.estimated]
  return (
    <div className="relative h-[480px]">
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

interface ScenarioGroup {
  scenarioType: string
  events: TimelineItem[]
  firstTime: string
  lastTime: string
  totalRequests: number | null
  totalPassed: number | null
  outcomes: Stage[]
}

function groupByScenario(timeline: TimelineItem[]): ScenarioGroup[] {
  const map = new Map<string, TimelineItem[]>()
  timeline.forEach((item) => {
    const list = map.get(item.scenarioType) ?? []
    list.push(item)
    map.set(item.scenarioType, list)
  })
  return Array.from(map.entries())
    .map(([scenarioType, events]) => {
      const sortedTimes = [...events].map((e) => e.time).sort()
      const withRequests = events.filter((e) => e.requests !== null)
      const totalRequests =
        withRequests.length > 0 ? withRequests.reduce((sum, e) => sum + (e.requests ?? 0), 0) : null
      const totalPassed =
        withRequests.length > 0 ? withRequests.reduce((sum, e) => sum + (e.passed ?? 0), 0) : null
      return {
        scenarioType,
        events: [...events].sort((a, b) => a.time.localeCompare(b.time)),
        firstTime: sortedTimes[0],
        lastTime: sortedTimes[sortedTimes.length - 1],
        totalRequests,
        totalPassed,
        outcomes: Array.from(new Set(events.map((e) => e.stage))),
      }
    })
    .sort((a, b) => b.lastTime.localeCompare(a.lastTime))
}

// 시간축 그래프 대신, 이 IP가 일으킨 이벤트들을 "무슨 공격을 시도했는지"
// (scenarioType) 기준으로 묶어서 카드로 보여준다 - 개별 이벤트를 흩어진
// 점으로 보는 것보다 "이 IP는 SQLi 2번, 포트 스캔 1번을 시도했다" 처럼
// 공격 시나리오 단위로 읽는 게 더 자연스럽다는 피드백을 반영했다.
function ScenarioGroups({
  detail,
  highlightId,
  onSelectEvent,
}: {
  detail: AttackerDetail
  highlightId: string | null
  onSelectEvent: (eventId: string) => void
}) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const groups = useMemo(() => groupByScenario(detail.timeline), [detail.timeline])

  if (groups.length === 0) {
    return (
      <div className="rounded-2xl border border-[#E4E7EC] bg-white p-4 text-[13px] text-[#667085]">
        모아서 보여줄 이벤트가 없습니다.
      </div>
    )
  }

  const toggle = (scenarioType: string) => {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(scenarioType)) next.delete(scenarioType)
      else next.add(scenarioType)
      return next
    })
  }

  return (
    <div className="space-y-2">
      <p className="text-[13px] font-bold text-[#101828]">공격 시나리오별로 모아보기</p>
      {groups.map((group) => {
        const mitre = SCENARIO_MITRE[group.scenarioType]
        const isOpen = expanded.has(group.scenarioType)
        const remediationsForGroup = detail.remediations.filter((r) =>
          group.events.some((e) => e.eventId === r.eventId),
        )
        return (
          <div key={group.scenarioType} className="rounded-2xl border border-[#E4E7EC] bg-white">
            <button
              type="button"
              onClick={() => toggle(group.scenarioType)}
              className="flex w-full flex-wrap items-center gap-2 px-3 py-2.5 text-left hover:bg-[#F9FAFB]"
            >
              <span className="text-[14px] font-bold text-[#101828]">
                {SCENARIO_LABEL[group.scenarioType] ?? group.scenarioType}
              </span>
              <span className="text-[12.5px] text-[#667085]">
                {group.events.length}건 · {formatTime(group.firstTime)} ~ {formatTime(group.lastTime)}
                {group.totalRequests !== null &&
                  ` · 요청 ${formatCount(group.totalRequests)}건 중 ${formatCount(group.totalPassed)}건 통과`}
              </span>
              <div className="ml-auto flex flex-wrap items-center gap-1">
                {group.outcomes.map((stage) => (
                  <span
                    key={stage}
                    className={`rounded-full px-2 py-0.5 text-[11.5px] font-semibold ${STAGE_META[stage].className}`}
                  >
                    {STAGE_META[stage].label}
                  </span>
                ))}
                <span className={`text-[#98A2B3] transition-transform ${isOpen ? "rotate-180" : ""}`}>⌄</span>
              </div>
            </button>
            {mitre && (
              <p className="px-3 pb-2 text-[11px] text-[#98A2B3]">
                MITRE ATT&amp;CK 참고: {mitre.tactic} · {mitre.technique}
              </p>
            )}
            {isOpen && (
              <div className="space-y-1.5 border-t border-[#EAECF0] px-3 py-2.5">
                {group.events.map((ev) => (
                  <button
                    type="button"
                    key={ev.eventId}
                    id={`tl-${ev.eventId}`}
                    onClick={() => onSelectEvent(ev.eventId)}
                    className={`block w-full rounded-lg border px-3 py-2 text-left text-[13px] transition-colors ${
                      highlightId === ev.eventId
                        ? "border-[#101828] bg-[#F2F4F7]"
                        : "border-[#EAECF0] hover:bg-[#F9FAFB]"
                    } ${ev.excluded ? "opacity-50" : ""}`}
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="tabular-nums text-[#667085]">{formatTime(ev.time)}</span>
                      <span className="font-semibold text-[#101828]">{ev.title}</span>
                      <span
                        className={`ml-auto rounded-full px-2 py-0.5 text-[11px] font-semibold ${STAGE_META[ev.stage].className}`}
                      >
                        {STAGE_META[ev.stage].label}
                      </span>
                    </div>
                    <p className="mt-0.5 text-[12px] text-[#667085]">
                      {ev.requests !== null
                        ? `요청 ${formatCount(ev.requests)}건 중 ${formatCount(ev.passed)}건 통과`
                        : ev.stage === "S1"
                          ? `대상 ${ev.target ?? "미확인"}`
                          : ev.stage === "C"
                            ? "AWS API 호출 (네트워크 경로 아님)"
                            : "요청 수 정보 없음"}
                      {ev.source === "admin" && " · 관리자 ALB"}
                      {` · ${ev.status}`}
                    </p>
                  </button>
                ))}
                {remediationsForGroup.map((r) => (
                  <p
                    key={`rem-${r.eventId}-${r.time}`}
                    className="text-center text-[12.5px] font-semibold text-[#067647]"
                  >
                    {formatTime(r.time)} {ACTION_LABEL[r.action ?? ""] ?? r.action} · {r.result}
                  </p>
                ))}
              </div>
            )}
          </div>
        )
      })}
    </div>
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
  const [highlightId, setHighlightId] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    setDetail(null)
    setError(null)
    setHighlightId(null)
    fetchJson<AttackerDetail>(`/api/attackers/${encodeURIComponent(ip)}?range=${range}`, onUnauthorized)
      .then((data) => !cancelled && setDetail(data))
      .catch((err: Error) => !cancelled && setError(err.message))
    return () => {
      cancelled = true
    }
  }, [ip, range, onUnauthorized])

  if (error) return <p className="p-6 text-[14px] text-[#B42318]">{error}</p>
  if (!detail) return <p className="p-6 text-[14px] text-[#667085]">불러오는 중...</p>

  const s = detail.summary
  return (
    <div className="space-y-3 p-4">
      <div className="flex flex-wrap items-center gap-2">
        <p className="font-mono text-[20px] font-bold text-[#101828]">{detail.ip}</p>
        <BlockBadge block={s.block} />
        {s.isInternal && (
          <span className="rounded-full bg-[#F2F4F7] px-2 py-0.5 text-[12.5px] font-semibold text-[#475467]">내부 발신</span>
        )}
        <span className="ml-auto text-[13px] text-[#667085]">
          {formatTime(s.firstSeen)} ~ {formatTime(s.lastSeen)} · 이벤트 {s.eventCount}건 · 요청 {formatCount(s.requestCount)}건 중{" "}
          {formatCount(s.passedCount)}건 통과
        </span>
      </div>
      <OutcomeBadges detail={detail} />
      {s.block.state === "bypassed" && (
        <p className="rounded-lg bg-[#FEF3F2] px-3 py-2 text-[13.5px] text-[#B42318]">
          IP 차단({formatTime(s.block.at)}) 이후에도 WAF 를 통과한 요청이 있습니다. 차단 목록 반영 여부와 WAF 규칙 순서를 확인하세요.
        </p>
      )}
      {/* 구조도는 폭이 좁아지면 축소 스케일이 확 줄어서 내용이 잘려 보이므로
          다른 패널과 나란히 두지 않고 전체 폭을 그대로 준다. */}
      <ReachMap reach={detail.reach} />
      <div className="flex flex-wrap gap-3 text-[12.5px] text-[#667085]">
        <span className="flex items-center gap-1">
          <span className="inline-block h-3 w-3 rounded-sm ring-2 ring-[#D92D20]" /> 로그로 확인된 도달
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block h-3 w-3 rounded-sm outline-2 outline-dashed outline-[#F79009]" /> 추정 도달 (ALB 이후 앱 로그 미수집)
        </span>
      </div>
      <div className="max-h-[480px] overflow-y-auto">
        <ScenarioGroups detail={detail} highlightId={highlightId} onSelectEvent={setHighlightId} />
      </div>
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
          <p className="text-[20px] font-bold text-[#101828]">공격 IP 추적</p>
          <p className="text-[13.5px] text-[#667085]">IP 별로 공격이 어디까지 들어왔는지 탐지 로그 기준으로 보여줍니다.</p>
        </div>
        <div className="flex rounded-lg border border-[#D0D5DD] bg-white p-0.5">
          {(["24h", "7d"] as RangeKey[]).map((key) => (
            <button
              key={key}
              type="button"
              onClick={() => setRange(key)}
              className={`rounded-md px-3 py-1 text-[13.5px] font-semibold ${
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
        <p className="rounded-lg bg-[#FFFAEB] px-3 py-2 text-[13.5px] text-[#B54708]">
          조회 기간의 이벤트가 많아 최근 5,000건만 집계했습니다. 기간을 줄여 보세요.
        </p>
      )}

      <section className="space-y-2 rounded-2xl border border-[#E4E7EC] bg-white p-3">
        <div className="flex flex-wrap items-center gap-2">
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="IP 검색"
            className="w-48 rounded-lg border border-[#D0D5DD] px-3 py-1.5 text-[14px] outline-none focus:border-[#101828]"
          />
          <div className="flex flex-wrap gap-1">
            {STAGE_FILTERS.map((stage) => (
              <button
                key={stage || "all"}
                type="button"
                onClick={() => setStageFilter(stage)}
                className={`rounded-full px-2.5 py-0.5 text-[12.5px] font-semibold ${
                  stageFilter === stage ? "bg-[#101828] text-white" : "bg-[#F2F4F7] text-[#475467] hover:bg-[#E4E7EC]"
                }`}
              >
                {stage ? STAGE_META[stage].label : "전체"}
              </button>
            ))}
          </div>
        </div>
        {error ? (
          <p className="p-2 text-[14px] text-[#B42318]">{error}</p>
        ) : !list ? (
          <p className="p-2 text-[14px] text-[#667085]">불러오는 중...</p>
        ) : items.length === 0 ? (
          <p className="p-2 text-[14px] text-[#667085]">조건에 맞는 IP 가 없습니다.</p>
        ) : (
          // 세로 목록 대신 가로로 훑어보는 칩 목록 - IP 선택이 화면 상단에서
          // 한눈에 끝나고, 아래는 선택한 IP의 재구성 화면에 전부 쓸 수 있다.
          // overflow-x-auto를 주면 overflow-y도 자동으로 auto가 돼서 선택된
          // 칩의 ring이 위아래로 살짝 잘려 보인다 - py로 ring이 들어갈 공간을 확보한다.
          <div className="flex gap-2 overflow-x-auto px-0.5 py-1">
            {items.map((item) => (
              <button
                key={item.ip}
                type="button"
                onClick={() => onSelectIp(item.ip)}
                className={`min-w-[168px] flex-shrink-0 space-y-1 rounded-xl border px-3 py-2 text-left transition-colors ${
                  selectedIp === item.ip
                    ? "border-[#101828] bg-[#F2F4F7] ring-1 ring-[#101828]"
                    : "border-[#E4E7EC] bg-white hover:bg-[#F9FAFB]"
                }`}
              >
                <div className="flex flex-wrap items-center gap-1">
                  <span className="font-mono text-[13px] font-semibold text-[#101828]">{item.ip}</span>
                  {item.block.state === "bypassed" && (
                    <span className="rounded-full bg-[#D92D20] px-1.5 text-[10.5px] font-bold text-white">재시도</span>
                  )}
                  {item.block.state === "blocked" && (
                    <span className="rounded-full bg-[#ECFDF3] px-1.5 text-[10.5px] font-semibold text-[#067647]">차단됨</span>
                  )}
                  {item.isInternal && (
                    <span className="rounded-full bg-[#F2F4F7] px-1.5 text-[10.5px] font-semibold text-[#475467]">내부</span>
                  )}
                </div>
                <div className="flex flex-wrap items-center gap-1">
                  <StageBadge stage={item.maxStage} confidence={item.maxStageConfidence} />
                  {item.cloudAccess && <StageBadge stage="C" />}
                </div>
                <p className="text-[11px] text-[#98A2B3]">{formatTime(item.lastSeen)}</p>
              </button>
            ))}
          </div>
        )}
      </section>

      <section className="min-h-[300px] rounded-2xl border border-[#E4E7EC] bg-white">
        {selectedIp ? (
          <DetailPanel key={selectedIp} ip={selectedIp} range={range} onUnauthorized={handleUnauthorized} />
        ) : (
          <p className="p-6 text-[14px] text-[#667085]">위 목록에서 IP 를 선택하세요.</p>
        )}
      </section>

      <p className="text-[12.5px] text-[#98A2B3]">
        IP 기준 집계이며 같은 공격자임을 보장하지 않습니다. WAF 통과 이후(k3s·Flask 등) 도달은 앱·ALB 로그가 수집되지 않아 추정으로 표시합니다.
        '예외 처리'된 이벤트는 최대 단계 계산에서 제외합니다.
      </p>
    </div>
  )
}
