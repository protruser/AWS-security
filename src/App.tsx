import React, { useState, useEffect, useRef } from "react"
import type {
  AssetStatus,
  RightTab,
  ActionEvent,
  ScenarioCard,
  DetectHistoryItem,
  RemediationHistoryItem,
  DashboardApiResponse,
  NumericOverviewMetric,
  OverviewMetricsResponse,
} from "./data/types"

import { SCENARIO_CARDS, SUGGESTED_QUESTIONS } from "./data/staticContent"

import { ASSETS } from "./data/architecture"

import { ArchitectureMap } from "./components/ArchitectureMap"
import { ScenarioPage } from "./components/ScenarioPage"
import { ManualMonitoringPage } from "./components/ManualMonitoringPage"
import { AIDiagnosisPage } from "./components/AIDiagnosisPage"
import { ApprovalQueuePage, ApprovalRequestList } from "./components/ApprovalQueuePage"
import { ApprovalModal, DonutGauge, SeverityBadge } from "./components/common"
import { LoginPage } from "./components/LoginPage"
import { fetchOverviewMetrics } from "./services/dashboardApi"
import { EventDetailModal } from "./components/EventDetailModal"
import { eventDisplayTitle } from "./services/eventAnalysis"

// ─── Action card ──────────────────────────────────────────────────────────────
function canRemediate(event: ActionEvent) {
  // 백엔드 REMEDIATION_ACTIONS와 반드시 같은 목록이어야 한다(안 그러면 "자동 조치
  // 가능" 배지는 뜨는데 승인 버튼은 "수동 조치 필요"로 나오는 불일치가 생김).
  return ["sqli", "dir", "brute", "xss", "cred", "port", "flood"].includes(event.scenarioType ?? "")
    && !["조치 완료", "자동 완료", "완료", "예외 처리"].includes(event.status)
}

const SEVERITY_RANK: Record<string, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
  Info: 4,
}

type ActionSortKey = "time" | "severity"

function sortActionEvents(items: ActionEvent[], sortKey: ActionSortKey): ActionEvent[] {
  if (sortKey === "time") return items
  return [...items].sort(
    (a, b) => (SEVERITY_RANK[a.severity] ?? 99) - (SEVERITY_RANK[b.severity] ?? 99),
  )
}

function isPendingApproval(event: ActionEvent) {
  // 백엔드의 PENDING_APPROVAL_STATUS/MANUAL_APPROVED_STATUS와 반드시 같은
  // 문자열이어야 한다. "승인 대기"는 Lambda A가 자동 조치 가능한 탐지 건에
  // 기본으로 붙이는 상태(아직 아무도 안 건드림)라 겹치면 안 된다 - 실제로
  // 겹쳐서 요청을 하나도 안 보낸 건들까지 전부 잠겨버렸던 적이 있다.
  return event.status === "승인 요청됨" || event.status === "수동 조치 대기"
}

function ActionCard({
  ev,
  selected,
  onSelect,
  checked,
  onToggleCheck,
}: {
  ev: ActionEvent
  selected: boolean
  onSelect: () => void
  checked: boolean
  onToggleCheck: () => void
}) {
  return (
    <div
      role="group"
      tabIndex={0}
      aria-label={`${eventDisplayTitle(ev)} 상세 보기`}
      onClick={(event) => {
        event.currentTarget.focus()
        onSelect()
      }}
      onKeyDown={(event) => {
        if (event.target === event.currentTarget && (event.key === "Enter" || event.key === " ")) {
          event.preventDefault()
          onSelect()
        }
      }}
      className={`relative rounded-xl border cursor-pointer transition-all overflow-hidden ${
        selected
          ? "border-[#101828] ring-2 ring-[#101828]/10 shadow-sm"
          : "border-[#EAECF0] hover:border-[#D0D5DD] hover:shadow-sm"
      } bg-white`}
    >
      {ev.severity === "Critical" && (
        <div className="absolute left-0 top-0 bottom-0 w-1 bg-[#D92D20]" />
      )}
      <div className={`p-3 ${ev.severity === "Critical" ? "pl-4" : ""}`}>
        <div className="flex items-start justify-between gap-2 mb-1.5">
          <div className="flex items-center gap-1.5 flex-wrap">
            <input
              type="checkbox"
              checked={checked}
              onClick={(e) => e.stopPropagation()}
              onChange={onToggleCheck}
              aria-label="일괄 예외 처리를 위해 선택"
              className="h-3.5 w-3.5 rounded border-[#D0D5DD] accent-[#111111] cursor-pointer"
            />
            <SeverityBadge sev={ev.severity} small />
            {ev.autoRemediation && (
              <span className="text-[9px] font-semibold px-1.5 py-0.5 rounded-full bg-[#F5F5F5] text-[#111111]">
                자동 조치 가능
              </span>
            )}
            {(ev.occurrenceCount ?? 1) > 1 && (
              <span
                className="text-[9px] font-semibold px-1.5 py-0.5 rounded-full bg-[#FEF0C7] text-[#B54708]"
                title="같은 종류로 반복 감지된 것을 최신 1건으로 합쳐서 보여주고 있어요"
              >
                {ev.occurrenceCount}번 반복 감지
              </span>
            )}
          </div>
          <span className="text-[10px] text-[#6B6B6B] whitespace-nowrap">
            미조치 {ev.elapsed}
          </span>
        </div>
        <p className="text-xs font-bold text-[#0D0D0D] mb-1">{eventDisplayTitle(ev)}</p>
        <div className="flex items-center gap-2 mb-1 flex-wrap">
          <span className="text-[10px] text-[#111111] font-medium">
            {ev.service}
          </span>
          <span className="text-[10px] text-[#6B6B6B]">{ev.asset}</span>
        </div>
        <p className="text-[10px] text-[#6B6B6B]">
          {ev.detectedAt} ·{" "}
          <span className="text-[#F79009] font-semibold">{ev.status}</span>
        </p>
      </div>
    </div>
  )
}

// ─── Right panel (top half) ───────────────────────────────────────────────────

function RightPanel({
  tab,
  setTab,
  events,
  detectHistory,
  remediationHistory,
  selectedEvent,
  onSelectEvent,
  onApprove,
  onExcept,
  onBulkRequest,
  role,
  onUnauthorized,
}: {
  tab: RightTab
  setTab: (t: RightTab) => void

  events: ActionEvent[]
  detectHistory: DetectHistoryItem[]
  remediationHistory: RemediationHistoryItem[]

  selectedEvent: ActionEvent | null

  onSelectEvent: (ev: ActionEvent | null) => void

  onApprove: (ev: ActionEvent) => void
  onExcept: (eventIds: string[]) => void
  onBulkRequest: (eventIds: string[]) => void
  role: string
  onUnauthorized: () => void
}) {
  const [detectFilter, setDetectFilter] = useState("전체")
  const [checkedIds, setCheckedIds] = useState<Set<string>>(new Set())
  const [requestCheckedIds, setRequestCheckedIds] = useState<Set<string>>(new Set())
  const [autoSortKey, setAutoSortKey] = useState<ActionSortKey>("time")
  const [manualSortKey, setManualSortKey] = useState<ActionSortKey>("time")
  const [detailEventId, setDetailEventId] = useState<string | null>(null)

  useEffect(() => {
    if (tab !== "action") setDetailEventId(null)
  }, [tab])

  // 탐지/조치 이력은 이미 처리(차단 등)가 끝난 이벤트라 "조치 필요" 목록엔 없다.
  // 그래도 클릭하면 AI 챗봇 컨텍스트로 넘길 수 있게 ActionEvent 모양으로 맞춰준다.
  const detectHistoryToEvent = (d: DetectHistoryItem): ActionEvent => ({
    id: String(d.id),
    severity: d.sev,
    title: d.event,
    scenarioType: d.scenarioType,
    service: d.service,
    asset: d.asset,
    detectedAt: d.time,
    elapsed: "",
    status: d.status,
    recommendation: "",
    autoRemediation: false,
    highlightAssets: [],
    attackPath: [],
    details: {
      attackerIP: d.ip && d.ip !== "-" ? d.ip : undefined,
      blocked: d.blocked === "차단" ? true : d.blocked === "-" ? undefined : undefined,
      logs: "",
    },
  })

  const remediationToEvent = (r: RemediationHistoryItem): ActionEvent => ({
    id: String(r.id),
    severity: "Info",
    title: r.event,
    scenarioType: r.scenarioType,
    service: "-",
    asset: r.asset,
    detectedAt: r.completedAt || r.time,
    elapsed: "",
    status: r.result,
    recommendation: "",
    autoRemediation: false,
    highlightAssets: [],
    attackPath: [],
    details: {
      attackerIP: r.ip ?? undefined,
      blocked: r.ip ? true : undefined,
      logs: `${r.method} 조치 · 승인 ${r.approver} · ${r.completedAt}`,
    },
  })

  const detectFilters = ["전체", "Critical", "High", "Medium", "Low"]

  const activeEvents = events
  const detailEvent = activeEvents.find((event) => event.id === detailEventId) ?? null
  const autoEvents = activeEvents.filter(canRemediate)
  const manualEvents = activeEvents.filter((ev) => !canRemediate(ev))

  const toggleChecked = (id: string) => {
    setCheckedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const toggleRequestChecked = (id: string) => {
    setRequestCheckedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  // "승인요청"에는 자동 조치 정책이 없는 수동 이벤트만 표시한다.
  const requestableEvents = activeEvents.filter(
    (ev) => !canRemediate(ev) && !isPendingApproval(ev) && ev.status !== "예외 처리",
  )

  const handleBulkRequest = () => {
    const eventIds = requestableEvents.filter((event) => requestCheckedIds.has(event.id)).map((event) => event.id)
    if (eventIds.length === 0) return
    onBulkRequest(eventIds)
    setRequestCheckedIds(new Set())
  }

  const handleBulkExcept = () => {
    if (checkedIds.size === 0) return
    onExcept([...checkedIds])
    setCheckedIds(new Set())
  }

  // 승인자는 탐지이력/조치필요/조치이력을 볼 필요가 없다 - 책임은 승인/반려뿐이라
  // 탭 자체를 없애고 요청 목록만 바로 보여준다.
  if (role === "승인자") {
    return (
      <div className="flex flex-col min-h-full p-3">
        <p className="text-[11px] font-bold text-[#101828] mb-2">승인 대기 목록</p>
        <ApprovalRequestList role={role} onUnauthorized={onUnauthorized} />
      </div>
    )
  }

  return (
    <div className="flex flex-col min-h-full">
      {/* Tabs — segmented control */}
      <div className="flex-shrink-0 px-3 pt-3 pb-1">
        <div role="tablist" className="flex gap-1 p-1 rounded-xl bg-[#EEF0F3]">
          {[
            { key: "detect", label: "탐지 이력" },

            { key: "action", label: "조치 필요", count: activeEvents.length },

            { key: "requests", label: "승인요청" },

            { key: "history", label: "조치 이력" },
          ].map((t) => (
            <button
              key={t.key}
              role="tab"
              aria-selected={tab === t.key}
              onClick={() => setTab(t.key as RightTab)}
              className={`flex-1 py-1.5 text-xs font-semibold rounded-lg transition-all flex items-center justify-center gap-1.5 ${
                tab === t.key
                  ? "bg-white text-[#101828] shadow-[0_1px_2px_rgba(16,24,40,0.12)]"
                  : "text-[#667085] hover:text-[#101828]"
              }`}
            >
              {t.label}
              {t.count !== undefined && (
                <span
                  className={`text-[9px] font-bold px-1.5 py-0.5 rounded-full ${
                    tab === t.key
                      ? "bg-[#D92D20] text-white"
                      : "bg-[#D0D5DD] text-white"
                  }`}
                >
                  {t.count}
                </span>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* Action tab */}
      {tab === "action" && (
        <div className="p-3">
          {checkedIds.size > 0 && (
            <div className="flex items-center justify-between gap-2 mb-2.5 rounded-lg bg-[#F2F4F7] px-2.5 py-1.5">
              <span className="text-[11px] font-medium text-[#344054]">
                {checkedIds.size}개 선택됨
              </span>
              <div className="flex items-center gap-1.5">
                <button
                  onClick={() => setCheckedIds(new Set())}
                  className="text-[10px] text-[#6B6B6B] hover:text-[#111111] px-2 py-1"
                >
                  선택 해제
                </button>
                <button
                  onClick={handleBulkExcept}
                  className="text-[11px] font-semibold text-white bg-[#111111] hover:bg-[#262626] px-2.5 py-1.5 rounded-lg transition-colors"
                >
                  선택 항목 일괄 예외 처리
                </button>
              </div>
            </div>
          )}
          {activeEvents.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-32 text-[#6B6B6B]">
              <span className="text-2xl mb-2">✅</span>
              <p className="text-sm font-medium">조치 필요 항목 없음</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
              {[
                { label: "자동 조치", items: autoEvents, sortKey: autoSortKey, setSortKey: setAutoSortKey },
                { label: "수동 조치", items: manualEvents, sortKey: manualSortKey, setSortKey: setManualSortKey },
              ].map(({ label, items, sortKey, setSortKey }) => (
                <div key={label}>
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <p className="text-[11px] font-bold text-[#344054]">
                      {label} ({items.length})
                    </p>
                    <div className="inline-flex rounded-lg border border-[#D0D5DD] bg-white p-0.5">
                      {(["severity", "time"] as const).map((key) => (
                        <button
                          key={key}
                          onClick={() => setSortKey(key)}
                          className={`text-[10px] font-semibold px-2 py-1 rounded-md transition-colors ${
                            sortKey === key
                              ? "bg-[#101828] text-white"
                              : "text-[#667085] hover:text-[#101828]"
                          }`}
                        >
                          {key === "severity" ? "위험도순" : "시간순"}
                        </button>
                      ))}
                    </div>
                  </div>
                  {items.length === 0 ? (
                    <div className="flex items-center justify-center h-16 text-[#98A2B3]">
                      <p className="text-[11px] font-medium">항목 없음</p>
                    </div>
                  ) : (
                    <div
                      role="region"
                      aria-label={`${label} 이벤트 목록`}
                      tabIndex={0}
                      className="space-y-2.5 max-h-[min(520px,55vh)] overflow-y-auto overscroll-y-contain [scrollbar-gutter:stable]"
                    >
                      {sortActionEvents(items, sortKey).map((ev: ActionEvent) => (
                        <ActionCard
                          key={ev.id}
                          ev={ev}
                          selected={selectedEvent?.id === ev.id}
                          onSelect={() => {
                            if (selectedEvent?.id !== ev.id) onSelectEvent(ev)
                            setDetailEventId(ev.id)
                          }}
                          checked={checkedIds.has(ev.id)}
                          onToggleCheck={() => toggleChecked(ev.id)}
                        />
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* 승인요청 탭: 위쪽은 아직 요청 안 보낸 것들 일괄 선택, 아래쪽은 이미 보낸 요청 현황 */}
      {tab === "requests" && (
        <div className="p-3 space-y-4">
          <div>
            <div className="flex items-center justify-between gap-2 mb-2">
              <label className="flex items-center gap-1.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={
                    requestableEvents.length > 0 &&
                    requestableEvents.every((ev) => requestCheckedIds.has(ev.id))
                  }
                  onChange={(e) =>
                    setRequestCheckedIds(
                      e.target.checked
                        ? new Set(requestableEvents.map((ev) => ev.id))
                        : new Set(),
                    )
                  }
                  disabled={requestableEvents.length === 0}
                  className="h-3.5 w-3.5 rounded border-[#D0D5DD] accent-[#111111]"
                />
                <p className="text-[11px] font-bold text-[#101828]">
                  요청 대기 중인 항목 ({requestableEvents.length}) · 전체 선택
                </p>
              </label>
              {requestCheckedIds.size > 0 && (
                <button
                  onClick={handleBulkRequest}
                  className="text-[11px] font-bold text-white bg-[#111111] hover:bg-[#262626] rounded-lg px-2.5 py-1.5"
                >
                  선택한 {requestCheckedIds.size}건 승인 요청 보내기
                </button>
              )}
            </div>
            {requestableEvents.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-20 text-[#98A2B3]">
                <p className="text-xs font-medium">요청 보낼 수 있는 항목이 없습니다.</p>
              </div>
            ) : (
              <div className="space-y-1.5 max-h-64 overflow-auto">
                {requestableEvents.map((ev) => (
                  <label
                    key={ev.id}
                    className="flex items-center gap-2 rounded-lg border border-[#EAECF0] bg-white px-2.5 py-1.5 cursor-pointer hover:border-[#D0D5DD]"
                  >
                    <input
                      type="checkbox"
                      checked={requestCheckedIds.has(ev.id)}
                      onChange={() => toggleRequestChecked(ev.id)}
                      className="h-3.5 w-3.5 rounded border-[#D0D5DD] accent-[#111111]"
                    />
                    <SeverityBadge sev={ev.severity} small />
                    <span className="text-[11px] font-semibold text-[#101828] flex-1 truncate">
                      {eventDisplayTitle(ev)}
                    </span>
                    <button
                      onClick={(e) => {
                        e.preventDefault()
                        e.stopPropagation()
                        onApprove(ev)
                      }}
                      className="text-[10px] font-bold text-[#475467] hover:text-[#101828] flex-shrink-0"
                    >
                      개별 요청
                    </button>
                  </label>
                ))}
              </div>
            )}
          </div>

          <div className="pt-3 border-t border-[#EAECF0]">
            <p className="text-[11px] font-bold text-[#101828] mb-2">보낸 요청 현황</p>
            <ApprovalRequestList role={role} onUnauthorized={onUnauthorized} compact />
          </div>
        </div>
      )}

      {/* Remediation history tab */}
      {tab === "history" && (
        <div className="p-3">
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-2">
            {remediationHistory.map((r) => (
              <div
                key={r.id}
                onClick={() => onSelectEvent(remediationToEvent(r))}
                className="rounded-xl border border-[#EAECF0] bg-white p-3 cursor-pointer hover:bg-[#FAFAFA] transition-colors"
              >
                <div className="flex items-center justify-between gap-2">
                  <p className="text-xs font-bold text-[#0D0D0D]">{eventDisplayTitle({ title: r.event, scenarioType: r.scenarioType })}</p>
                  <div className="flex items-center gap-1 flex-shrink-0">
                    {(r.occurrenceCount ?? 1) > 1 && (
                      <span
                        className="text-[9px] font-semibold px-1.5 py-0.5 rounded-full bg-[#FEF0C7] text-[#B54708]"
                        title="같은 종류로 반복된 조치를 최신 1건으로 합쳐서 보여주고 있어요"
                      >
                        {r.occurrenceCount}건
                      </span>
                    )}
                    <span className="text-[9px] font-bold px-1.5 py-0.5 rounded-full bg-[#16A34A] text-white">
                      {r.result}
                    </span>
                  </div>
                </div>
                <p className="text-[10px] text-[#6B6B6B] mt-1">{r.asset}</p>
                <div className="flex flex-wrap gap-1 mt-1.5">
                  {r.ip && (
                    <span className="text-[10px] font-mono bg-[#FEF3F2] text-[#B42318] rounded px-1.5 py-0.5">
                      {r.ip}
                    </span>
                  )}
                  <span className="text-[10px] bg-[#F2F4F7] text-[#475467] rounded px-1.5 py-0.5">
                    {r.method} 조치
                  </span>
                  <span className="text-[10px] bg-[#F2F4F7] text-[#475467] rounded px-1.5 py-0.5">
                    승인 {r.approver}
                  </span>
                  <span className="text-[10px] bg-[#F2F4F7] text-[#475467] rounded px-1.5 py-0.5 font-mono">
                    {r.completedAt}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Detect history tab */}
      {tab === "detect" && (
        <div className="p-3 space-y-2.5">
          <div className="flex gap-1 flex-wrap">
            {detectFilters.map((f) => (
              <button
                key={f}
                onClick={() => setDetectFilter(f)}
                className={`text-[10px] font-medium px-2 py-1 rounded-full transition-colors ${
                  detectFilter === f
                    ? "bg-[#111111] text-white"
                    : "bg-[#F5F5F5] text-[#6B6B6B] hover:bg-[#E0E0E0]"
                }`}
              >
                {f}
              </button>
            ))}
          </div>
          <div className="overflow-x-auto rounded-xl border border-[#E0E0E0] bg-white">
            <table className="w-full text-left" style={{ minWidth: 320 }}>
              <thead>
                <tr className="bg-[#FAFAFA] border-b border-[#E0E0E0]">
                  {["시각", "등급", "이벤트", "IP", "차단", "상태"].map((h) => (
                    <th
                      key={h}
                      className="py-2 px-2 text-[10px] font-semibold text-[#6B6B6B] whitespace-nowrap"
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {detectHistory
                  .filter(
                    (d) => detectFilter === "전체" || d.sev === detectFilter,
                  )
                  .map((d) => (
                    <tr
                      key={d.id}
                      onClick={() => onSelectEvent(detectHistoryToEvent(d))}
                      className="border-b border-[#F5F5F5] hover:bg-[#FAFAFA] cursor-pointer"
                    >
                      <td className="py-1.5 px-2 text-[10px] font-mono text-[#6B6B6B]">
                        {d.time}
                      </td>
                      <td className="py-1.5 px-2">
                        <SeverityBadge sev={d.sev} small />
                      </td>
                      <td className="py-1.5 px-2 text-[10px] text-[#0D0D0D] max-w-[100px] truncate">
                        {eventDisplayTitle({ title: d.event, scenarioType: d.scenarioType })}
                      </td>
                      <td className="py-1.5 px-2 text-[10px] font-mono text-[#475467] whitespace-nowrap">
                        {d.ip}
                      </td>
                      <td className="py-1.5 px-2">
                        <span
                          className={`text-[9px] font-bold px-1.5 py-0.5 rounded-full text-white ${
                            d.blocked === "차단"
                              ? "bg-[#16A34A]"
                              : d.blocked === "부분"
                                ? "bg-[#F79009]"
                                : "bg-[#98A2B3]"
                          }`}
                        >
                          {d.blocked}
                        </span>
                      </td>
                      <td className="py-1.5 px-2 text-[10px] text-[#6B6B6B]">
                        {d.status}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      {tab === "action" && detailEvent && (
        <EventDetailModal
          key={detailEvent.id}
          event={detailEvent}
          isAuto={canRemediate(detailEvent)}
          isPending={isPendingApproval(detailEvent)}
          onClose={() => setDetailEventId(null)}
          onApprove={() => {
            setDetailEventId(null)
            onApprove(detailEvent)
          }}
          onExcept={() => {
            setDetailEventId(null)
            onExcept([detailEvent.id])
          }}
        />
      )}
    </div>
  )
}

// ─── Security Chatbot ─────────────────────────────────────────────────────────

interface ChatMessage {
  role: "user" | "bot"

  text: string

  actions?: string[]
}

interface AuthUser {
  username: string
  role: string
  team: string
}

function SecurityChatbot({
  selectedEvent,
  onHighlightPath,
  onShowRecommend,
  onClose,
}: {
  selectedEvent: ActionEvent | null

  onHighlightPath: () => void

  onShowRecommend: () => void

  onClose?: () => void
}) {
  const [messages, setMessages] = useState<ChatMessage[]>([])

  const [input, setInput] = useState("")
  const [sending, setSending] = useState(false)

  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (scrollRef.current)
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
  }, [messages, sending])

  const sendMessage = async (text: string) => {
    const trimmed = text.trim()
    if (!trimmed || sending) return

    const history = messages.map((message) => ({
      role: message.role,
      text: message.text,
    }))

    setMessages((prev) => [...prev, { role: "user", text: trimmed }])
    setInput("")
    setSending(true)

    try {
      const response = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          message: trimmed,
          history,
          event: selectedEvent,
        }),
      })

      const data = (await response.json()) as {
        text?: string
        actions?: string[]
        message?: string
      }

      if (!response.ok) {
        throw new Error(data.message || `Chat API ${response.status}`)
      }

      setMessages((prev) => [
        ...prev,
        {
          role: "bot",
          text: data.text || "응답을 받지 못했습니다.",
          actions: data.actions || [],
        },
      ])
    } catch (error) {
      setMessages((prev) => [
        ...prev,
        {
          role: "bot",
          text: `챗봇 연결 오류: ${
            error instanceof Error ? error.message : "알 수 없는 오류"
          }`,
        },
      ])
    } finally {
      setSending(false)
    }
  }

  const handleActionBtn = (action: string) => {
    if (action === "공격 경로 강조") onHighlightPath()

    if (action === "권장 조치 보기") onShowRecommend()
  }

  const handleClear = () => setMessages([])

  return (
    <div className="flex flex-col h-full bg-white">
      {/* Chatbot header */}
      <div className="flex items-center gap-2 px-3 py-2.5 border-b border-[#E0E0E0] flex-shrink-0 bg-[#FAFAFA]">
        <div className="w-6 h-6 rounded-lg bg-[#111111] flex items-center justify-center flex-shrink-0">
          <svg
            viewBox="0 0 24 24"
            width="13"
            height="13"
            fill="none"
            stroke="white"
            strokeWidth="2.2"
          >
            <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z" />
          </svg>
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-[11px] font-bold text-[#0D0D0D] leading-tight">
            보안 분석 어시스턴트
          </p>
          <div className="flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-[#16A34A]" />
            <span className="text-[9px] text-[#6B6B6B]">온라인</span>
          </div>
        </div>
        <button
          onClick={handleClear}
          className="text-[10px] text-[#6B6B6B] hover:text-[#0D0D0D] px-1.5 py-1 rounded border border-[#E0E0E0] hover:bg-white transition-colors"
        >
          새 대화
        </button>
        {onClose && (
          <button
            onClick={onClose}
            aria-label="챗봇 닫기"
            title="닫기"
            className="w-7 h-7 flex items-center justify-center rounded-lg text-[#667085] hover:text-[#101828] hover:bg-white transition-colors"
          >
            <svg
              viewBox="0 0 24 24"
              width="15"
              height="15"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
            >
              <path d="M18 6L6 18M6 6l12 12" />
            </svg>
          </button>
        )}
      </div>

      {/* Context chip */}
      {selectedEvent && (
        <div className="px-3 py-1.5 bg-[#F5F5F5] border-b border-[#D4D4D4] flex-shrink-0">
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[9px] font-bold text-[#111111]">
              컨텍스트:
            </span>
            <span className="text-[9px] bg-white border border-[#A3A3A3] text-[#111111] px-1.5 py-0.5 rounded-full font-medium">
              {eventDisplayTitle(selectedEvent)}
            </span>
            <SeverityBadge sev={selectedEvent.severity} small />
            <span className="text-[9px] text-[#111111]">
              {selectedEvent.service}
            </span>
          </div>
        </div>
      )}

      {/* Message area */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto p-3 space-y-3">
        {messages.length === 0 && (
          <div className="text-center py-3">
            <p className="text-[10px] text-[#6B6B6B] leading-relaxed mb-3">
              탐지된 이벤트, 원본 로그 또는 권장 조치에 대해 질문해 보세요.
            </p>
            <div className="grid grid-cols-2 gap-1.5">
              {SUGGESTED_QUESTIONS.map((q) => (
                <button
                  key={q}
                  onClick={() => void sendMessage(q)}
                  className="text-[10px] text-[#111111] bg-[#F5F5F5] hover:bg-[#E0E0E0] border border-[#D4D4D4] px-2 py-1.5 rounded-lg text-left transition-colors leading-tight"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>
        )}
        {sending && (
          <div className="flex justify-start">
            <div className="bg-[#F5F5F5] text-[#667085] rounded-2xl rounded-tl-sm px-3 py-2">
              <p className="text-[11px]">분석 중...</p>
            </div>
          </div>
        )}
        {messages.map((msg, i) => (
          <div
            key={i}
            className={`flex ${
              msg.role === "user" ? "justify-end" : "justify-start"
            }`}
          >
            <div
              className={`max-w-[90%] ${
                msg.role === "user"
                  ? "bg-[#111111] text-white rounded-2xl rounded-tr-sm px-3 py-2"
                  : "bg-[#F5F5F5] text-[#0D0D0D] rounded-2xl rounded-tl-sm px-3 py-2"
              }`}
            >
              <p className="text-[11px] leading-relaxed">{msg.text}</p>
              {msg.actions && msg.actions.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-2">
                  {msg.actions.map((a) => (
                    <button
                      key={a}
                      onClick={() => handleActionBtn(a)}
                      className="text-[9px] font-medium bg-white text-[#111111] border border-[#D4D4D4] px-1.5 py-0.5 rounded-full hover:bg-[#F5F5F5] transition-colors"
                    >
                      {a}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Input area */}
      <div className="border-t border-[#E0E0E0] p-2.5 flex-shrink-0 bg-[#FAFAFA]">
        <div className="flex gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.nativeEvent.isComposing) {
                void sendMessage(input)
              }
            }}
            disabled={sending}
            placeholder="보안 이벤트 또는 로그에 대해 질문하세요"
            className="flex-1 text-[11px] border border-[#E0E0E0] rounded-lg px-2.5 py-1.5 outline-none focus:border-[#111111] bg-white disabled:bg-[#F2F4F7]"
          />
          <button
            onClick={() => void sendMessage(input)}
            disabled={sending}
            className="text-[11px] font-bold text-white bg-[#111111] hover:bg-[#262626] px-3 py-1.5 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {sending ? "분석 중" : "전송"}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Attack scenario cards ────────────────────────────────────────────────────

// ─── Scenario card variants ───────────────────────────────────────────────────

// Small arrow icon reused in all cards

function CardArrow({ onOpen }: { onOpen: () => void }) {
  return (
    <button
      onClick={(e) => {
        e.stopPropagation()
        onOpen()
      }}
      aria-label="상세 페이지 열기"
      title="상세 페이지 열기"
      className="flex-shrink-0 flex items-center gap-0.5 text-[11px] font-semibold text-[#667085] hover:text-[#101828] bg-[#F2F4F7] hover:bg-[#E4E7EC] rounded-full pl-1.5 pr-1 py-0.5 transition-colors"
    >
      상세
      <svg
        viewBox="0 0 16 16"
        width="10"
        height="10"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
      >
        <path d="M6 3l5 5-5 5" />
      </svg>
    </button>
  )
}

function cardBase(isSelected: boolean, isMuted: boolean, accentColor: string) {
  return {
    borderColor: isSelected ? accentColor : "#E0E0E0",

    borderWidth: isSelected ? 2 : 1,

    opacity: isMuted ? 0.38 : 1,

    boxShadow: isSelected ? `0 0 0 3px ${accentColor}18` : "none",
  } as React.CSSProperties
}

function CardShell({
  accent,
  isSelected,
  isMuted,
  onClick,
  children,
}: {
  accent: string
  isSelected: boolean
  isMuted: boolean
  onClick: () => void
  children: React.ReactNode
}) {
  return (
    <div
      onClick={onClick}
      className="relative bg-white rounded-[10px] border cursor-pointer transition-all h-full flex flex-col hover:shadow-md"
      style={cardBase(isSelected, isMuted, accent)}
    >
      <div
        className="absolute top-0 left-0 right-0 h-[3px] rounded-t-[10px]"
        style={{ backgroundColor: accent }}
      />
      {children}
    </div>
  )
}

function CardHeader({ title, onOpen }: { title: string; onOpen: () => void }) {
  return (
    <div className="flex items-start justify-between gap-1 px-3 pt-3.5">
      <p className="text-[12px] font-bold text-[#0D0D0D] leading-tight">
        {title}
      </p>
      <CardArrow onOpen={onOpen} />
    </div>
  )
}

function StatusBadge({ label, color }: { label: string; color: string }) {
  return (
    <span
      className="inline-block w-fit text-[10px] font-bold px-2 py-0.5 rounded-full text-white"
      style={{ backgroundColor: color }}
    >
      {label}
    </span>
  )
}

interface CardProps {
  card: ScenarioCard
  isSelected: boolean
  isMuted: boolean
  onClick: () => void
  onOpen: () => void
}

// 이벤트형: 상태 + 차단 건수
function EventCard({ card, isSelected, isMuted, onClick, onOpen }: CardProps) {
  const isSql = card.id === "sql"
  const accent = isSql ? "#D92D20" : "#16A34A"

  return (
    <CardShell
      accent={accent}
      isSelected={isSelected}
      isMuted={isMuted}
      onClick={onClick}
    >
      <CardHeader title={card.title} onOpen={onOpen} />
      <div className="px-3 pb-3 flex-1 flex flex-col justify-center gap-1.5">
        <StatusBadge label={isSql ? "차단됨" : "정상 방어"} color={accent} />
        <p className="text-[26px] font-bold text-[#0D0D0D] leading-none">
          <span style={{ color: accent }}>{isSql ? 3 : 0}</span>
          <span className="text-[12px] font-medium text-[#667085] ml-1">
            건 차단
          </span>
        </p>
      </div>
    </CardShell>
  )
}

// 임계치형: 게이지 + 현재/한도
function TrafficCard({
  card,
  isSelected,
  isMuted,
  onClick,
  onOpen,
}: CardProps) {
  const isDir = card.id === "dir"
  const pct = isDir ? 80 : 100
  const accent = isDir ? "#F79009" : "#D92D20"

  return (
    <CardShell
      accent={accent}
      isSelected={isSelected}
      isMuted={isMuted}
      onClick={onClick}
    >
      <CardHeader title={card.title} onOpen={onOpen} />
      <div className="flex items-center gap-2.5 px-3 pb-2 flex-1">
        <DonutGauge pct={pct} color={accent} size={64} />
        <div className="min-w-0">
          <StatusBadge label={isDir ? "주의" : "차단 중"} color={accent} />
          <p className="mt-1 text-[16px] font-bold text-[#0D0D0D] leading-none">
            {isDir ? 120 : 50}
            <span className="text-[11px] font-normal text-[#667085]">
              {" "}
              / {isDir ? 150 : 50}
            </span>
          </p>
        </div>
      </div>
    </CardShell>
  )
}

// 이상행위형: 상태 + 탐지 건수
function AnomalyCard({
  card,
  isSelected,
  isMuted,
  onClick,
  onOpen,
}: CardProps) {
  const accent = "#D92D20"

  return (
    <CardShell
      accent={accent}
      isSelected={isSelected}
      isMuted={isMuted}
      onClick={onClick}
    >
      <CardHeader title={card.title} onOpen={onOpen} />
      <div className="px-3 pb-3 flex-1 flex flex-col justify-center gap-1.5">
        <StatusBadge label="이상행위 탐지" color={accent} />
        <p
          className="text-[26px] font-bold leading-none"
          style={{ color: accent }}
        >
          1
          <span className="text-[12px] font-medium text-[#667085] ml-1">
            건 탐지
          </span>
        </p>
      </div>
    </CardShell>
  )
}

// 정적 스캔형: 심각도별 개수 + 스택바
function VulnCard({ card, isSelected, isMuted, onClick, onOpen }: CardProps) {
  const counts = [
    { label: "Critical", count: 1, color: "#D92D20" },
    { label: "High", count: 3, color: "#F79009" },
    { label: "Medium", count: 2, color: "#EAB308" },
  ]
  const total = counts.reduce((n, c) => n + c.count, 0)

  return (
    <div
      onClick={onClick}
      className="relative w-full bg-white rounded-[10px] border cursor-pointer transition-all hover:shadow-md"
      style={cardBase(isSelected, isMuted, "#101828")}
    >
      <div className="flex items-center gap-5 px-4 py-2.5">
        <p className="text-[12px] font-bold text-[#0D0D0D] whitespace-nowrap">
          {card.title}
        </p>
        <div className="flex items-center gap-4 flex-shrink-0">
          {counts.map((c) => (
            <div key={c.label} className="flex items-baseline gap-1">
              <span
                className="text-[10px] font-bold px-1.5 py-0.5 rounded-full text-white"
                style={{ backgroundColor: c.color }}
              >
                {c.label}
              </span>
              <span
                className="text-[18px] font-bold leading-none"
                style={{ color: c.color }}
              >
                {c.count}
              </span>
            </div>
          ))}
        </div>
        <div className="flex flex-1 min-w-0 rounded-full overflow-hidden h-2.5 bg-[#E5E7EB]">
          {counts.map((c) => (
            <div
              key={c.label}
              style={{
                width: `${(c.count / total) * 100}%`,
                backgroundColor: c.color,
              }}
            />
          ))}
        </div>
        <CardArrow onOpen={onOpen} />
      </div>
    </div>
  )
}

export function ScenarioCardWrapper({
  card,
  isSelected,
  anySelected,
  onSelect,
  onOpen,
}: {
  card: ScenarioCard

  isSelected: boolean

  anySelected: boolean

  onSelect: (card: ScenarioCard) => void

  onOpen: (card: ScenarioCard) => void
}) {
  const isMuted = anySelected && !isSelected

  const props = {
    card,
    isSelected,
    isMuted,
    onClick: () => onSelect(card),
    onOpen: () => onOpen(card),
  }

  if (card.type === "event") return <EventCard {...props} />

  if (card.type === "traffic") return <TrafficCard {...props} />

  if (card.type === "anomaly") return <AnomalyCard {...props} />

  if (card.type === "vuln") return <VulnCard {...props} />

  return null
}

// ─── Main App ─────────────────────────────────────────────────────────────────

type MainSection = "dashboard" | "events" | "monitoring" | "ai-actions" | "ai-diagnosis" | "approvals"
type DashboardDataState = "loading" | "success" | "error"

interface SecurityNotification {
  id: string
  event: ActionEvent
  read: boolean
}

function ComingSoonSection({
  title,
  description,
  items,
}: {
  title: string
  description: string
  items: string[]
}) {
  return (
    <div className="min-h-full p-4">
      <div className="mb-3">
        <p className="text-[18px] font-bold text-[#101828]">{title}</p>
        <p className="text-[11px] text-[#667085] mt-0.5">{description}</p>
      </div>

      <div className="bg-white border border-[#EAECF0] rounded-2xl p-5">
        <div className="flex items-center gap-2 mb-4">
          <div className="w-8 h-8 rounded-lg bg-[#F2F4F7] text-[#475467] flex items-center justify-center">
            <svg
              viewBox="0 0 24 24"
              width="17"
              height="17"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.8"
            >
              <path d="M4 19V9M10 19V5M16 19v-7M22 19H2" />
            </svg>
          </div>
          <div>
            <p className="text-xs font-bold text-[#101828]">화면 준비 중</p>
            <p className="text-[10px] text-[#98A2B3]">
              현재는 메뉴와 기본 레이아웃만 제공됩니다.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
          {items.map((item) => (
            <div
              key={item}
              className="min-h-[72px] rounded-xl border border-[#EAECF0] bg-[#FAFAFA] px-3.5 py-3 flex items-center"
            >
              <span className="w-2 h-2 rounded-full bg-[#D0D5DD] mr-2.5 flex-shrink-0" />
              <span className="text-[11px] font-semibold text-[#475467]">
                {item}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function DashboardDataStatus({
  status,
  onRetry,
}: {
  status: Exclude<DashboardDataState, "success">
  onRetry: () => void
}) {
  const isLoading = status === "loading"

  return (
    <div className="bg-white border border-[#EAECF0] rounded-xl px-4 py-3 flex items-center gap-3">
      <div className="w-8 h-8 rounded-lg bg-[#F2F4F7] text-[#475467] flex items-center justify-center flex-shrink-0">
        {isLoading ? (
          <span className="w-4 h-4 rounded-full border-2 border-[#D0D5DD] border-t-[#101828] animate-spin" />
        ) : (
          <svg
            viewBox="0 0 24 24"
            width="19"
            height="19"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.8"
          >
            <path d="M12 9v4M12 17h.01" />
            <path d="M10.3 3.6L2.7 17a2 2 0 001.7 3h15.2a2 2 0 001.7-3L13.7 3.6a2 2 0 00-3.4 0z" />
          </svg>
        )}
      </div>
      <div className="min-w-0">
        <p className="text-xs font-bold text-[#101828]">
          {isLoading
            ? "데이터를 불러오는 중입니다."
            : "데이터를 불러오지 못했습니다."}
        </p>
        <p className="text-[10px] text-[#667085] mt-0.5">
          {isLoading
            ? "연결이 완료되면 실제 DB 데이터가 표시됩니다."
            : "DB 또는 API 연결 상태를 확인해주세요. 화면은 빈 데이터 상태로 표시됩니다."}
        </p>
      </div>
      {!isLoading && (
        <button
          onClick={onRetry}
          className="ml-auto flex-shrink-0 text-[10px] font-semibold text-white bg-[#101828] hover:bg-[#1D2939] px-3 py-1.5 rounded-lg transition-colors"
        >
          다시 시도
        </button>
      )}
    </div>
  )
}

function Sparkline({ values, color }: { values: number[]; color: string }) {
  if (values.length < 2) {
    return <span className="text-[9px] text-[#98A2B3]">최근 추이 없음</span>
  }

  const width = 160
  const height = 48
  const min = Math.min(...values)
  const max = Math.max(...values)
  const range = max - min || 1
  const points = values
    .map((value, index) => {
      const x = (index / (values.length - 1)) * width
      const y = height - 2 - ((value - min) / range) * (height - 4)
      return `${x},${y}`
    })
    .join(" ")

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      className="w-full h-12"
      role="img"
      aria-label="최근 지표 추이"
    >
      <polyline
        points={points}
        fill="none"
        stroke={color}
        strokeWidth="2.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

function OverviewMetricCard({
  title,
  metric,
  unit,
  decimals = 1,
  color = "#101828",
  waiting,
}: {
  title: string
  metric: NumericOverviewMetric | null
  unit: string
  decimals?: number
  color?: string
  waiting: boolean
}) {
  const hasValue = metric?.current !== null && metric?.current !== undefined

  return (
    <div className="h-full min-w-0 rounded-xl border border-[#EAECF0] bg-white p-3 flex flex-col overflow-hidden">
      <div className="flex items-start justify-between gap-2">
        <p className="text-[11px] font-bold text-[#101828] truncate">{title}</p>
        <span className="text-[8px] text-[#98A2B3] whitespace-nowrap">
          최근 추이
        </span>
      </div>
      <div className="mt-1 min-w-0">
        {hasValue ? (
          <p className="leading-tight whitespace-nowrap">
            <span className="text-[23px] font-bold" style={{ color }}>
              {metric.current!.toFixed(decimals)}
            </span>
            <span className="text-xs text-[#667085] ml-1">{unit}</span>
          </p>
        ) : (
          <p className="text-[12px] font-bold text-[#98A2B3] leading-7 whitespace-nowrap">
            {waiting ? "수집 대기 중" : "데이터 없음"}
          </p>
        )}
      </div>
      <div className="mt-auto h-12 flex items-center">
        {hasValue ? <Sparkline values={metric.series} color={color} /> : null}
      </div>
    </div>
  )
}

function HealthMetricCard({
  metric,
  waiting,
}: {
  metric: OverviewMetricsResponse["health"] | null
  waiting: boolean
}) {
  const labels = { NORMAL: "정상", WARNING: "경고", CRITICAL: "장애" } as const
  const colors = {
    NORMAL: "#16A34A",
    WARNING: "#F79009",
    CRITICAL: "#D92D20",
  } as const
  const status = metric?.status ?? null

  return (
    <div className="h-full min-w-0 rounded-xl border border-[#EAECF0] bg-white p-3 flex flex-col overflow-hidden">
      <div className="min-w-0">
        <p className="text-[11px] font-bold text-[#101828]">서비스 상태</p>
        {status ? (
          <p
            className="text-[23px] font-bold leading-tight mt-1"
            style={{ color: colors[status] }}
          >
            {labels[status]}
          </p>
        ) : (
          <p className="text-[12px] font-bold text-[#98A2B3] leading-6 whitespace-nowrap">
            {waiting ? "수집 대기 중" : "데이터 없음"}
          </p>
        )}
      </div>
      {status && (
        <div className="mt-auto grid grid-cols-2 gap-1.5 text-[9px] text-[#667085] whitespace-nowrap">
          <div className="rounded-lg bg-[#F2F4F7] px-2 py-1.5">
            <p className="text-[#98A2B3]">Healthy</p>
            <p className="text-[13px] font-bold text-[#16A34A]">
              {metric?.healthy ?? "-"}
            </p>
          </div>
          <div className="rounded-lg bg-[#F2F4F7] px-2 py-1.5">
            <p className="text-[#98A2B3]">Unhealthy</p>
            <p className="text-[13px] font-bold text-[#D92D20]">
              {metric?.unhealthy ?? "-"}
            </p>
          </div>
        </div>
      )}
    </div>
  )
}

function parseRoute(): string | null {
  const m = window.location.hash.match(/^#\/scenario\/(\w+)/)
  return m && SCENARIO_CARDS.some((c) => c.id === m[1]) ? m[1] : null
}

const SECTION_KEYS: MainSection[] = [
  "events",
  "monitoring",
  "ai-diagnosis",
  "ai-actions",
  "approvals",
]

// 새로고침해도 보고 있던 탭(대시보드 제외)이 유지되도록, 현재 섹션을 해시에 남긴다.
function parseSectionRoute(): MainSection {
  const m = window.location.hash.match(/^#\/(events|monitoring|ai-diagnosis|ai-actions|approvals)$/)
  const key = m?.[1] as MainSection | undefined
  return key && SECTION_KEYS.includes(key) ? key : "dashboard"
}

export default function App() {
  const [now, setNow] = useState(new Date())
  const [authState, setAuthState] =
    useState<"loading" | "authenticated" | "unauthenticated">("loading")
  const [authUser, setAuthUser] = useState<AuthUser | null>(null)

  const [autoRefresh, setAutoRefresh] = useState(true)

  const [activeSection, setActiveSection] = useState<MainSection>(parseSectionRoute)
  const [chatOpen, setChatOpen] = useState(false)

  const [rightTab, setRightTab] = useState<RightTab>("action")

  const [selectedEvent, setSelectedEvent] = useState<ActionEvent | null>(null)

  const [selectedScenario, setSelectedScenario] = useState<ScenarioCard | null>(
    null,
  )

  // 지도에서 누른 인프라 하나 (그 자산과 연결된 선만 강조)
  const [selectedAsset, setSelectedAsset] = useState<string | null>(null)

  const [approvalTarget, setApprovalTarget] = useState<ActionEvent | null>(null)
  const [requestNote, setRequestNote] = useState("")

  const [isRemediating, setIsRemediating] = useState(false)
  const remediationPendingRef = useRef(false)
  const [remediationError, setRemediationError] = useState<string | null>(null)
  const [remediationSucceeded, setRemediationSucceeded] = useState(false)

  const exceptPendingRef = useRef(false)

  // Scenario detail page (hash route: #/scenario/<id>)
  const [pageId, setPageId] = useState<string | null>(parseRoute)

  // actionId -> 실행 시각 (상세 페이지에서 실행한 조치)
  const [doneActions, setDoneActions] = useState<Record<string, string>>({})

  const [toast, setToast] = useState<string | null>(null)

  const [dashboardDataState, setDashboardDataState] =
    useState<DashboardDataState>("loading")
  const [actionEvents, setActionEvents] = useState<ActionEvent[]>([])
  const [detectHistory, setDetectHistory] = useState<DetectHistoryItem[]>([])
  const [remediationHistory, setRemediationHistory] =
    useState<RemediationHistoryItem[]>([])
  const [overviewMetrics, setOverviewMetrics] =
    useState<OverviewMetricsResponse | null>(null)
  const [overviewMetricsState, setOverviewMetricsState] =
    useState<DashboardDataState>("loading")
  const [notifications, setNotifications] = useState<SecurityNotification[]>([])
  const [notificationsOpen, setNotificationsOpen] = useState(false)
  const knownEventIdsRef = useRef<Set<string> | null>(null)
  const notifiedEventIdsRef = useRef(new Set<string>())
  const notificationPopoverRef = useRef<HTMLDivElement>(null)

  const loadOverviewMetrics = async (showLoading = true) => {
    if (showLoading) setOverviewMetricsState("loading")

    try {
      const data = await fetchOverviewMetrics()
      setOverviewMetrics(data)
      setOverviewMetricsState("success")
    } catch (error) {
      setOverviewMetrics(null)
      setOverviewMetricsState("error")
      console.error("운영 지표를 불러오지 못했습니다.", error)
    }
  }

  const loadDashboardData = async (showLoading = true, preserveOnError = false) => {
    if (showLoading) setDashboardDataState("loading")

    try {
      const response = await fetch("/api/dashboard", { credentials: "include" })
      if (response.status === 401) {
        setAuthUser(null)
        setAuthState("unauthenticated")
        knownEventIdsRef.current = null
        notifiedEventIdsRef.current.clear()
        setNotifications([])
        setNotificationsOpen(false)
        return
      }
      if (!response.ok) {
        throw new Error(`Dashboard API ${response.status}`)
      }

      const data = (await response.json()) as DashboardApiResponse
      if (
        !Array.isArray(data.events) ||
        !Array.isArray(data.detectHistory) ||
        !Array.isArray(data.remediationHistory)
      ) {
        throw new Error("Dashboard API response is invalid")
      }

      const incomingIds = new Set(data.events.map((event) => event.id))
      if (knownEventIdsRef.current === null) {
        knownEventIdsRef.current = incomingIds
      } else {
        const newEvents = data.events.filter(
          (event) =>
            !knownEventIdsRef.current!.has(event.id) &&
            !notifiedEventIdsRef.current.has(event.id),
        )

        data.events.forEach((event) => knownEventIdsRef.current!.add(event.id))
        newEvents.forEach((event) => notifiedEventIdsRef.current.add(event.id))

        if (newEvents.length > 0) {
          setNotifications((previous) => [
            ...newEvents.map((event) => ({
              id: event.id,
              event,
              read: false,
            })),
            ...previous,
          ].slice(0, 30))
        }
      }

      setActionEvents(data.events)
      setDetectHistory(data.detectHistory)
      setRemediationHistory(data.remediationHistory)
      setDashboardDataState("success")
      return true
    } catch (error) {
      if (!preserveOnError) {
        setActionEvents([])
        setDetectHistory([])
        setRemediationHistory([])
        setSelectedEvent(null)
        setSelectedAsset(null)
      }
      setDashboardDataState("error")
      console.error("DB 대시보드 데이터를 불러오지 못했습니다.", error)
      return false
    }
  }

  useEffect(() => {
    const checkAuth = async () => {
      try {
        const response = await fetch("/api/auth/status", {
          credentials: "include",
        })
        if (!response.ok) throw new Error(`Auth API ${response.status}`)

        const data = (await response.json()) as {
          authenticated: boolean
          user?: AuthUser
        }

        if (data.authenticated && data.user) {
          setAuthUser(data.user)
          setAuthState("authenticated")
        } else {
          setAuthState("unauthenticated")
        }
      } catch (error) {
        console.warn("로그인 상태 확인 실패", error)
        setAuthState("unauthenticated")
      }
    }

    void checkAuth()
  }, [])

  useEffect(() => {
    if (authState === "authenticated") {
      void loadDashboardData(true)
      void loadOverviewMetrics(true)
    }
  }, [authState])

  useEffect(() => {
    const onHash = () => {
      setPageId(parseRoute())
      setActiveSection(parseSectionRoute())
    }
    window.addEventListener("hashchange", onHash)
    return () => window.removeEventListener("hashchange", onHash)
  }, [])

  useEffect(() => {
    if (!toast) return
    const id = setTimeout(() => setToast(null), 2600)
    return () => clearTimeout(id)
  }, [toast])

  useEffect(() => {
    if (!notificationsOpen) return

    const closeOnOutsideClick = (event: MouseEvent) => {
      if (
        notificationPopoverRef.current &&
        !notificationPopoverRef.current.contains(event.target as Node)
      ) {
        setNotificationsOpen(false)
      }
    }

    document.addEventListener("mousedown", closeOnOutsideClick)
    return () => document.removeEventListener("mousedown", closeOnOutsideClick)
  }, [notificationsOpen])

  const openScenario = (id: string) => {
    window.location.hash = `#/scenario/${id}`
  }

  const closeScenario = () => {
    window.location.hash = ""
    setActiveSection("dashboard")
  }

  const goSection = (section: MainSection) => {
    window.location.hash = section === "dashboard" ? "" : `#/${section}`
    setActiveSection(section)
  }

  const toggleAutoRefresh = () => {
    if (autoRefresh) {
      setAutoRefresh(false)
      return
    }

    setAutoRefresh(true)
    void loadDashboardData(false)
    void loadOverviewMetrics(false)
  }

  // 실제 현재 시간: 브라우저 시스템 시간을 1초마다 다시 읽는다.
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(id)
  }, [])

  // 자동 갱신은 시간 표시와 분리하여 DB 데이터만 1분마다 다시 읽는다.
  useEffect(() => {
    if (!autoRefresh || authState !== "authenticated") return

    const id = setInterval(() => {
      void loadDashboardData(false)
      void loadOverviewMetrics(false)
    }, 60000)

    return () => clearInterval(id)
  }, [autoRefresh, authState])

  const clearSelection = () => {
    setSelectedScenario(null)
    setSelectedEvent(null)
    setSelectedAsset(null)
  }

  // Esc 로 선택 해제
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !approvalTarget) {
        setSelectedScenario(null)
        setSelectedEvent(null)
        setSelectedAsset(null)
      }
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [approvalTarget])

  // 지도의 인프라 클릭 → 그 인프라와 연결된 선만 강조 (다시 누르면 해제)
  const handleAssetClick = (assetId: string) => {
    if (selectedAsset === assetId) {
      clearSelection()
      return
    }
    setSelectedScenario(null)
    setSelectedEvent(null)
    setSelectedAsset(assetId)
  }

  const handleSelectEvent = (ev: ActionEvent | null) => {
    if (!ev || selectedEvent?.id === ev.id) {
      clearSelection()
      return
    }

    setSelectedAsset(null)
    setSelectedEvent(ev)
    setSelectedScenario(
      SCENARIO_CARDS.find((c) => c.actionEventId === ev.id) ?? null,
    )
  }

  const handleNotificationClick = (notification: SecurityNotification) => {
    setNotifications((previous) =>
      previous.map((item) =>
        item.id === notification.id ? { ...item, read: true } : item,
      ),
    )
    setNotificationsOpen(false)
    window.location.hash = ""
    setActiveSection("events")
    setRightTab("action")
    setSelectedAsset(null)
    setSelectedEvent(notification.event)
    setSelectedScenario(
      SCENARIO_CARDS.find(
        (card) => card.actionEventId === notification.event.id,
      ) ?? null,
    )
  }

  const markAllNotificationsRead = () => {
    setNotifications((previous) =>
      previous.map((notification) => ({ ...notification, read: true })),
    )
  }

  const handleDirectRemediation = async (event: ActionEvent) => {
    if (remediationPendingRef.current) return
    remediationPendingRef.current = true
    setToast("자동 조치를 실행하고 있습니다.")
    try {
      const response = await fetch("/api/remediate", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ event_id: event.id }),
      })
      const result = await response.json()
      if (!response.ok || result.success !== true) {
        throw new Error(result.message || "자동 조치 실행에 실패했습니다.")
      }
      clearSelection()
      const refreshed = await loadDashboardData(false, true)
      setToast(refreshed
        ? `자동 조치가 완료되었습니다 — ${eventDisplayTitle(event)}`
        : "자동 조치는 완료됐지만 최신 목록을 조회하지 못했습니다. 새로고침해 주세요.")
    } catch (error) {
      setToast(error instanceof Error ? error.message : "자동 조치 실행에 실패했습니다.")
    } finally {
      remediationPendingRef.current = false
    }
  }

  const handleApproveConfirm = async () => {
    if (!approvalTarget || remediationPendingRef.current) return
    remediationPendingRef.current = true
    setIsRemediating(true)
    setRemediationError(null)
    try {
      if (!remediationSucceeded) {
        const response = await fetch("/api/approval-requests", {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ event_id: approvalTarget.id, note: requestNote }),
        })
        const result = await response.json()
        if (!response.ok || result.success !== true) {
          throw new Error(result.message || "승인 요청 전송에 실패했습니다.")
        }
        setRemediationSucceeded(true)
      }
      if (!(await loadDashboardData(false, true))) {
        throw new Error("요청은 전송됐지만 최신 데이터를 조회하지 못했습니다. 다시 확인하면 데이터만 재조회합니다.")
      }
      setApprovalTarget(null)
      setRequestNote("")
      clearSelection()
      setToast(`승인자에게 조치 요청을 보냈습니다 — ${approvalTarget.title}`)
    } catch (error) {
      setRemediationError(error instanceof Error ? error.message : "승인 요청 전송에 실패했습니다.")
    } finally {
      remediationPendingRef.current = false
      setIsRemediating(false)
    }
  }

  const handleExceptEvents = async (eventIds: string[]) => {
    if (eventIds.length === 0 || exceptPendingRef.current) return
    exceptPendingRef.current = true
    try {
      const response = await fetch("/api/exception", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ event_ids: eventIds }),
      })
      const result = await response.json()
      if (!response.ok || result.success !== true) {
        throw new Error(result.message || "예외 처리에 실패했습니다.")
      }
      if (selectedEvent && eventIds.includes(selectedEvent.id)) clearSelection()
      await loadDashboardData(false, true)
      setToast(
        eventIds.length === 1
          ? "예외 처리되었습니다."
          : `${eventIds.length}건이 예외 처리되었습니다.`,
      )
    } catch (error) {
      setToast(error instanceof Error ? error.message : "예외 처리에 실패했습니다.")
    } finally {
      exceptPendingRef.current = false
    }
  }

  const bulkRequestPendingRef = useRef(false)

  const handleBulkApprovalRequests = async (eventIds: string[]) => {
    if (eventIds.length === 0 || bulkRequestPendingRef.current) return
    bulkRequestPendingRef.current = true
    try {
      // 백엔드에 일괄 요청 API가 따로 없어서, 개별 요청을 병렬로 보낸다
      // (한 건이 실패해도 나머지는 계속 보내지도록 allSettled 사용).
      const results = await Promise.allSettled(
        eventIds.map((eventId) =>
          fetch("/api/approval-requests", {
            method: "POST",
            credentials: "include",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ event_id: eventId }),
          }).then(async (response) => {
            const result = await response.json()
            if (!response.ok || result.success !== true) {
              throw new Error(result.message || "요청 전송 실패")
            }
          }),
        ),
      )
      const failed = results.filter((r) => r.status === "rejected").length
      await loadDashboardData(false, true)
      setToast(
        failed === 0
          ? `${eventIds.length}건 모두 승인 요청을 보냈습니다.`
          : `${eventIds.length - failed}건 요청 완료, ${failed}건 실패했습니다.`,
      )
    } finally {
      bulkRequestPendingRef.current = false
    }
  }

  const fmt = (d: Date) => {
    const parts = new Intl.DateTimeFormat("ko-KR", {
      timeZone: "Asia/Seoul",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }).formatToParts(d)
    const part = (type: Intl.DateTimeFormatPartTypes) =>
      parts.find((item) => item.type === type)?.value ?? "00"
    return `${part("year")}.${part("month")}.${part("day")} ${part("hour")}:${part("minute")}:${part("second")}`
  }

  const executeScenarioAction = (actionId: string) => {
    const t = `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}`
    setDoneActions((prev) => ({ ...prev, [actionId]: t }))
    setToast("조치가 실행되었습니다")
  }

  const activeEvents = actionEvents
  const unreadNotificationCount = notifications.filter(
    (notification) => !notification.read,
  ).length
  const displayedActionEvents = selectedEvent && !activeEvents.some((event) => event.id === selectedEvent.id)
    ? [
        selectedEvent,
        ...activeEvents.filter((event) => event.id !== selectedEvent.id),
      ]
    : activeEvents

  const selection = selectedEvent ?? selectedScenario
  const hasExplicitSelection = selection !== null || selectedAsset !== null
  const uniqueAssetIds = (assetIds: string[]) => [...new Set(assetIds)]
  // 아무것도 클릭하지 않았을 때는 지도를 완전히 평범한 상태로 둔다.
  // (예전에는 미해결 이벤트를 전부 자동으로 강조해서, 아무것도 안 눌러도
  //  뭔가 선택된 것처럼 보였다. 작은 경보 점(alerts)은 아래에서 별도로 계속 표시한다.)
  const highlightedAssets = selection
    ? uniqueAssetIds([...selection.highlightAssets, ...selection.attackPath])
    : selectedAsset
      ? [selectedAsset]
      : []
  const attackPathAssets = selection
    ? uniqueAssetIds(selection.attackPath)
    : selectedAsset
      ? []
      : []
  const connectionAssetGroups = selection
    ? [highlightedAssets]
    : selectedAsset
      ? [[selectedAsset]]
      : []
  const hasScenario =
    hasExplicitSelection ||
    highlightedAssets.length > 0 ||
    attackPathAssets.length > 0

  const statuses: Record<string, AssetStatus> = {}
  ASSETS.forEach((asset) => {
    statuses[asset.id] = asset.defaultStatus
  })
  highlightedAssets.forEach((assetId) => {
    statuses[assetId] = "warning"
  })
  attackPathAssets.forEach((assetId) => {
    statuses[assetId] = "critical"
  })

  const alerts: Record<string, {
    level: "critical" | "warning"
    reason: string
  }> = {}
  if (!hasExplicitSelection) {
    activeEvents.forEach((event) => {
      const level = event.severity === "Critical" ? "critical" : "warning"
      const reason = `${event.title} · ${event.severity}`
      uniqueAssetIds([...event.highlightAssets, ...event.attackPath]).forEach(
        (assetId) => {
          const existing = alerts[assetId]
          if (
            !existing ||
            (level === "critical" && existing.level !== "critical")
          ) {
            alerts[assetId] = { level, reason }
          }
        },
      )
    })
  }

  const criticalCount = activeEvents.filter(
    (event) => event.severity === "Critical",
  ).length
  const warningCount = activeEvents.length - criticalCount

  const chatContextEvent = selectedEvent

  const handleLogin = async (username: string, password: string) => {
    const response = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ username, password }),
    })
    const data = (await response.json()) as { user?: AuthUser; message?: string }
    if (!response.ok || !data.user) {
      throw new Error(data.message || "아이디 또는 비밀번호를 확인해 주세요.")
    }

    setAuthUser(data.user)
    setAuthState("authenticated")
    return data.user
  }

  const handleLogout = async () => {
    try {
      await fetch("/api/auth/logout", {
        method: "POST",
        credentials: "include",
      })
    } finally {
      setAuthUser(null)
      setAuthState("unauthenticated")
      setDashboardDataState("loading")
      setActionEvents([])
      setDetectHistory([])
      setRemediationHistory([])
      knownEventIdsRef.current = null
      notifiedEventIdsRef.current.clear()
      setNotifications([])
      setNotificationsOpen(false)
      clearSelection()
    }
  }

  if (authState === "loading") {
    return (
      <div className="min-h-screen bg-[#F6F7F9] flex items-center justify-center text-[12px] text-[#667085]">
        로그인 상태 확인 중...
      </div>
    )
  }

  if (authState === "unauthenticated") {
    return <LoginPage onLogin={handleLogin} />
  }

  return (
    <div
      className="h-screen flex flex-col overflow-hidden bg-[#FAFAFA]"
      style={{
        fontFamily:
          "'Pretendard Variable', 'Pretendard', -apple-system, sans-serif",
      }}
    >
      {/* ── Header ─────────────────────────────────────────────────────── */}
      <header className="relative z-[80] bg-white border-b border-[#E4E7EC] h-14 flex-shrink-0 flex items-center px-5 justify-between">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 bg-[#111111] rounded-lg flex items-center justify-center flex-shrink-0">
              <svg
                viewBox="0 0 24 24"
                width="15"
                height="15"
                fill="none"
                stroke="white"
                strokeWidth="2.2"
              >
                <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" />
              </svg>
            </div>
            <div>
              <p className="text-[11px] font-bold text-[#111111] leading-tight">
                AWS Security Monitoring Center
              </p>
              <p className="text-[9px] text-[#6B6B6B] leading-tight">
                통합 보안관제
              </p>
            </div>
          </div>
          <div className="w-px h-7 bg-[#E0E0E0]" />
          <div className="flex items-center gap-1.5">
            <span
              className={`w-2 h-2 rounded-full flex-shrink-0 ${
                dashboardDataState === "error"
                  ? "bg-[#D92D20]"
                  : dashboardDataState === "loading"
                    ? "bg-[#98A2B3]"
                    : criticalCount
                      ? "bg-[#D92D20] alert-dot-critical"
                      : warningCount
                        ? "bg-[#F79009] alert-dot-warning"
                        : "bg-[#16A34A]"
              }`}
            />
            <span
              className="text-[11px] font-semibold"
              style={{
                color:
                  dashboardDataState === "error"
                    ? "#D92D20"
                    : dashboardDataState === "loading"
                      ? "#667085"
                      : criticalCount
                        ? "#D92D20"
                        : warningCount
                          ? "#B54708"
                          : "#16A34A",
              }}
            >
              {dashboardDataState === "error"
                ? "데이터 연결 오류"
                : dashboardDataState === "loading"
                  ? "데이터 연결 중"
                  : criticalCount
                    ? `비상 ${criticalCount}건 대응 필요`
                    : warningCount
                      ? `주의 ${warningCount}건`
                      : "정상 운영 중"}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-4 text-xs text-[#6B6B6B]">
          <span className="font-mono text-[11px] text-[#0D0D0D]">
            {fmt(now)}
          </span>
          <button
            onClick={toggleAutoRefresh}
            className={`text-[11px] font-semibold px-2.5 py-1 rounded-full border transition-colors ${
              autoRefresh
                ? "border-[#111111] text-[#111111] bg-[#F5F5F5]"
                : "border-[#E0E0E0] text-[#6B6B6B]"
            }`}
          >
            {autoRefresh ? "자동 갱신 ON" : "자동 갱신 OFF"}
          </button>

          {/* Alert bell */}
          <div className="relative" ref={notificationPopoverRef}>
            <button
              onClick={() => setNotificationsOpen((open) => !open)}
              aria-label={`보안 이벤트 알림 ${unreadNotificationCount}개`}
              aria-expanded={notificationsOpen}
              className={`relative p-1.5 rounded-lg transition-colors ${
                notificationsOpen ? "bg-[#F2F4F7]" : "hover:bg-[#F5F5F5]"
              }`}
            >
              <svg
                width="18"
                height="18"
                viewBox="0 0 24 24"
                fill="none"
                stroke="#6B6B6B"
                strokeWidth="2"
              >
                <path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9M13.73 21a2 2 0 01-3.46 0" />
              </svg>
              {unreadNotificationCount > 0 && (
                <span className="absolute -top-0.5 -right-0.5 min-w-4 h-4 px-1 bg-[#D92D20] text-white text-[9px] font-bold rounded-full flex items-center justify-center">
                  {unreadNotificationCount > 99
                    ? "99+"
                    : unreadNotificationCount}
                </span>
              )}
            </button>

            {notificationsOpen && (
              <div className="absolute right-0 top-[calc(100%+10px)] z-[100] w-[360px] overflow-hidden rounded-xl border border-[#E4E7EC] bg-white shadow-[0_18px_48px_rgba(16,24,40,0.18)]">
                <div className="flex items-center justify-between border-b border-[#EAECF0] px-4 py-3">
                  <div className="flex items-center gap-2">
                    <p className="text-[13px] font-bold text-[#101828]">알림</p>
                    {unreadNotificationCount > 0 && (
                      <span className="rounded-full bg-[#FEE4E2] px-1.5 py-0.5 text-[9px] font-bold text-[#B42318]">
                        안 읽음 {unreadNotificationCount}
                      </span>
                    )}
                  </div>
                  <button
                    onClick={markAllNotificationsRead}
                    disabled={unreadNotificationCount === 0}
                    className="text-[10px] font-semibold text-[#475467] hover:text-[#101828] disabled:cursor-default disabled:text-[#D0D5DD]"
                  >
                    모두 읽음
                  </button>
                </div>

                <div className="max-h-[420px] overflow-y-auto">
                  {notifications.length === 0 ? (
                    <div className="px-4 py-10 text-center">
                      <p className="text-[12px] font-semibold text-[#667085]">
                        새로운 보안 이벤트 알림이 없습니다.
                      </p>
                      <p className="mt-1 text-[10px] text-[#98A2B3]">
                        다음 조회에서 새 event.id가 확인되면 표시됩니다.
                      </p>
                    </div>
                  ) : (
                    notifications.map((notification) => {
                      const event = notification.event
                      const time =
                        event.detectedAt.match(/\d{2}:\d{2}$/)?.[0] ??
                        event.detectedAt
                      const severityColor =
                        event.severity === "Critical"
                          ? "text-[#B42318]"
                          : event.severity === "High"
                            ? "text-[#B54708]"
                            : event.severity === "Medium"
                              ? "text-[#B54708]"
                              : "text-[#475467]"

                      return (
                        <button
                          key={notification.id}
                          onClick={() => handleNotificationClick(notification)}
                          className={`relative block w-full border-b border-[#F2F4F7] px-4 py-3 text-left transition-colors last:border-b-0 ${
                            notification.read
                              ? "bg-white hover:bg-[#F9FAFB]"
                              : "bg-[#F8FAFF] hover:bg-[#F2F6FF]"
                          }`}
                        >
                          {!notification.read && (
                            <span className="absolute left-1.5 top-4 h-1.5 w-1.5 rounded-full bg-[#2563EB]" />
                          )}
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <p className="truncate text-[11px] font-bold text-[#101828]">
                                <span className={severityColor}>
                                  [{event.severity.toUpperCase()}]
                                </span>{" "}
                                {eventDisplayTitle(event)}
                              </p>
                              <p className="mt-1 text-[10px] font-semibold text-[#475467]">
                                {event.service}
                              </p>
                              <p className="mt-0.5 truncate text-[10px] text-[#667085]">
                                대상: {event.asset || "-"}
                              </p>
                              {event.scenarioType && (
                                <p className="mt-0.5 truncate text-[9px] text-[#98A2B3]">
                                  유형: {event.scenarioType}
                                </p>
                              )}
                            </div>
                            <span className="flex-shrink-0 font-mono text-[9px] text-[#98A2B3]">
                              {time}
                            </span>
                          </div>
                        </button>
                      )
                    })
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Profile */}
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-2 hover:bg-[#F5F5F5] rounded-lg px-2 py-1 transition-colors">
              <div className="w-7 h-7 rounded-full bg-[#111111] flex items-center justify-center text-white text-[11px] font-bold">
                관
              </div>
              <div>
                <p className="text-[11px] font-semibold text-[#0D0D0D] leading-tight">
                  {authUser?.team || "보안관제팀"}
                </p>
                <p className="text-[9px] text-[#6B6B6B] leading-tight">
                  {authUser?.username || "관리자"} ·{" "}
                  {authUser?.role || "관리자"}
                </p>
              </div>
            </div>
            <button
              onClick={() => void handleLogout()}
              className="text-[10px] text-[#98A2B3] hover:text-[#344054] transition-colors"
            >
              로그아웃
            </button>
          </div>
        </div>
      </header>

      {/* ── Body ───────────────────────────────────────────────────────── */}
      <div className="flex flex-1 min-h-0 overflow-hidden">
        {/* ── Left navigation ─────────────────────────────────────────── */}
        <nav className="w-[176px] flex-shrink-0 bg-white border-r border-[#E4E7EC] px-2.5 py-3 flex flex-col gap-1.5">
          <p className="px-2.5 pb-1 text-[9px] font-bold tracking-[0.12em] text-[#98A2B3] uppercase">
            Navigation
          </p>

          {[
            {
              key: "dashboard",
              label: "대시보드",
              icon: (
                <svg
                  viewBox="0 0 24 24"
                  width="17"
                  height="17"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.8"
                >
                  <rect x="3" y="3" width="7" height="7" rx="1" />
                  <rect x="14" y="3" width="7" height="7" rx="1" />
                  <rect x="3" y="14" width="7" height="7" rx="1" />
                  <rect x="14" y="14" width="7" height="7" rx="1" />
                </svg>
              ),
            },
            {
              key: "events",
              label: "보안 이벤트",
              badge: activeEvents.length,
              icon: (
                <svg
                  viewBox="0 0 24 24"
                  width="17"
                  height="17"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.8"
                >
                  <path d="M12 9v4M12 17h.01" />
                  <path d="M10.3 3.6L2.7 17a2 2 0 001.7 3h15.2a2 2 0 001.7-3L13.7 3.6a2 2 0 00-3.4 0z" />
                </svg>
              ),
            },
            {
              key: "monitoring",
              label: "수동 모니터링",
              icon: (
                <svg
                  viewBox="0 0 24 24"
                  width="17"
                  height="17"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.8"
                >
                  <path d="M3 12h4l2.5-6 5 12 2.5-6h4" />
                  <path d="M4 21h16a1 1 0 001-1V4a1 1 0 00-1-1H4a1 1 0 00-1 1v16a1 1 0 001 1z" />
                </svg>
              ),
            },
            {
              key: "ai-diagnosis",
              label: "AI 진단",
              icon: (
                <svg
                  viewBox="0 0 24 24"
                  width="17"
                  height="17"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.8"
                >
                  <path d="M9 12l2 2 4-4" />
                  <circle cx="12" cy="12" r="9" />
                </svg>
              ),
            },
            {
              key: "ai-actions",
              label: "AI 조치",
              icon: (
                <svg
                  viewBox="0 0 24 24"
                  width="17"
                  height="17"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.8"
                >
                  <path d="M12 3l1.2 3.8L17 8l-3.8 1.2L12 13l-1.2-3.8L7 8l3.8-1.2L12 3z" />
                  <path d="M18.5 13l.8 2.2 2.2.8-2.2.8-.8 2.2-.8-2.2-2.2-.8 2.2-.8.8-2.2zM5 14l.7 2.3L8 17l-2.3.7L5 20l-.7-2.3L2 17l2.3-.7L5 14z" />
                </svg>
              ),
            },
            {
              key: "approvals",
              label: "승인 관리",
              icon: (
                <svg
                  viewBox="0 0 24 24"
                  width="17"
                  height="17"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.8"
                >
                  <path d="M9 11l3 3L22 4" />
                  <path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11" />
                </svg>
              ),
            },
          ].map((item) => {
            const selected =
              (item.key === "dashboard" && pageId !== null) ||
              (pageId === null && activeSection === item.key)
            return (
              <button
                key={item.key}
                onClick={() => goSection(item.key as MainSection)}
                className={`w-full min-h-[44px] flex items-center gap-2.5 rounded-xl px-3 text-left transition-colors ${
                  selected
                    ? "bg-[#101828] text-white shadow-sm"
                    : "text-[#475467] hover:bg-[#F2F4F7] hover:text-[#101828]"
                }`}
              >
                <span className="flex-shrink-0">{item.icon}</span>
                <span className="text-[11px] font-semibold flex-1">
                  {item.label}
                </span>
                {item.badge !== undefined && item.badge > 0 && (
                  <span
                    className={`min-w-[20px] h-5 px-1.5 rounded-full text-[9px] font-bold flex items-center justify-center ${
                      selected
                        ? "bg-white text-[#D92D20]"
                        : "bg-[#FEE4E2] text-[#D92D20]"
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
            )
          })}

          <div className="mt-auto px-2 py-2 rounded-xl bg-[#F8F9FB] border border-[#EAECF0]">
            <div className="flex items-center gap-2">
              <span
                className={`w-2 h-2 rounded-full ${
                  autoRefresh ? "bg-[#16A34A]" : "bg-[#98A2B3]"
                }`}
              />
              <span className="text-[10px] font-semibold text-[#475467]">
                {autoRefresh ? "실시간 조회 중" : "자동 조회 중지"}
              </span>
            </div>
            <p className="text-[9px] text-[#98A2B3] mt-1 pl-4">
              DB 대시보드 데이터
            </p>
          </div>
        </nav>

        {/* ── Main content ───────────────────────────────────────────── */}
        <section data-app-scroll-container className="flex-1 min-w-0 min-h-0 overflow-y-auto overscroll-contain bg-[#FAFAFA]">
          {pageId ? (
            <ScenarioPage
              id={pageId}
              doneActions={doneActions}
              onExecute={executeScenarioAction}
              onNavigate={openScenario}
              onBack={closeScenario}
            />
          ) : activeSection === "events" ? (
            <div className="min-h-full p-4 flex flex-col">
              <div className="flex items-end justify-between mb-3 flex-shrink-0">
                <div>
                  <p className="text-[18px] font-bold text-[#101828]">
                    보안 이벤트
                  </p>
                  <p className="text-[11px] text-[#667085] mt-0.5">
                    조치 필요 이벤트와 탐지·조치 이력을 한곳에서 확인합니다.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  {selectedEvent && (
                    <button
                      onClick={() => goSection("dashboard")}
                      className="text-[10px] font-semibold text-white bg-[#101828] hover:bg-[#1D2939] px-3 py-1.5 rounded-lg transition-colors"
                    >
                      선택 이벤트 맵에서 보기
                    </button>
                  )}
                  <button
                    onClick={() => void loadDashboardData()}
                    className="text-[10px] font-semibold text-[#344054] bg-white border border-[#D0D5DD] hover:bg-[#F9FAFB] px-3 py-1.5 rounded-lg transition-colors"
                  >
                    지금 새로고침
                  </button>
                </div>
              </div>
              {dashboardDataState !== "success" && (
                <div className="mb-3 flex-shrink-0">
                  <DashboardDataStatus
                    status={dashboardDataState}
                    onRetry={() => void loadDashboardData()}
                  />
                </div>
              )}
              <div className="flex-1 bg-[#F6F7F9] border border-[#EAECF0] rounded-2xl overflow-hidden">
                <RightPanel
                  tab={rightTab}
                  setTab={setRightTab}
                  events={displayedActionEvents}
                  detectHistory={detectHistory}
                  remediationHistory={remediationHistory}
                  selectedEvent={selectedEvent}
                  onSelectEvent={handleSelectEvent}
                  onApprove={(event) => {
                    if (remediationPendingRef.current || isPendingApproval(event)) return
                    if (canRemediate(event)) {
                      void handleDirectRemediation(event)
                      return
                    }
                    setRemediationError(null)
                    setRemediationSucceeded(false)
                    setApprovalTarget(event)
                  }}
                  onExcept={handleExceptEvents}
                  onBulkRequest={handleBulkApprovalRequests}
                  role={authUser?.role ?? ""}
                  onUnauthorized={() => {
                    setAuthUser(null)
                    setAuthState("unauthenticated")
                  }}
                />
              </div>
            </div>
          ) : activeSection === "monitoring" ? (
            <ManualMonitoringPage
              onUnauthorized={() => {
                setAuthUser(null)
                setAuthState("unauthenticated")
              }}
            />
          ) : activeSection === "ai-actions" ? (
            <ComingSoonSection
              title="AI 조치"
              description="탐지 이벤트 분석과 조치 검토를 위한 화면입니다."
              items={[
                "위험 원인",
                "공격 경로",
                "권장 조치",
                "조치 근거",
                "예상 영향",
                "승인 · 보류 · 예외 처리",
              ]}
            />
          ) : activeSection === "ai-diagnosis" ? (
            <AIDiagnosisPage
              onUnauthorized={() => {
                setAuthUser(null)
                setAuthState("unauthenticated")
              }}
            />
          ) : activeSection === "approvals" ? (
            <ApprovalQueuePage
              role={authUser?.role ?? ""}
              onUnauthorized={() => {
                setAuthUser(null)
                setAuthState("unauthenticated")
              }}
            />
          ) : (
            <main className="min-h-full flex flex-col gap-2 p-3">
              {/* Architecture map now uses the full dashboard width */}
              {/* absolute 배너로 떠 있게 해서, 로딩 배너가 뜨고 사라질 때
                  지도 영역 크기 자체가 바뀌지 않게 한다(새로고침마다 "줌"되어 보이던 원인). */}
              <div className="flex-1 min-h-[360px] relative">
                {dashboardDataState !== "success" && (
                  <div className="absolute left-0 right-0 top-0 z-10">
                    <DashboardDataStatus
                      status={dashboardDataState}
                      onRetry={() => void loadDashboardData()}
                    />
                  </div>
                )}
                <ArchitectureMap
                  assetStatuses={statuses}
                  highlightedAssets={highlightedAssets}
                  attackPathAssets={attackPathAssets}
                  connectionAssetGroups={connectionAssetGroups}
                  alerts={alerts}
                  onAssetClick={handleAssetClick}
                  onBackgroundClick={clearSelection}
                  hasScenario={hasScenario}
                />
              </div>

              {/* 운영 지표는 기존 6개 카드 위치와 크기를 그대로 사용한다. */}
              <div className="flex-shrink-0">
                <div className="grid grid-cols-6 gap-2" style={{ height: 150 }}>
                  <OverviewMetricCard
                    title="CPU 사용률"
                    metric={overviewMetrics?.cpu ?? null}
                    unit="%"
                    color="#2563EB"
                    waiting={overviewMetricsState === "loading"}
                  />
                  <OverviewMetricCard
                    title="메모리 사용률"
                    metric={overviewMetrics?.memory ?? null}
                    unit="%"
                    color="#7C3AED"
                    waiting={overviewMetricsState === "loading"}
                  />
                  <OverviewMetricCard
                    title="요청 지연 시간"
                    metric={overviewMetrics?.latency ?? null}
                    unit="ms"
                    decimals={0}
                    color="#0891B2"
                    waiting={overviewMetricsState === "loading"}
                  />
                  <OverviewMetricCard
                    title="요청 처리량"
                    metric={overviewMetrics?.rps ?? null}
                    unit="rps"
                    color="#16A34A"
                    waiting={overviewMetricsState === "loading"}
                  />
                  <OverviewMetricCard
                    title="에러율"
                    metric={overviewMetrics?.errorRate ?? null}
                    unit="%"
                    color="#D92D20"
                    waiting={overviewMetricsState === "loading"}
                  />
                  <HealthMetricCard
                    metric={overviewMetrics?.health ?? null}
                    waiting={overviewMetricsState === "loading"}
                  />
                </div>
              </div>
            </main>
          )}
        </section>
      </div>

      {/* ── Floating AI assistant ─────────────────────────────────────── */}
      {chatOpen ? (
        <div
          className="fixed right-5 bottom-3 z-[70] w-[390px] max-w-[calc(100vw-40px)] bg-white border border-[#D0D5DD] rounded-2xl shadow-[0_20px_48px_rgba(16,24,40,0.18)] overflow-hidden"
          style={{ height: 520, maxHeight: "calc(100vh - 96px)" }}
        >
          <SecurityChatbot
            selectedEvent={chatContextEvent}
            onHighlightPath={() => {
              if (selectedEvent) {
                setSelectedEvent(selectedEvent)
                goSection("dashboard")
              }
            }}
            onShowRecommend={() => {
              if (selectedEvent) goSection("events")
            }}
            onClose={() => setChatOpen(false)}
          />
        </div>
      ) : (
        <button
          onClick={() => setChatOpen(true)}
          className="fixed right-5 bottom-3 z-[70] w-11 h-11 rounded-xl bg-[#101828] text-white shadow-[0_10px_24px_rgba(16,24,40,0.22)] hover:bg-[#1D2939] hover:-translate-y-0.5 transition-all flex items-center justify-center"
          aria-label="보안 AI 챗봇 열기"
          title="보안 AI 챗봇"
        >
          <svg
            viewBox="0 0 24 24"
            width="19"
            height="19"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z" />
            <path d="M8 10h.01M12 10h.01M16 10h.01" />
          </svg>
          {selectedEvent && (
            <span className="absolute -top-1 -right-1 w-5 h-5 rounded-full bg-[#D92D20] border-2 border-white" />
          )}
        </button>
      )}

      {toast && (
        <div className="fixed top-16 left-1/2 -translate-x-1/2 z-[60] bg-[#101828] text-white text-xs font-semibold rounded-full px-4 py-2.5 shadow-xl fade-in">
          ✓ {toast}
        </div>
      )}

      {/* ── Approval Modal ─────────────────────────────────────────────── */}
      {approvalTarget && (
        <ApprovalModal
          ev={{ ...approvalTarget, executor: "Remediation Lambda", rollback: "조치별 별도 확인 필요" }}
          isExecuting={isRemediating}
          error={remediationError}
          title="조치 요청 보내기"
          description="아래 내용으로 승인자에게 조치 요청을 보냅니다. 승인자가 승인해야 실제로 조치가 실행됩니다."
          agreementText="위 내용을 확인했으며 이 조치 요청을 승인자에게 보냅니다."
          executingLabel="요청 보내는 중..."
          confirmLabel={remediationSucceeded ? "최신 상태 다시 조회" : "승인 요청 보내기"}
          onClose={() => {
            if (!remediationPendingRef.current) {
              setApprovalTarget(null)
              setRequestNote("")
            }
          }}
          onConfirm={handleApproveConfirm}
          {...(!canRemediate(approvalTarget)
            ? { noteValue: requestNote, onNoteChange: setRequestNote }
            : {})}
        />
      )}
    </div>
  )
}
