import { useState } from "react"
import type { ActionEvent, DetectHistoryItem, RemediationHistoryItem, RightTab } from "../../data/types"
import { ActionCard } from "../events/ActionCard"
import { SeverityBadge } from "../shared/common"

export function RightPanel({
  tab,
  setTab,
  events,
  detectHistory,
  remediationHistory,
  selectedEvent,
  onSelectEvent,
  onApprove,
}: {
  tab: RightTab
  setTab: (t: RightTab) => void

  events: ActionEvent[]
  detectHistory: DetectHistoryItem[]
  remediationHistory: RemediationHistoryItem[]

  selectedEvent: ActionEvent | null

  onSelectEvent: (ev: ActionEvent | null) => void

  onApprove: (ev: ActionEvent) => void
}) {
  const [detectFilter, setDetectFilter] = useState("전체")

  const detectFilters = ["전체", "Critical", "High", "Medium", "Low"]

  const activeEvents = events

  return (
    <div className="flex flex-col overflow-hidden h-full">
      {/* Tabs — segmented control */}
      <div className="flex-shrink-0 px-3 pt-3 pb-1">
        <div
          role="tablist"
          className="flex gap-1 p-1 rounded-xl bg-[#EEF0F3]"
        >
          {[
            { key: "action", label: "조치 필요", count: activeEvents.length },

            { key: "detect", label: "탐지 이력" },

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
        <div className="flex-1 overflow-y-auto p-3 space-y-2.5">
          {activeEvents.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-32 text-[#6B6B6B]">
              <span className="text-2xl mb-2">✅</span>
              <p className="text-sm font-medium">조치 필요 항목 없음</p>
            </div>
          ) : (
            activeEvents.map((ev: ActionEvent) => (
              <ActionCard
                key={ev.id}
                ev={ev}
                selected={selectedEvent?.id === ev.id}
                onSelect={() => onSelectEvent(ev)}
                onApprove={() => onApprove(ev)}
              />
            ))
          )}
        </div>
      )}

      {/* Remediation history tab */}
      {tab === "history" && (
        <div className="flex-1 overflow-y-auto p-3 space-y-2">
          {remediationHistory.map((r) => (
            <div
              key={r.id}
              className="rounded-xl border border-[#EAECF0] bg-white p-3"
            >
              <div className="flex items-center justify-between gap-2">
                <p className="text-xs font-bold text-[#0D0D0D]">{r.event}</p>
                <span className="text-[9px] font-bold px-1.5 py-0.5 rounded-full bg-[#16A34A] text-white">
                  {r.result}
                </span>
              </div>
              <p className="text-[10px] text-[#6B6B6B] mt-1">{r.asset}</p>
              <div className="flex flex-wrap gap-1 mt-1.5">
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
      )}

      {/* Detect history tab */}
      {tab === "detect" && (
        <div className="flex-1 overflow-y-auto p-3 space-y-2.5">
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
                  {["시각", "등급", "이벤트", "차단", "상태"].map((h) => (
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
                {detectHistory.filter(
                  (d) => detectFilter === "전체" || d.sev === detectFilter,
                ).map((d) => (
                  <tr
                    key={d.id}
                    className="border-b border-[#F5F5F5] hover:bg-[#FAFAFA] cursor-pointer"
                  >
                    <td className="py-1.5 px-2 text-[10px] font-mono text-[#6B6B6B]">
                      {d.time}
                    </td>
                    <td className="py-1.5 px-2">
                      <SeverityBadge sev={d.sev} small />
                    </td>
                    <td className="py-1.5 px-2 text-[10px] text-[#0D0D0D] max-w-[100px] truncate">
                      {d.event}
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
    </div>
  )
}
