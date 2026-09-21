import React, { useState, useEffect, useRef, useMemo } from "react"
import type {
  AssetStatus,
  RightTab,
  ActionEvent,
  ScenarioCard,
} from "./data/types"

import {
  ACTION_EVENTS,
  DETECT_HISTORY,
  REMEDIATION_HISTORY,
  SCENARIO_CARDS,
  SUGGESTED_QUESTIONS,
  getBotResponse,
} from "./data/mock"

import { ALERT_RULES, ASSETS, scenariosForAsset } from "./data/architecture"
import { SCENARIO_DETAILS } from "./data/scenarios"

import { ArchitectureMap } from "./components/architecture/ArchitectureMap"
import { ScenarioPage } from "./components/scenario/ScenarioPage"
import { AttackLabPage } from "./components/attack-lab/AttackLabPage"
import { ApprovalModal, DonutGauge, SeverityBadge } from "./components/common"

// ─── Action card ──────────────────────────────────────────────────────────────

function ActionCard({
  ev,
  selected,
  onSelect,
  onApprove,
}: {
  ev: ActionEvent
  selected: boolean
  onSelect: () => void
  onApprove: () => void
}) {
  return (
    <div
      onClick={onSelect}
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
            <SeverityBadge sev={ev.severity} small />
            {ev.autoRemediation && (
              <span className="text-[9px] font-semibold px-1.5 py-0.5 rounded-full bg-[#F5F5F5] text-[#111111]">
                자동 조치 가능
              </span>
            )}
          </div>
          <span className="text-[10px] text-[#6B6B6B] whitespace-nowrap">
            미조치 {ev.elapsed}
          </span>
        </div>
        <p className="text-xs font-bold text-[#0D0D0D] mb-1">{ev.title}</p>
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
        <div className="flex gap-1.5 mt-2.5">
          <button
            onClick={(e) => {
              e.stopPropagation()
              onApprove()
            }}
            className="flex-1 text-[11px] font-bold text-white bg-[#111111] hover:bg-[#262626] px-2.5 py-1.5 rounded-lg transition-colors"
          >
            조치 승인
          </button>
          <button
            onClick={(e) => e.stopPropagation()}
            className="text-[11px] text-[#6B6B6B] border border-[#E0E0E0] hover:bg-[#FAFAFA] px-2.5 py-1.5 rounded-lg transition-colors"
          >
            예외 처리
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Right panel (top half) ───────────────────────────────────────────────────

function RightPanel({
  tab,
  setTab,
  events,
  selectedEvent,
  onSelectEvent,
  onApprove,
}: {
  tab: RightTab
  setTab: (t: RightTab) => void

  events: ActionEvent[]

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
          {REMEDIATION_HISTORY.map((r) => (
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
                {DETECT_HISTORY.filter(
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

// ─── Security Chatbot ─────────────────────────────────────────────────────────

interface ChatMessage {
  role: "user" | "bot"

  text: string

  actions?: string[]
}

function SecurityChatbot({
  selectedEvent,
  onHighlightPath,
  onShowRecommend,
}: {
  selectedEvent: ActionEvent | null

  onHighlightPath: () => void

  onShowRecommend: () => void
}) {
  const [messages, setMessages] = useState<ChatMessage[]>([])

  const [input, setInput] = useState("")

  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (scrollRef.current)
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
  }, [messages])

  const sendMessage = (text: string) => {
    if (!text.trim()) return

    const { text: botText, actions } = getBotResponse(text, selectedEvent)

    setMessages((prev) => [
      ...prev,

      { role: "user", text },

      { role: "bot", text: botText, actions },
    ])

    setInput("")
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
      </div>

      {/* Context chip */}
      {selectedEvent && (
        <div className="px-3 py-1.5 bg-[#F5F5F5] border-b border-[#D4D4D4] flex-shrink-0">
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[9px] font-bold text-[#111111]">
              컨텍스트:
            </span>
            <span className="text-[9px] bg-white border border-[#A3A3A3] text-[#111111] px-1.5 py-0.5 rounded-full font-medium">
              {selectedEvent.title}
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
                  onClick={() => sendMessage(q)}
                  className="text-[10px] text-[#111111] bg-[#F5F5F5] hover:bg-[#E0E0E0] border border-[#D4D4D4] px-2 py-1.5 rounded-lg text-left transition-colors leading-tight"
                >
                  {q}
                </button>
              ))}
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
            onKeyDown={(e) => e.key === "Enter" && sendMessage(input)}
            placeholder="보안 이벤트 또는 로그에 대해 질문하세요"
            className="flex-1 text-[11px] border border-[#E0E0E0] rounded-lg px-2.5 py-1.5 outline-none focus:border-[#111111] bg-white"
          />
          <button
            onClick={() => sendMessage(input)}
            className="text-[11px] font-bold text-white bg-[#111111] hover:bg-[#262626] px-3 py-1.5 rounded-lg transition-colors"
          >
            전송
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

function CardHeader({
  title,
  onOpen,
}: {
  title: string
  onOpen: () => void
}) {
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
function TrafficCard({ card, isSelected, isMuted, onClick, onOpen }: CardProps) {
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
function AnomalyCard({ card, isSelected, isMuted, onClick, onOpen }: CardProps) {
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
        <p className="text-[26px] font-bold leading-none" style={{ color: accent }}>
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
      className="relative bg-white rounded-[10px] border cursor-pointer transition-all hover:shadow-md"
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

function ScenarioCardWrapper({
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

function parseRoute(): string | null {
  const m = window.location.hash.match(/^#\/scenario\/(\w+)/)
  return m && SCENARIO_CARDS.some((c) => c.id === m[1]) ? m[1] : null
}

const isLabRoute = () => window.location.hash === "#/lab"

export default function App() {
  const [now, setNow] = useState(new Date(2026, 8, 18, 14, 32, 10))

  const [autoRefresh, setAutoRefresh] = useState(true)

  const [rightTab, setRightTab] = useState<RightTab>("action")

  const [selectedEvent, setSelectedEvent] = useState<ActionEvent | null>(null)

  const [selectedScenario, setSelectedScenario] = useState<ScenarioCard | null>(
    null,
  )

  // 지도에서 누른 인프라 하나 (그 자산과 연결된 선만 강조)
  const [selectedAsset, setSelectedAsset] = useState<string | null>(null)

  const [approvalTarget, setApprovalTarget] = useState<ActionEvent | null>(null)

  const [removedIds, setRemovedIds] = useState<Set<string>>(new Set())

  // Scenario detail page (hash route: #/scenario/<id>)
  const [pageId, setPageId] = useState<string | null>(parseRoute)

  // 공격 시뮬레이션 페이지 (hash route: #/lab) — 관제 화면과 분리된 별도 페이지
  const [labOpen, setLabOpen] = useState(isLabRoute)

  // actionId -> 실행 시각 (상세 페이지에서 실행한 조치)
  const [doneActions, setDoneActions] = useState<Record<string, string>>({})

  const [toast, setToast] = useState<string | null>(null)

  useEffect(() => {
    const onHash = () => {
      setPageId(parseRoute())
      setLabOpen(isLabRoute())
    }
    window.addEventListener("hashchange", onHash)
    return () => window.removeEventListener("hashchange", onHash)
  }, [])

  useEffect(() => {
    if (!toast) return
    const id = setTimeout(() => setToast(null), 2600)
    return () => clearTimeout(id)
  }, [toast])

  const openScenario = (id: string) => {
    window.location.hash = `#/scenario/${id}`
  }

  const closeScenario = () => {
    window.location.hash = ""
  }

  // Clock tick

  useEffect(() => {
    if (!autoRefresh) return

    const id = setInterval(
      () => setNow((d) => new Date(d.getTime() + 60000)),
      60000,
    )

    return () => clearInterval(id)
  }, [autoRefresh])

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

  // Compute asset statuses based on selected event

  const statuses = useMemo((): Record<string, AssetStatus> => {
    const base: Record<string, AssetStatus> = {}

    ASSETS.forEach((a) => {
      base[a.id] = a.defaultStatus
    })

    const selection = selectedEvent ?? selectedScenario
    if (selection) {
      selection.attackPath.forEach((id) => {
        base[id] = "critical"
      })
      selection.highlightAssets.forEach((id) => {
        if (!selection.attackPath.includes(id)) base[id] = "warning"
      })
    }

    return base
  }, [selectedEvent, selectedScenario])

  // 시나리오 선택 (같은 것을 다시 누르면 해제)
  const toggleScenario = (card: ScenarioCard) => {
    if (selectedScenario?.id === card.id) {
      clearSelection()
      return
    }

    setSelectedAsset(null)
    setSelectedScenario(card)
    setSelectedEvent(
      card.actionEventId
        ? (ACTION_EVENTS.find((e) => e.id === card.actionEventId) ?? null)
        : null,
    )
  }

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

  const handleApproveConfirm = () => {
    if (!approvalTarget) return

    setRemovedIds((prev) => new Set([...prev, approvalTarget.id]))

    setToast(`조치가 실행되었습니다 — ${approvalTarget.title}`)

    setApprovalTarget(null)

    clearSelection()
  }

  const fmt = (d: Date) =>
    `${d.getFullYear()}.${String(d.getMonth() + 1).padStart(2, "0")}.${String(d.getDate()).padStart(2, "0")} ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`

  const executeScenarioAction = (actionId: string) => {
    const t = `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}`
    setDoneActions((prev) => ({ ...prev, [actionId]: t }))
    setToast("조치가 실행되었습니다")
  }

  const activeEvents = ACTION_EVENTS.filter((e) => !removedIds.has(e.id))

  const scenarioResolved = (id: string) => {
    const acts = SCENARIO_DETAILS[id]?.actions ?? []
    return acts.length > 0 && acts.every((a) => doneActions[a.id])
  }

  // 아직 해제되지 않은 비상 자산 (지도의 빨간/주황 점)
  const alerts: Record<string, { level: "critical" | "warning"; reason: string }> = {}
  ALERT_RULES.forEach((r) => {
    const cleared =
      (r.clearedByEvent && removedIds.has(r.clearedByEvent)) ||
      (r.clearedByScenario && scenarioResolved(r.clearedByScenario))
    if (!cleared) alerts[r.assetId] = { level: r.level, reason: r.reason }
  })
  const criticalCount = Object.values(alerts).filter((a) => a.level === "critical").length
  const warningCount = Object.values(alerts).length - criticalCount

  const abnormalScenarios = SCENARIO_CARDS.filter(
    (c) => SCENARIO_DETAILS[c.id].tone !== "ok" && !scenarioResolved(c.id),
  ).length

  const avgWait = activeEvents.length
    ? Math.round(
        activeEvents.reduce((n, e) => n + parseInt(e.elapsed, 10), 0) /
          activeEvents.length,
      )
    : 0

  const selection = selectedEvent ?? selectedScenario

  const hasScenario = selection !== null || selectedAsset !== null

  const highlightedAssets = selection
    ? selection.highlightAssets
    : selectedAsset
      ? [selectedAsset]
      : []

  // 누른 인프라와 관련된 시나리오 카드는 함께 강조한다.
  const relatedScenarioIds = selectedAsset ? scenariosForAsset(selectedAsset) : []

  const attackPathAssets = selection ? selection.attackPath : []

  const chatContextEvent = selectedEvent

  return (
    <div
      className="h-screen flex flex-col overflow-hidden bg-[#FAFAFA]"
      style={{
        fontFamily:
          "'Pretendard Variable', 'Pretendard', -apple-system, sans-serif",
      }}
    >
      {/* ── Header ─────────────────────────────────────────────────────── */}
      <header className="bg-white border-b border-[#E4E7EC] h-14 flex-shrink-0 flex items-center px-5 justify-between">
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
                criticalCount
                  ? "bg-[#D92D20] alert-dot-critical"
                  : warningCount
                    ? "bg-[#F79009] alert-dot-warning"
                    : "bg-[#16A34A]"
              }`}
            />
            <span
              className="text-[11px] font-semibold"
              style={{
                color: criticalCount ? "#D92D20" : warningCount ? "#B54708" : "#16A34A",
              }}
            >
              {criticalCount
                ? `비상 ${criticalCount}건 대응 필요`
                : warningCount
                  ? `주의 ${warningCount}건`
                  : "정상 운영 중"}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-4 text-xs text-[#6B6B6B]">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#101828] pulse-dot flex-shrink-0" />
            <span className="text-[#101828] font-bold text-[11px]">LIVE</span>
          </div>
          <span className="font-mono text-[11px] text-[#0D0D0D]">
            {fmt(now)}
          </span>
          <button
            onClick={() => setAutoRefresh((v) => !v)}
            className={`text-[11px] font-semibold px-2.5 py-1 rounded-full border transition-colors ${
              autoRefresh
                ? "border-[#111111] text-[#111111] bg-[#F5F5F5]"
                : "border-[#E0E0E0] text-[#6B6B6B]"
            }`}
          >
            {autoRefresh ? "자동 갱신 ON" : "자동 갱신 OFF"}
          </button>

          <a
            href="#/lab"
            className="text-[11px] text-[#98A2B3] hover:text-[#344054] transition-colors"
          >
            공격 시뮬레이션
          </a>

          {/* Alert bell */}
          <button className="relative p-1.5 hover:bg-[#F5F5F5] rounded-lg">
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
            {criticalCount + warningCount > 0 && (
              <span className="absolute -top-0.5 -right-0.5 w-4 h-4 bg-[#D92D20] text-white text-[9px] font-bold rounded-full flex items-center justify-center">
                {criticalCount + warningCount}
              </span>
            )}
          </button>

          {/* Profile */}
          <div className="flex items-center gap-2 cursor-pointer hover:bg-[#F5F5F5] rounded-lg px-2 py-1 transition-colors">
            <div className="w-7 h-7 rounded-full bg-[#111111] flex items-center justify-center text-white text-[11px] font-bold">
              관
            </div>
            <div>
              <p className="text-[11px] font-semibold text-[#0D0D0D] leading-tight">
                보안관제팀
              </p>
              <p className="text-[9px] text-[#6B6B6B] leading-tight">관리자</p>
            </div>
          </div>
        </div>
      </header>

      {/* ── Body ───────────────────────────────────────────────────────── */}
      {labOpen ? (
        <AttackLabPage onBack={closeScenario} />
      ) : pageId ? (
        <ScenarioPage
          id={pageId}
          doneActions={doneActions}
          onExecute={executeScenarioAction}
          onNavigate={openScenario}
          onBack={closeScenario}
        />
      ) : (
      <div className="flex flex-1 overflow-hidden">
        {/* ── Left: Architecture map + scenario cards ──────────────────── */}
        <main
          className="flex-1 min-w-0 overflow-hidden flex flex-col gap-2 p-3"
        >
          {/* Summary strip */}
          <div className="grid grid-cols-4 gap-2 flex-shrink-0">
            {[
              {
                label: "비상 자산",
                value: criticalCount,
                unit: "건",
                tone: criticalCount ? "#D92D20" : "#16A34A",
                hint: warningCount ? `주의 ${warningCount}건 별도` : "주의 없음",
              },
              {
                label: "조치 필요",
                value: activeEvents.length,
                unit: "건",
                tone: activeEvents.length ? "#F79009" : "#16A34A",
                hint: `Critical ${activeEvents.filter((e) => e.severity === "Critical").length}건 포함`,
              },
              {
                label: "이상 시나리오",
                value: abnormalScenarios,
                unit: `/ ${SCENARIO_CARDS.length}`,
                tone: abnormalScenarios ? "#D92D20" : "#16A34A",
                hint: `정상 ${SCENARIO_CARDS.length - abnormalScenarios}개`,
              },
              {
                label: "평균 조치 대기",
                value: avgWait,
                unit: "분",
                tone: "#101828",
                hint: "미조치 이벤트 기준",
              },
            ].map((k) => (
              <div
                key={k.label}
                className="bg-white rounded-lg ring-1 ring-[#EAECF0] px-3 py-1.5 flex items-center gap-2"
              >
                <div>
                  <p className="text-[11px] text-[#667085]">{k.label}</p>
                  <p className="leading-tight">
                    <span
                      className="text-[17px] font-bold"
                      style={{ color: k.tone }}
                    >
                      {k.value}
                    </span>
                    <span className="text-xs text-[#667085] ml-1">{k.unit}</span>
                  </p>
                </div>
                <p className="ml-auto text-[9px] text-[#98A2B3] text-right hidden xl:block">
                  {k.hint}
                </p>
              </div>
            ))}
          </div>

          {/* Architecture map — flex-1 fills remaining height, map scales to fit */}
          <div className="flex-1 min-h-0 relative">
            <ArchitectureMap
              assetStatuses={statuses}
              highlightedAssets={highlightedAssets}
              attackPathAssets={attackPathAssets}
              alerts={alerts}
              onAssetClick={handleAssetClick}
              onBackgroundClick={clearSelection}
              hasScenario={hasScenario}
            />
          </div>

          {/* Scenario cards: compact row of 6 + full-width vuln card */}
          <div className="flex-shrink-0 flex flex-col gap-2">
            <div className="grid grid-cols-6 gap-2" style={{ height: 150 }}>
              {SCENARIO_CARDS.filter((c) => c.type !== "vuln").map((card) => (
                <ScenarioCardWrapper
                  key={card.id}
                  card={card}
                  isSelected={
                    selectedScenario?.id === card.id ||
                    relatedScenarioIds.includes(card.id)
                  }
                  anySelected={hasScenario}
                  onSelect={toggleScenario}
                  onOpen={(c) => openScenario(c.id)}
                />
              ))}
            </div>
            {SCENARIO_CARDS.filter((c) => c.type === "vuln").map((card) => (
              <ScenarioCardWrapper
                key={card.id}
                card={card}
                isSelected={
                  selectedScenario?.id === card.id ||
                  relatedScenarioIds.includes(card.id)
                }
                anySelected={hasScenario}
                onSelect={toggleScenario}
                onOpen={(c) => openScenario(c.id)}
              />
            ))}
          </div>
        </main>

        {/* ── Right: split panel ──────────────────────────────────────── */}
        <aside
          className="flex-shrink-0 border-l border-[#E4E7EC] bg-[#F6F7F9] flex flex-col overflow-hidden"
          style={{ width: 380, height: "calc(100vh - 56px)" }}
        >
          {/* Top: action list + detect history */}
          <div
            className="flex flex-col overflow-hidden"
            style={{ height: "68%" }}
          >
            <RightPanel
              tab={rightTab}
              setTab={setRightTab}
              events={activeEvents}
              selectedEvent={selectedEvent}
              onSelectEvent={handleSelectEvent}
              onApprove={setApprovalTarget}
            />
          </div>

          {/* Divider */}
          <div className="border-t border-[#E4E7EC] flex-shrink-0" />

          {/* Bottom: compact AI assistant */}
          <div
            className="flex flex-col overflow-hidden"
            style={{ height: "32%" }}
          >
            <SecurityChatbot
              selectedEvent={chatContextEvent}
              onHighlightPath={() => {
                if (selectedEvent) {
                  setSelectedEvent(selectedEvent)
                }
              }}
              onShowRecommend={() => {}}
            />
          </div>
        </aside>
      </div>
      )}

      {toast && (
        <div className="fixed top-16 left-1/2 -translate-x-1/2 z-[60] bg-[#101828] text-white text-xs font-semibold rounded-full px-4 py-2.5 shadow-xl fade-in">
          ✓ {toast}
        </div>
      )}

      {/* ── Approval Modal ─────────────────────────────────────────────── */}
      {approvalTarget && (
        <ApprovalModal
          ev={approvalTarget}
          onClose={() => setApprovalTarget(null)}
          onConfirm={handleApproveConfirm}
        />
      )}
    </div>
  )
}
