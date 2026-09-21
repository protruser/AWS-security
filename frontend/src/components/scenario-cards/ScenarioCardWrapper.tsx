import React from "react"
import type { ScenarioCard } from "../../data/types"
import { DonutGauge } from "../shared/common"

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
