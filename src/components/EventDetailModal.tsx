import { useEffect, useRef } from "react"
import { createPortal } from "react-dom"
import type { ActionEvent } from "../data/types"
import { eventDisplayTitle } from "../services/eventAnalysis"
import { EventAIAnalysis, OriginalEventLogs } from "./EventAIAnalysis"
import { SeverityBadge } from "./common"
import { STAGE_META } from "./AttackerTrackingPage"

interface EventDetailModalProps {
  event: ActionEvent
  isAuto: boolean
  isPending: boolean
  onClose: () => void
  onApprove: () => void
  onExcept: () => void
}

export function EventDetailModal({
  event,
  isAuto,
  isPending,
  onClose,
  onApprove,
  onExcept,
}: EventDetailModalProps) {
  const dialogRef = useRef<HTMLDivElement>(null)
  const closeButtonRef = useRef<HTMLButtonElement>(null)
  const onCloseRef = useRef(onClose)
  onCloseRef.current = onClose

  useEffect(() => {
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null
    const pageScroller = document.querySelector<HTMLElement>("[data-app-scroll-container]")
    const previousBodyOverflow = document.body.style.overflow
    const previousPageOverflow = pageScroller?.style.overflow ?? ""
    document.body.style.overflow = "hidden"
    if (pageScroller) pageScroller.style.overflow = "hidden"
    closeButtonRef.current?.focus()

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault()
        event.stopPropagation()
        onCloseRef.current()
      }
      if (event.key !== "Tab") return
      const buttons = Array.from(
        dialogRef.current?.querySelectorAll<HTMLElement>(
          'button:not([disabled]), summary, [tabindex]:not([tabindex="-1"])',
        ) ?? [],
      )
      if (buttons.length === 0) return
      const first = buttons[0]
      const last = buttons[buttons.length - 1]
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first.focus()
      }
    }
    // Capture Escape before the dashboard's selection-clearing window listener.
    document.addEventListener("keydown", onKeyDown, true)
    return () => {
      document.removeEventListener("keydown", onKeyDown, true)
      document.body.style.overflow = previousBodyOverflow
      if (pageScroller) pageScroller.style.overflow = previousPageOverflow
      previousFocus?.focus()
    }
  }, [])

  const facts = [
    ["유형", event.scenarioType],
    ...(event.scenarioType === "vuln" ? [["원본 이벤트 제목", event.title]] : []),
    ["공격 IP", event.details.attackerIP],
    ["요청", event.details.requestURL],
    ["위험도", event.severity],
    ["탐지 시간", event.detectedAt],
    ["탐지 서비스", event.service],
    ["대상 자산", event.asset],
    ["탐지 규칙", event.details.rule],
    // blocked 컬럼은 IP 차단 조치 후 '차단'으로 덮어써지므로, Lambda B 원래 수치가 있으면 그것을 보여준다.
    event.reach && event.reach.requests !== null
      ? ["WAF 결과", `요청 ${event.reach.requests}건 중 ${event.reach.passed ?? 0}건 통과 (${event.reach.stage} ${STAGE_META[event.reach.stage].label})`]
      : ["차단 여부", event.details.blocked === undefined || event.details.blocked === null
        ? null : event.details.blocked ? "차단" : "미차단"],
    [isAuto ? "조치 내용" : "권장 조치", event.recommendation],
  ].filter((entry): entry is [string, string] => typeof entry[1] === "string" && entry[1].length > 0)

  const content = (
    <div className="fixed inset-0 z-[80] flex items-center justify-center bg-[#101828]/60 p-3 sm:p-6">
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="event-detail-title"
        className="flex w-full max-w-[1000px] max-h-[85dvh] min-h-0 flex-col overflow-hidden rounded-2xl bg-white shadow-[0_24px_64px_rgba(16,24,40,0.3)]"
      >
        <header className="flex shrink-0 items-start justify-between gap-4 border-b border-[#E4E7EC] px-4 py-3 sm:px-6 sm:py-4">
          <div className="min-w-0">
            <div className="mb-1 flex flex-wrap items-center gap-2">
              <SeverityBadge sev={event.severity} small />
              <span className="rounded-full bg-[#F2F4F7] px-2 py-0.5 text-[10px] font-semibold text-[#475467]">{event.status}</span>
            </div>
            <h2 id="event-detail-title" className="break-words text-base font-bold text-[#101828] sm:text-lg">
              {eventDisplayTitle(event)}
            </h2>
          </div>
          <button
            ref={closeButtonRef}
            type="button"
            onClick={onClose}
            aria-label="이벤트 상세 닫기"
            className="shrink-0 rounded-lg px-2 py-1 text-lg text-[#667085] hover:bg-[#F2F4F7] hover:text-[#101828]"
          >
            ×
          </button>
        </header>

        <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain px-4 py-4 text-[12px] sm:px-6" data-event-detail-body>
          <h3 className="mb-2 text-xs font-bold text-[#101828]">기본 정보</h3>
          <dl className="grid grid-cols-1 gap-x-5 gap-y-2 rounded-xl border border-[#EAECF0] bg-[#F9FAFB] p-3 sm:grid-cols-2">
            {facts.map(([label, value]) => (
              <div key={label} className="min-w-0">
                <dt className="text-[10px] font-semibold text-[#667085]">{label}</dt>
                <dd className="break-all text-[#344054]">
                  {value}
                  {label === "공격 IP" && (
                    <a
                      href={`#/attackers/${encodeURIComponent(value)}`}
                      onClick={onClose}
                      className="ml-2 whitespace-nowrap text-[11px] font-semibold text-[#175CD3] hover:underline"
                    >
                      이 IP 추적 →
                    </a>
                  )}
                </dd>
              </div>
            ))}
          </dl>
          <EventAIAnalysis key={event.id} eventId={event.id} />
          <OriginalEventLogs key={`logs-${event.id}`} logs={event.details.logs} />
        </div>

        <footer className="flex shrink-0 flex-wrap justify-end gap-2 border-t border-[#E4E7EC] px-4 py-3 sm:px-6">
          <button type="button" onClick={onClose} className="rounded-lg border border-[#D0D5DD] px-3 py-2 text-xs font-semibold text-[#475467] hover:bg-[#F9FAFB]">
            닫기
          </button>
          <button type="button" onClick={onExcept} className="rounded-lg border border-[#D0D5DD] px-3 py-2 text-xs font-semibold text-[#475467] hover:bg-[#F9FAFB]">
            예외 처리
          </button>
          <button
            type="button"
            onClick={onApprove}
            disabled={isPending}
            className="rounded-lg bg-[#101828] px-3 py-2 text-xs font-bold text-white hover:bg-[#1D2939] disabled:cursor-not-allowed disabled:opacity-60"
          >
            {isPending ? "승인자 확인 대기 중" : isAuto ? "자동 조치 실행" : "이 조치로 승인 요청 보내기"}
          </button>
        </footer>
      </div>
    </div>
  )

  return typeof document === "undefined" ? content : createPortal(content, document.body)
}
