import { useEffect, useState } from "react"
import {
  fetchEventAnalysis,
  type EventAnalysis,
} from "../services/eventAnalysis"

export function AnalysisContent({ analysis }: { analysis: EventAnalysis }) {
  const heading = "font-semibold text-[#344054] mb-1"
  return (
    <div className="space-y-3 leading-relaxed break-words">
      <p className="text-[#667085]">
        {analysis.attack_type} ·{" "}
        {analysis.event_status === "CONFIRMED"
          ? "탐지 근거 확인"
          : analysis.event_status === "SUSPICIOUS"
            ? "의심 활동"
            : "정보성 이벤트"}
      </p>
      <section>
        <h4 className={heading}>탐지 요약</h4>
        <p>{analysis.summary}</p>
      </section>
      <section>
        <h4 className={heading}>핵심 근거</h4>
        <dl className="space-y-2">
          {analysis.key_evidence.map((item, index) => (
            <div
              key={index}
              className="rounded border border-[#EAECF0] bg-white p-2"
            >
              <dt className="font-semibold">{item.label}</dt>
              <dd className="whitespace-pre-wrap break-all font-mono text-[#101828]">
                {item.value}
              </dd>
              <dd className="mt-1 text-[#667085]">{item.description}</dd>
            </div>
          ))}
        </dl>
      </section>
      <section>
        <h4 className={heading}>예상 영향</h4>
        <p>{analysis.impact}</p>
      </section>
      {analysis.remediation_type === "AUTO" ? (
        <section>
          <h4 className={heading}>자동 조치 내용</h4>
          <p>{analysis.automatic_action}</p>
        </section>
      ) : (
        <section>
          <h4 className={heading}>권장 조치</h4>
          <ol className="list-decimal pl-4 space-y-1">
            {analysis.recommended_actions.map((item, index) => (
              <li key={index}>{item}</li>
            ))}
          </ol>
        </section>
      )}
      <section>
        <h4 className={heading}>추가 확인</h4>
        {analysis.additional_check.length ? (
          <ul className="list-disc pl-4 space-y-1">
            {analysis.additional_check.map((item, index) => (
              <li key={index}>{item}</li>
            ))}
          </ul>
        ) : (
          <p>추가 확인 항목 없음</p>
        )}
      </section>
    </div>
  )
}

export function EventAIAnalysis({ eventId }: { eventId: string }) {
  const [state, setState] = useState<{
    id: string
    analysis?: EventAnalysis
    failed?: boolean
  }>({ id: eventId })
  const [retry, setRetry] = useState(0)
  useEffect(() => {
    let active = true
    setState({ id: eventId })
    fetchEventAnalysis(eventId).then(
      (analysis) => {
        if (active) setState({ id: eventId, analysis })
      },
      () => {
        if (active) setState({ id: eventId, failed: true })
      },
    )
    return () => {
      active = false
    }
  }, [eventId, retry])
  const current = state.id === eventId ? state : { id: eventId }
  return (
    <section
      className="mt-3 border-t border-[#E4E7EC] pt-3 text-[#475467]"
      onClick={(event) => event.stopPropagation()}
      aria-label="AI 이벤트 분석"
    >
      <h3 className="mb-2 text-xs font-bold text-[#101828]">AI 이벤트 분석</h3>
      {current.analysis ? (
        <AnalysisContent analysis={current.analysis} />
      ) : (
        <p role="status">
          {current.failed
            ? "AI 분석을 불러오지 못했습니다."
            : "AI 분석을 불러오는 중입니다."}
          {current.failed && (
            <button
              className="ml-2 underline"
              onClick={() => setRetry((value) => value + 1)}
            >
              다시 시도
            </button>
          )}
        </p>
      )}
    </section>
  )
}

export function OriginalEventLogs({ logs }: { logs: string }) {
  return (
    <details
      className="mt-3 border-t border-[#E4E7EC] pt-2"
      onClick={(event) => event.stopPropagation()}
    >
      <summary className="cursor-pointer font-semibold text-[#344054]">
        원본 로그 보기
      </summary>
      <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all rounded bg-white p-2 font-mono text-[10px] text-[#667085]">
        {logs || "원본 로그 없음"}
      </pre>
    </details>
  )
}
