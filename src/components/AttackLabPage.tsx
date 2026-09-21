import { useEffect, useRef, useState } from "react"
import { SCENARIO_CARDS } from "../data/mock"
import { LAB_SCENARIOS } from "../data/attackLab"

type RunState = { step: number; done: boolean }

const STORAGE_KEY = "attack-lab-confirmed"

function loadConfirmed(): Record<string, boolean> {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}")
  } catch {
    return {}
  }
}

export function AttackLabPage({ onBack }: { onBack: () => void }) {
  const [runs, setRuns] = useState<Record<string, RunState>>({})
  const [confirmed, setConfirmed] = useState<Record<string, boolean>>(loadConfirmed)
  const timers = useRef<number[]>([])

  useEffect(() => {
    const list = timers.current
    return () => list.forEach((t) => window.clearTimeout(t))
  }, [])

  const toggleConfirmed = (id: string) => {
    setConfirmed((prev) => {
      const next = { ...prev, [id]: !prev[id] }
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(next))
      } catch {
        // 저장이 막힌 환경에서는 이 화면에서만 유지한다.
      }
      return next
    })
  }

  // 실제 트래픽은 보내지 않고 단계만 순서대로 보여준다.
  const run = (id: string, total: number) => {
    setRuns((r) => ({ ...r, [id]: { step: 0, done: false } }))
    for (let i = 1; i <= total; i++) {
      timers.current.push(
        window.setTimeout(
          () =>
            setRuns((r) => ({
              ...r,
              [id]: { step: i, done: i === total },
            })),
          i * 700,
        ),
      )
    }
  }

  const doneCount = LAB_SCENARIOS.filter((s) => confirmed[s.id]).length

  return (
    <div className="flex-1 min-h-0 overflow-y-auto bg-[#F6F7F9]">
      <div className="mx-auto max-w-[900px] px-6 py-5 space-y-4">
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="inline-flex items-center gap-1.5 text-xs font-semibold text-[#344054] bg-white ring-1 ring-[#D0D5DD] hover:bg-[#F9FAFB] rounded-lg px-3 py-1.5 transition-colors"
          >
            <svg
              viewBox="0 0 16 16"
              width="12"
              height="12"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.8"
            >
              <path d="M13 8H3M7 4L3 8l4 4" />
            </svg>
            대시보드
          </button>
          <p className="ml-auto text-xs text-[#667085]">
            탐지 확인{" "}
            <b className="text-[#101828]">
              {doneCount} / {LAB_SCENARIOS.length}
            </b>
          </p>
        </div>

        <div>
          <h1 className="text-xl font-bold text-[#101828]">공격 시뮬레이션</h1>
          <p className="text-xs text-[#667085] mt-1">
            시나리오별로 어떤 AWS 서비스가 탐지해야 하는지 미리 확인하는 모의
            화면입니다. 실제 트래픽은 보내지 않습니다.
          </p>
        </div>

        <p className="text-[12px] leading-relaxed text-[#B54708] bg-[#FFFAEB] ring-1 ring-[#FEDF89] rounded-xl px-4 py-3">
          실제 재현은 본인이 소유한 테스트 환경(wonny-sec)에서만 진행하세요. 운영
          중인 서비스나 다른 사람의 시스템에는 실행하지 마세요.
        </p>

        <div className="space-y-3">
          {LAB_SCENARIOS.map((s) => {
            const title = SCENARIO_CARDS.find((c) => c.id === s.id)?.title ?? s.id
            const state = runs[s.id]
            const running = !!state && !state.done
            return (
              <section
                key={s.id}
                className="bg-white rounded-2xl ring-1 ring-[#EAECF0] px-5 py-4"
              >
                <div className="flex items-start justify-between gap-4 flex-wrap">
                  <div>
                    <h2 className="text-[14px] font-bold text-[#101828]">
                      {title}
                    </h2>
                    <div className="flex flex-wrap gap-1 mt-1.5">
                      {s.tools.map((t) => (
                        <span
                          key={t}
                          className="text-[11px] font-mono bg-[#F2F4F7] text-[#475467] rounded px-1.5 py-0.5"
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                  <button
                    onClick={() => run(s.id, s.steps.length)}
                    disabled={running}
                    className="text-xs font-bold text-white bg-[#101828] hover:bg-[#1D2939] disabled:opacity-40 rounded-lg px-3.5 py-2 transition-colors"
                  >
                    {running ? "실행 중…" : state?.done ? "다시 실행" : "시뮬레이션 실행"}
                  </button>
                </div>

                <dl className="mt-3 grid gap-1 text-xs">
                  <div className="flex gap-3">
                    <dt className="w-16 flex-shrink-0 text-[#667085]">탐지</dt>
                    <dd className="font-semibold text-[#101828]">{s.detector}</dd>
                  </div>
                  <div className="flex gap-3">
                    <dt className="w-16 flex-shrink-0 text-[#667085]">기대 결과</dt>
                    <dd className="text-[#344054]">{s.signal}</dd>
                  </div>
                </dl>

                {state && (
                  <ol className="mt-3 space-y-1.5 border-t border-[#F2F4F7] pt-3">
                    {s.steps.map((text, i) => {
                      const reached = state.step > i
                      return (
                        <li
                          key={text}
                          className={`flex items-center gap-2 text-xs transition-colors ${
                            reached ? "text-[#101828]" : "text-[#98A2B3]"
                          }`}
                        >
                          <span
                            className={`w-4 h-4 rounded-full flex items-center justify-center text-[9px] font-bold flex-shrink-0 ${
                              reached
                                ? "bg-[#16A34A] text-white"
                                : "bg-[#F2F4F7] text-[#98A2B3]"
                            }`}
                          >
                            {reached ? "✓" : i + 1}
                          </span>
                          {text}
                        </li>
                      )
                    })}
                  </ol>
                )}

                <label className="mt-3 flex items-center gap-2 text-xs text-[#344054] cursor-pointer w-fit">
                  <input
                    type="checkbox"
                    checked={!!confirmed[s.id]}
                    onChange={() => toggleConfirmed(s.id)}
                  />
                  실제 환경에서 탐지 확인함
                </label>
              </section>
            )
          })}
        </div>
      </div>
    </div>
  )
}
