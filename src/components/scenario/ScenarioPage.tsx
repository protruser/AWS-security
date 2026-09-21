import { useState } from "react"
import { SCENARIO_CARDS } from "../../data/mock"
import {
  SCENARIO_DETAILS,
  type ScenarioAction,
  type ScenarioDetail,
  type Tone,
} from "../../data/scenarios"
import { ApprovalModal, DonutGauge, SEV_COLOR, SeverityBadge } from "../shared/common"

const TONE: Record<Tone, { fg: string; bg: string; dot: string }> = {
  danger: { fg: "#B42318", bg: "#FEF3F2", dot: "#D92D20" },
  warn: { fg: "#B54708", bg: "#FFFAEB", dot: "#F79009" },
  ok: { fg: "#027A48", bg: "#ECFDF3", dot: "#16A34A" },
  neutral: { fg: "#475467", bg: "#F2F4F7", dot: "#98A2B3" },
}

function StatusPill({ tone, label }: { tone: Tone; label: string }) {
  const t = TONE[tone]
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-semibold"
      style={{ backgroundColor: t.bg, color: t.fg }}
    >
      <span
        className="w-1.5 h-1.5 rounded-full"
        style={{ backgroundColor: t.dot }}
      />
      {label}
    </span>
  )
}

function Panel({
  title,
  right,
  children,
}: {
  title: string
  right?: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <section className="bg-white rounded-2xl shadow-[0_1px_2px_rgba(16,24,40,0.06)] ring-1 ring-[#EAECF0]">
      <div className="flex items-center justify-between px-5 pt-4 pb-3">
        <h3 className="text-[13px] font-bold text-[#101828]">{title}</h3>
        {right}
      </div>
      <div className="px-5 pb-5">{children}</div>
    </section>
  )
}

export function ScenarioPage({
  id,
  doneActions,
  onExecute,
  onNavigate,
  onBack,
}: {
  id: string
  doneActions: Record<string, string>
  onExecute: (actionId: string) => void
  onNavigate: (id: string) => void
  onBack: () => void
}) {
  const d = SCENARIO_DETAILS[id]
  const [pending, setPending] = useState<ScenarioAction | null>(null)
  const [showLog, setShowLog] = useState(false)

  if (!d) return null

  const doneCount = d.actions.filter((a) => doneActions[a.id]).length
  const allDone = doneCount === d.actions.length
  const tone: Tone = allDone ? "ok" : d.tone
  const statusLabel = allDone ? "조치 완료" : d.statusLabel

  // 실행한 조치가 있으면 "현재 설정" 값을 조치 후 값으로 바꿔 보여준다.
  const policy = d.policy.map((p) => {
    const act = d.actions.find((a) => a.policyKey === p.key && doneActions[a.id])
    return { ...p, value: act?.policyAfter ?? p.value, changed: !!act }
  })

  return (
    <div className="flex-1 min-h-0 overflow-y-auto bg-[#F6F7F9]">
      <div className="mx-auto max-w-[1180px] px-6 py-5 space-y-4">
        {/* Top bar */}
        <div className="flex items-center gap-3 flex-wrap">
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
          <div className="flex gap-1 flex-wrap ml-auto">
            {SCENARIO_CARDS.map((c) => {
              const active = c.id === id
              return (
                <button
                  key={c.id}
                  onClick={() => onNavigate(c.id)}
                  className={`text-[11px] font-medium rounded-full px-2.5 py-1 transition-colors ${
                    active
                      ? "bg-[#101828] text-white"
                      : "bg-white text-[#475467] ring-1 ring-[#E4E7EC] hover:bg-[#F2F4F7]"
                  }`}
                >
                  {c.title}
                </button>
              )
            })}
          </div>
        </div>

        {/* Title */}
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <h1 className="text-xl font-bold text-[#101828]">{d.title}</h1>
              <SeverityBadge sev={d.severity} />
              <StatusPill tone={tone} label={statusLabel} />
            </div>
            <p className="text-xs text-[#667085] mt-1">{d.source}</p>
          </div>
          <div className="text-right">
            <p className="text-[11px] text-[#667085]">조치 진행</p>
            <p className="text-sm font-bold text-[#101828]">
              {doneCount} / {d.actions.length} 완료
            </p>
          </div>
        </div>

        <p className="text-[13px] leading-relaxed text-[#344054] bg-white ring-1 ring-[#EAECF0] rounded-xl px-4 py-3">
          {d.summary}
        </p>

        {/* KPI */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {d.kpis.map((k) => (
            <div
              key={k.label}
              className="bg-white rounded-xl ring-1 ring-[#EAECF0] px-4 py-3"
            >
              <p className="text-[11px] text-[#667085]">{k.label}</p>
              <p
                className="text-2xl font-bold mt-0.5 leading-tight"
                style={{ color: k.tone ? TONE[k.tone].dot : "#101828" }}
              >
                {k.value}
              </p>
              {k.sub && (
                <p className="text-[11px] text-[#98A2B3] mt-0.5">{k.sub}</p>
              )}
            </div>
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-5 gap-4 items-start">
          {/* Left: status */}
          <div className="lg:col-span-3 space-y-4">
            <Panel title="현재 상황">
              {d.gauge && (
                <div className="flex items-center gap-4 mb-4 pb-4 border-b border-[#F2F4F7]">
                  <DonutGauge
                    pct={d.gauge.pct}
                    color={TONE[d.tone].dot}
                    size={88}
                  />
                  <div>
                    <p className="text-2xl font-bold text-[#101828] leading-none">
                      {d.gauge.value}
                      <span className="text-sm font-normal text-[#667085]">
                        {" "}
                        / {d.gauge.max}
                      </span>
                    </p>
                    <p className="text-xs text-[#667085] mt-1.5">
                      {d.gauge.unit}
                    </p>
                  </div>
                </div>
              )}
              <dl className="divide-y divide-[#F2F4F7]">
                {policy.map((p) => (
                  <div
                    key={p.key}
                    className="flex items-center justify-between gap-4 py-2.5 text-xs"
                  >
                    <dt className="text-[#667085]">{p.label}</dt>
                    <dd
                      className={`font-semibold text-right ${
                        "text-[#101828]"
                      }`}
                    >
                      {p.changed && <span className="mr-1">✓</span>}
                      {p.value}
                    </dd>
                  </div>
                ))}
              </dl>
            </Panel>

            {d.cves ? <CveTable d={d} /> : <EventTable d={d} />}

            <Panel
              title="원본 로그"
              right={
                <button
                  onClick={() => setShowLog((v) => !v)}
                  className="text-[11px] font-medium text-[#475467] hover:text-[#101828]"
                >
                  {showLog ? "접기" : "펼치기"}
                </button>
              }
            >
              {showLog ? (
                <pre className="text-[11px] leading-relaxed font-mono bg-[#F9FAFB] rounded-lg p-3 overflow-x-auto text-[#344054]">
                  {d.logSample}
                </pre>
              ) : (
                <p className="text-xs text-[#98A2B3]">
                  펼치면 최근 탐지 건의 원본 로그를 볼 수 있습니다.
                </p>
              )}
            </Panel>
          </div>

          {/* Right: actions */}
          <div className="lg:col-span-2 space-y-4 lg:sticky lg:top-0">
            <Panel title="조치">
              <div className="space-y-2.5">
                {d.actions.map((a) => {
                  const doneAt = doneActions[a.id]
                  return (
                    <div
                      key={a.id}
                      className={`rounded-xl p-3.5 ring-1 ${
                        doneAt
                          ? "bg-[#F9FAFB] ring-[#D0D5DD]"
                          : "bg-white ring-[#E4E7EC]"
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <p className="text-[13px] font-bold text-[#101828] leading-snug">
                          {a.title}
                        </p>
                        <span
                          className="text-[10px] font-bold px-1.5 py-0.5 rounded-full text-white flex-shrink-0"
                          style={{ backgroundColor: SEV_COLOR[a.risk] }}
                        >
                          {a.risk}
                        </span>
                      </div>
                      <p className="text-xs text-[#667085] mt-1 leading-relaxed">
                        {a.desc}
                      </p>
                      <p className="text-[11px] text-[#98A2B3] mt-1.5">
                        대상 · {a.target}
                      </p>
                      <div className="mt-3">
                        {doneAt ? (
                          <p className="text-xs font-semibold text-[#344054]">
                            ✓ {doneAt} 실행 완료
                          </p>
                        ) : (
                          <button
                            onClick={() => setPending(a)}
                            className="w-full text-xs font-bold text-white bg-[#101828] hover:bg-[#1D2939] rounded-lg py-2 transition-colors"
                          >
                            조치 승인
                          </button>
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>
            </Panel>

            <Panel title="관련 자산">
              <div className="flex flex-wrap gap-1.5">
                {d.relatedAssets.map((a) => (
                  <span
                    key={a}
                    className="text-[11px] font-medium text-[#344054] bg-[#F2F4F7] rounded-md px-2 py-1"
                  >
                    {a}
                  </span>
                ))}
              </div>
            </Panel>
          </div>
        </div>
      </div>

      {pending && (
        <ApprovalModal
          ev={{
            severity: pending.risk,
            title: pending.title,
            asset: pending.target,
            service: d.source,
            recommendation: pending.desc,
            executor: pending.executor,
            rollback: pending.rollback,
          }}
          onClose={() => setPending(null)}
          onConfirm={() => {
            onExecute(pending.id)
            setPending(null)
          }}
        />
      )}
    </div>
  )
}

function EventTable({ d }: { d: ScenarioDetail }) {
  return (
    <Panel title="최근 이벤트">
      {d.events.length === 0 ? (
        <p className="text-xs text-[#98A2B3]">최근 이벤트가 없습니다.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="text-[11px] text-[#667085]">
                {d.eventColumns.map((c) => (
                  <th key={c} className="py-2 pr-3 font-medium">
                    {c}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {d.events.map((e, i) => (
                <tr key={i} className="border-t border-[#F2F4F7]">
                  {e.cells.map((c, j) => (
                    <td
                      key={j}
                      className={`py-2 pr-3 ${
                        j === 0 ? "font-mono text-[#667085]" : "text-[#101828]"
                      } ${j === 2 ? "font-mono text-[11px]" : ""}`}
                    >
                      {j === e.cells.length - 1 ? (
                        <StatusPill tone={e.tone ?? "neutral"} label={c} />
                      ) : (
                        c
                      )}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  )
}

function CveTable({ d }: { d: ScenarioDetail }) {
  const cves = d.cves ?? []
  const count = (s: string) => cves.filter((c) => c.sev === s).length
  return (
    <Panel title="발견된 취약점">
      <div className="flex rounded-full overflow-hidden h-2.5 bg-[#EAECF0] mb-4">
        {(["Critical", "High", "Medium"] as const).map((s) => (
          <div
            key={s}
            style={{
              width: `${(count(s) / cves.length) * 100}%`,
              backgroundColor: SEV_COLOR[s],
            }}
          />
        ))}
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="text-[11px] text-[#667085]">
              <th className="py-2 pr-3 font-medium">CVE</th>
              <th className="py-2 pr-3 font-medium">등급</th>
              <th className="py-2 pr-3 font-medium">패키지</th>
              <th className="py-2 pr-3 font-medium">설치 → 수정</th>
            </tr>
          </thead>
          <tbody>
            {cves.map((c) => (
              <tr key={c.id} className="border-t border-[#F2F4F7]">
                <td className="py-2 pr-3 font-mono text-[11px] text-[#101828]">
                  {c.id}
                </td>
                <td className="py-2 pr-3">
                  <SeverityBadge sev={c.sev} small />
                </td>
                <td className="py-2 pr-3 text-[#344054]">{c.pkg}</td>
                <td className="py-2 pr-3 font-mono text-[11px] text-[#667085]">
                  {c.installed} → {c.fixed}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  )
}
