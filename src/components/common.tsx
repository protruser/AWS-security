import { useState } from "react"
import type { Severity } from "../data/types"

export const SEV_COLOR: Record<Severity, string> = {
  Critical: "#D92D20",
  High: "#F79009",
  Medium: "#EAB308",
  Low: "#98A2B3",
  Info: "#98A2B3",
}

export function SeverityBadge({
  sev,
  small,
}: {
  sev: Severity
  small?: boolean
}) {
  return (
    <span
      className={`inline-flex items-center font-bold rounded-full text-white tracking-wide ${
        small ? "text-[9px] px-1.5 py-0.5" : "text-[11px] px-2 py-0.5"
      }`}
      style={{ backgroundColor: SEV_COLOR[sev] }}
    >
      {sev}
    </span>
  )
}

export function DonutGauge({
  pct,
  color,
  size = 64,
}: {
  pct: number
  color: string
  size?: number
}) {
  const R = 26,
    cx = 32,
    cy = 32,
    sw = 7
  const circ = 2 * Math.PI * R
  const dash = circ * Math.min(pct / 100, 1)

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      style={{ flexShrink: 0 }}
    >
      <circle
        cx={cx}
        cy={cy}
        r={R}
        fill="none"
        stroke="#E5E7EB"
        strokeWidth={sw}
      />
      <circle
        cx={cx}
        cy={cy}
        r={R}
        fill="none"
        stroke={color}
        strokeWidth={sw}
        strokeDasharray={`${dash} ${circ - dash}`}
        strokeDashoffset={circ * 0.25}
        strokeLinecap="round"
        style={{ transition: "stroke-dasharray 0.5s ease" }}
      />
      <text
        x={cx}
        y={cy + 1}
        textAnchor="middle"
        dominantBaseline="middle"
        fontSize="11"
        fontWeight="700"
        fill={color}
      >
        {pct}%
      </text>
    </svg>
  )
}

// ─── Approval Modal ───────────────────────────────────────────────────────────

export interface ApprovalRequest {
  severity: Severity
  title: string
  asset: string
  service: string
  recommendation: string
  executor?: string
  rollback?: string
}

export function ApprovalModal({
  ev,
  onClose,
  onConfirm,
  isExecuting = false,
  error,
  confirmLabel,
  title = "조치 승인 확인",
  description = "아래 내용을 검토 후 조치를 실행하세요.",
  agreementText = "위 내용을 확인했으며 서비스 영향을 인지하고 조치를 승인합니다.",
  executingLabel = "조치 실행 중...",
}: {
  ev: ApprovalRequest
  onClose: () => void
  onConfirm: () => void
  isExecuting?: boolean
  error?: string | null
  confirmLabel?: string
  title?: string
  description?: string
  agreementText?: string
  executingLabel?: string
}) {
  const [checked, setChecked] = useState(false)
  const isHighRisk = ev.severity === "Critical"

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div
        className="absolute inset-0 bg-black/40 backdrop-blur-[2px]"
        onClick={() => { if (!isExecuting) onClose() }}
      />
      <div className="relative bg-white rounded-2xl shadow-2xl w-full max-w-lg mx-4 fade-in">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#EEF0F3]">
          <div>
            <h3 className="text-sm font-bold text-[#0D0D0D]">{title}</h3>
            <p className="text-xs text-[#6B6B6B] mt-0.5">
              {description}
            </p>
          </div>
          <button
            onClick={onClose}
            className="text-[#6B6B6B] hover:text-[#0D0D0D] text-xl font-light"
            aria-label="닫기"
            disabled={isExecuting}
          >
            ✕
          </button>
        </div>
        <div className="px-6 py-4 space-y-3">
          <div className="flex items-center gap-2">
            <SeverityBadge sev={ev.severity} />
            <span className="text-xs font-bold text-[#0D0D0D]">{ev.title}</span>
          </div>

          {isHighRisk && (
            <div className="bg-[#D92D20] rounded-lg px-3 py-2.5">
              <p className="text-xs font-bold text-white">
                ⚠ 고위험 조치 — 서비스 영향 가능
              </p>
              <p className="text-xs text-white/85 mt-0.5">
                이 조치는 운영 중인 서비스에 영향을 줄 수 있습니다.
              </p>
            </div>
          )}

          {[
            ["조치 대상", ev.asset],
            ["탐지 서비스", ev.service],
            ["조치 내용", ev.recommendation],
            ["현재 설정", "변경 전 상태 (조치 승인 시 자동 조회)"],
            [
              "실행 방식",
              ev.executor ?? "Lambda Remediation → AWS Systems Manager",
            ],
            ["롤백 가능", ev.rollback ?? "예 — 30분 이내 자동 롤백 가능"],
          ].map(([k, v]) => (
            <div key={k} className="flex gap-3 text-xs">
              <span className="text-[#6B6B6B] w-24 flex-shrink-0 font-medium">
                {k}
              </span>
              <span className="text-[#0D0D0D]">{v}</span>
            </div>
          ))}

          {isHighRisk && (
            <label className="flex items-start gap-2 cursor-pointer mt-1">
              <input
                type="checkbox"
                checked={checked}
                onChange={(e) => setChecked(e.target.checked)}
                className="mt-0.5"
              />
              <span className="text-xs text-[#0D0D0D]">
                {agreementText}
              </span>
            </label>
          )}
        </div>
        {error && <p role="alert" className="px-6 pb-3 text-xs text-[#D92D20]">{error}</p>}
        <div className="flex gap-3 px-6 py-4 border-t border-[#EEF0F3]">
          <button
            onClick={onClose}
            disabled={isExecuting}
            className="flex-1 text-sm font-medium text-[#6B6B6B] border border-[#E0E0E0] hover:bg-[#FAFAFA] px-4 py-2 rounded-lg transition-colors"
          >
            취소
          </button>
          <button
            onClick={onConfirm}
            disabled={isExecuting || (isHighRisk && !checked)}
            className="flex-1 text-sm font-semibold text-white px-4 py-2 rounded-lg transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            style={{
              backgroundColor: isHighRisk && !checked ? "#A3A3A3" : "#111111",
            }}
          >
            {isExecuting ? executingLabel : confirmLabel ?? "조치 실행"}
          </button>
        </div>
      </div>
    </div>
  )
}
