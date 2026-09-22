import type { ServiceMetric, ServiceStatus } from "../../data/types"

interface ServiceHealthStripProps {
  metrics: ServiceMetric[]
}

const STATUS_META: Record<ServiceStatus, { label: string; color: string }> = {
  healthy: { label: "정상", color: "#16A34A" },
  degraded: { label: "주의", color: "#F79009" },
  unhealthy: { label: "장애", color: "#D92D20" },
  unknown: { label: "확인 중", color: "#98A2B3" },
}

function pct(value: number | null, digits = 0) {
  return value === null ? "-" : `${value.toFixed(digits)}%`
}

/** 대시보드 하단: 보안 시나리오가 아니라 인프라 자체의 CPU/메모리/지연시간/처리량/에러율/상태. */
export function ServiceHealthStrip({ metrics }: ServiceHealthStripProps) {
  if (metrics.length === 0) return null

  return (
    <div className="grid grid-cols-5 gap-2 flex-shrink-0" style={{ height: 72 }}>
      {metrics.map((m) => {
        const meta = STATUS_META[m.status]
        const hasRequestMetrics = m.requestCount !== null

        return (
          <div
            key={m.server}
            className="bg-white rounded-lg ring-1 ring-[#EAECF0] px-3 py-1.5 flex flex-col justify-center gap-1"
          >
            <div className="flex items-center gap-1.5">
              <span
                className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                style={{ backgroundColor: meta.color }}
                aria-hidden
              />
              <p className="text-[11px] font-semibold text-[#101828] truncate">{m.displayName}</p>
              <span className="ml-auto text-[9px]" style={{ color: meta.color }}>
                {meta.label}
              </span>
            </div>

            <div className="flex items-center gap-2 text-[10px] text-[#667085]">
              <span>
                CPU <span className="text-[#101828] font-medium">{pct(m.cpuPercent)}</span>
              </span>
              <span>
                MEM <span className="text-[#101828] font-medium">{pct(m.memoryPercent)}</span>
              </span>
            </div>

            <p className="text-[9px] text-[#98A2B3] truncate">
              {hasRequestMetrics
                ? `지연 ${m.avgLatencyMs?.toFixed(0) ?? "-"}ms · 요청 ${m.requestCount}건 · 에러율 ${pct(m.errorRatePercent, 1)}`
                : "요청 지표 없음 (ALB 미연결)"}
            </p>
          </div>
        )
      })}
    </div>
  )
}
