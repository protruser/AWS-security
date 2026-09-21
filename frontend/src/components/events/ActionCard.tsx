import type { ActionEvent } from "../../data/types"
import { SeverityBadge } from "../shared/common"

export function ActionCard({
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
