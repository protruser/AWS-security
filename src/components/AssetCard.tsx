import type { AssetStatus } from "../data/types"
import { ICON, scenariosForAsset, type AssetDef } from "../data/architecture"
import { AwsIcon } from "./AwsIcon"

const STATUS_RING: Record<AssetStatus, string> = {
  normal: "transparent",
  warning: "#F79009",
  danger: "#E8541A",
  critical: "#D92D20",
  acting: "#1677FF",
  disconnected: "#A3A3A3",
}

const NODE_WIDTH = 120

export function AssetCard({
  asset,
  status,
  isHighlighted,
  isAttackPath,
  onClick,
  isMuted,
  alert,
}: {
  asset: AssetDef

  status: AssetStatus

  isHighlighted: boolean

  isAttackPath: boolean

  onClick: () => void

  isMuted: boolean

  alert?: { level: "critical" | "warning"; reason: string }
}) {
  // 7개 시나리오와 관련된 자산만 클릭할 수 있다.
  const interactive = scenariosForAsset(asset.id).length > 0

  const ring = isAttackPath
    ? "#D92D20"
    : isHighlighted
      ? "#101828"
      : STATUS_RING[status]

  return (
    <div
      data-asset-id={asset.id}
      role={interactive ? "button" : undefined}
      tabIndex={interactive ? 0 : undefined}
      aria-label={asset.detail ? `${asset.label}: ${asset.detail}` : asset.label}
      title={asset.detail}
      onKeyDown={(e) => {
        if (!interactive) return
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault()
          onClick()
        }
      }}
      onClick={
        interactive
          ? (e) => {
              e.stopPropagation()
              onClick()
            }
          : undefined
      }
      className={`absolute flex flex-col items-center transition-opacity ${
        interactive ? "cursor-pointer" : "cursor-default"
      }`}
      style={{
        left: asset.x + ICON / 2 - NODE_WIDTH / 2,
        top: asset.y,
        width: NODE_WIDTH,
        opacity: isMuted ? 0.25 : 1,
        zIndex: 3,
      }}
    >
      <div className="relative">
        <div
          className={`rounded-lg transition-shadow ${
            alert ? `alert-card-${alert.level}` : ""
          }`}
          style={{
            boxShadow:
              ring !== "transparent" && !alert
                ? `0 0 0 3px white, 0 0 0 5px ${ring}`
                : undefined,
          }}
        >
          <AwsIcon name={asset.icon} size={ICON} />
        </div>
        {alert && (
          <span
            title={alert.reason}
            aria-label={`${alert.level === "critical" ? "비상" : "주의"}: ${alert.reason}`}
            className={`absolute -top-1.5 -right-1.5 z-30 w-4 h-4 rounded-full border-2 border-white ${
              alert.level === "critical"
                ? "bg-[#D92D20] alert-dot-critical"
                : "bg-[#F79009] alert-dot-warning"
            }`}
          />
        )}
      </div>
      <div className="mt-1 rounded bg-white/90 px-1 text-center leading-tight">
        <p className="text-[12px] font-semibold text-[#101828] whitespace-nowrap">
          {asset.label}
        </p>
        {asset.sub && (
          <p className="text-[10.5px] text-[#667085] whitespace-nowrap">
            {asset.sub}
          </p>
        )}
      </div>
    </div>
  )
}
