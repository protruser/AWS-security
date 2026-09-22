import { useEffect, useRef, useState } from "react"
import type { AssetStatus } from "../data/types"
import { ASSETS } from "../data/architecture"
import { CANVAS, ZONES, LEGEND, type Zone } from "../data/architectureLayout"
import { AssetCard } from "./AssetCard"
import { Connections } from "./Connections"

interface MapProps {
  assetStatuses: Record<string, AssetStatus>
  highlightedAssets: string[]
  attackPathAssets: string[]
  connectionAssetGroups: string[][]
  alerts: Record<string, { level: "critical" | "warning"; reason: string }>
  onAssetClick: (assetId: string) => void
  onBackgroundClick: () => void
  hasScenario: boolean
}

function ZoneLabel({ z }: { z: Zone }) {
  const at = z.labelAt ?? "top-left"
  const pos: React.CSSProperties =
    at === "top-right"
      ? { right: 10, top: 6 }
      : at === "bottom-left"
        ? { left: 10, bottom: 5 }
        : { left: 10, top: 6 }
  return (
    <div
      className="absolute flex items-center gap-1.5 whitespace-nowrap"
      style={pos}
    >
      <strong className="text-[12px] font-bold" style={{ color: z.ink }}>
        {z.label}
      </strong>
      {z.badges?.map((b) => (
        <span
          key={b}
          className="rounded-full bg-white px-1.5 py-px text-[10px] font-medium"
          style={{ color: z.ink, border: `1px solid ${z.border}` }}
        >
          {b}
        </span>
      ))}
    </div>
  )
}

export function ArchitectureMap({
  assetStatuses,
  highlightedAssets,
  attackPathAssets,
  connectionAssetGroups,
  alerts,
  onAssetClick,
  onBackgroundClick,
  hasScenario,
}: MapProps) {
  const outerRef = useRef<HTMLDivElement>(null)
  // 처음엔 알 수 없음(null)으로 두고, 실제 크기를 잰 뒤에만 그린다.
  // 1로 시작했다가 실측값으로 바뀌면 새로고침할 때마다 "줌"되는 것처럼 보였다.
  const [scale, setScale] = useState<number | null>(null)
  useEffect(() => {
    const el = outerRef.current
    if (!el) return
    const observer = new ResizeObserver(([entry]) => {
      const { width, height } = entry.contentRect
      // 작은 창에서는 더 줄이지 않고 지도 안에서 스크롤한다.
      setScale(
        Math.max(
          0.6,
          Math.min(
            (width - 16) / CANVAS.width,
            (height - 16) / CANVAS.height,
            1.35,
          ),
        ),
      )
    })
    observer.observe(el)
    return () => observer.disconnect()
  }, [])

  return (
    <div
      ref={outerRef}
      className="architecture-viewport w-full h-full rounded-2xl ring-1 ring-[#E4E7EC] bg-white flex items-center justify-center"
      aria-label="AWS 아키텍처"
      onClick={onBackgroundClick}
    >
      {scale === null ? null : (
      <div
        style={{
          width: CANVAS.width * scale,
          height: CANVAS.height * scale,
          flexShrink: 0,
        }}
      >
        <div
          className="architecture-canvas"
          style={{
            width: CANVAS.width,
            height: CANVAS.height,
            transform: `scale(${scale})`,
          }}
        >
          <div className="architecture-subnets">
            {ZONES.map((z) => (
              <div
                key={z.id}
                data-zone={z.id}
                className="absolute rounded-xl"
                style={{
                  left: z.x,
                  top: z.y,
                  width: z.w,
                  height: z.h,
                  backgroundColor: z.fill,
                  border: `${z.dashed ? 1.5 : 1}px ${z.dashed ? "dashed" : "solid"} ${z.border}`,
                }}
              />
            ))}
          </div>
          <Connections
            highlightedAssets={highlightedAssets}
            highlightedAssetGroups={connectionAssetGroups}
            hasScenario={hasScenario}
          />
          {ZONES.map((z) => (
            <div
              key={z.id}
              className="absolute"
              style={{
                left: z.x,
                top: z.y,
                width: z.w,
                height: z.h,
                zIndex: 2,
                pointerEvents: "none",
              }}
            >
              <ZoneLabel z={z} />
            </div>
          ))}

          <div
            className="absolute rounded-lg border border-[#E4E7EC] bg-white px-2 py-2"
            style={{ left: 4, top: 300, width: 78, zIndex: 3 }}
          >
            {LEGEND.map((l) => (
              <div
                key={l.kind}
                className="flex items-center gap-1 py-0.5 text-[10px] text-[#667085]"
              >
                <span
                  style={{
                    width: 14,
                    borderTop: `2px ${l.kind === "attack" ? "dashed" : "solid"} ${l.color}`,
                  }}
                />
                {l.label}
              </div>
            ))}
            <div className="mt-1 flex items-center gap-1 border-t border-[#F2F4F7] pt-1.5 text-[10px] font-semibold text-[#B42318]">
              <span className="inline-block h-2 w-2 rounded-full bg-[#D92D20]" />
              비상
            </div>
          </div>

          {ASSETS.map((asset) => (
            <AssetCard
              key={asset.id}
              asset={asset}
              status={assetStatuses[asset.id] || asset.defaultStatus}
              isHighlighted={highlightedAssets.includes(asset.id)}
              isAttackPath={attackPathAssets.includes(asset.id)}
              alert={alerts[asset.id]}
              onClick={() => onAssetClick(asset.id)}
              isMuted={hasScenario && !highlightedAssets.includes(asset.id)}
            />
          ))}
        </div>
      </div>
      )}
    </div>
  )
}
