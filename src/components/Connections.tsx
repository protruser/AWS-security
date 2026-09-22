import { useId } from "react"
import { CANVAS, CONNECTIONS } from "../data/architectureLayout"

const MARKER_COLORS = ["#2F6FEB", "#98A2B3", "#101828", "#D92D20"]

export function Connections({
  highlightedAssets,
  highlightedAssetGroups,
  hasScenario,
}: {
  highlightedAssets: string[]
  highlightedAssetGroups: string[][]
  hasScenario: boolean
}) {
  const markerPrefix = useId().replace(/:/g, "")
  // 인프라 하나만 눌렀을 때는 그 자산에 닿은 선을, 시나리오를 골랐을 때는
  // 양쪽 끝이 모두 강조된 선만 켠다.
  const isLit = (assets: [string, string]) =>
    highlightedAssets.length === 1
      ? assets.some((id) => highlightedAssets.includes(id))
      : highlightedAssetGroups.some((group) =>
          assets.every((id) => group.includes(id)),
        )

  return (
    <svg
      aria-label="리소스 연결 흐름"
      className="architecture-connections"
      width={CANVAS.width}
      height={CANVAS.height}
    >
      <defs>
        {MARKER_COLORS.map((color, i) => (
          <marker
            key={color}
            id={`${markerPrefix}-${i}`}
            markerWidth="7"
            markerHeight="7"
            refX="6"
            refY="3.5"
            orient="auto"
            markerUnits="userSpaceOnUse"
          >
            <path d="M0,0 L0,7 L7,3.5 z" fill={color} />
          </marker>
        ))}
      </defs>
      {CONNECTIONS.map((c) => {
        const lit = !hasScenario || isLit(c.assets)
        const stroke =
          hasScenario && lit && c.kind !== "attack" ? "#101828" : c.color
        const d = c.points
          .map((p, i) => `${i ? "L" : "M"}${p.x},${p.y}`)
          .join(" ")
        return (
          <g
            key={c.id}
            opacity={!hasScenario ? 0.75 : lit ? 1 : 0.1}
            style={{ transition: "opacity 0.2s" }}
          >
            <title>{c.assets.join(" → ")}</title>
            {/* 흰 테두리로 교차하는 선을 분리한다. */}
            <path d={d} stroke="white" strokeWidth="5" fill="none" />
            <path
              data-connection-id={c.id}
              d={d}
              stroke={stroke}
              strokeWidth={hasScenario && lit ? 2.4 : 1.8}
              strokeDasharray={c.kind === "attack" ? "6 4" : undefined}
              fill="none"
              strokeLinejoin="round"
              markerEnd={`url(#${markerPrefix}-${MARKER_COLORS.indexOf(stroke)})`}
            />
          </g>
        )
      })}
      {CONNECTIONS.filter(
        (c) =>
          c.label &&
          c.labelPos &&
          (!hasScenario || isLit(c.assets)),
      ).map((c) => {
        const pos = c.labelPos!
        const width = c.label!.length * 7 + 14
        return (
          <g
            key={`${c.id}-label`}
            data-connection-label={c.id}
            transform={`translate(${pos.x},${pos.y})`}
          >
            <rect
              x={-width / 2}
              y={-10}
              width={width}
              height="20"
              rx="5"
              fill="white"
              stroke="#E4E7EC"
            />
            <text
              textAnchor="middle"
              dominantBaseline="central"
              fontSize="10.5"
              fontWeight="600"
              fill="#475467"
            >
              {c.label}
            </text>
          </g>
        )
      })}
    </svg>
  )
}
