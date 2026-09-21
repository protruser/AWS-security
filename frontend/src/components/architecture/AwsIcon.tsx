import type { IconName } from "../../data/architecture"
import igw from "../../assets/aws-icons/igw.svg"
import waf from "../../assets/aws-icons/waf.svg"
import alb from "../../assets/aws-icons/alb.svg"
import nat from "../../assets/aws-icons/nat.svg"
import ec2 from "../../assets/aws-icons/ec2.svg"
import db from "../../assets/aws-icons/db.svg"
import ecr from "../../assets/aws-icons/ecr.svg"
import secrets from "../../assets/aws-icons/secrets.svg"
import kms from "../../assets/aws-icons/kms.svg"
import cwlogs from "../../assets/aws-icons/cwlogs.svg"
import flowlogs from "../../assets/aws-icons/flowlogs.svg"
import cloudtrail from "../../assets/aws-icons/cloudtrail.svg"
import bucket from "../../assets/aws-icons/bucket.svg"
import guardduty from "../../assets/aws-icons/guardduty.svg"
import inspector from "../../assets/aws-icons/inspector.svg"
import analyzer from "../../assets/aws-icons/analyzer.svg"
import securityhub from "../../assets/aws-icons/securityhub.svg"
import eventbridge from "../../assets/aws-icons/eventbridge.svg"
import sns from "../../assets/aws-icons/sns.svg"

const CATEGORY = {
  actor: "#667085",
  attacker: "#B42318",
} as const

type Glyph = { color: string; paths: string[]; dots?: [number, number, number][] }

// AWS 서비스가 아닌 두 개(공격자, 일반 사용자)만 직접 그린다.
const CUSTOM: Partial<Record<IconName, Glyph>> = {
  attacker: {
    color: CATEGORY.attacker,
    paths: [
      "M12 3a7 7 0 00-4 12.7V19h8v-3.7A7 7 0 0012 3z",
      "M10 19v2M12 19v2M14 19v2",
    ],
    dots: [
      [9.5, 11, 1.2],
      [14.5, 11, 1.2],
    ],
  },
  user: {
    color: CATEGORY.actor,
    paths: ["M5 20c0-4 3.5-6 7-6s7 2 7 6"],
    dots: [[12, 8, 3.5]],
  },
}

const TILELESS = new Set<IconName>(["igw", "nat", "flowlogs", "analyzer", "db"])

// 나머지는 AWS 공식 아이콘(Asset-Package_07312025)을 그대로 쓴다.
const OFFICIAL: Partial<Record<IconName, string>> = {
  igw,
  waf,
  alb,
  nat,
  ec2,
  k3s: ec2,
  app: ec2,
  db,
  ecr,
  secrets,
  kms,
  cwlogs,
  flowlogs,
  cloudtrail,
  bucket,
  guardduty,
  inspector,
  analyzer,
  securityhub,
  eventbridge,
  sns,
}

export function AwsIcon({ name, size }: { name: IconName; size: number }) {
  const url = OFFICIAL[name]
  if (url) {
    // 리소스 아이콘은 색 타일이 없는 선 아이콘이라 흰 타일에 얹어 서비스 아이콘과 맞춘다.
    if (TILELESS.has(name)) {
      const pad = Math.round(size * 0.1)
      return (
        <div
          className="bg-white"
          style={{
            width: size,
            height: size,
            padding: pad,
            borderRadius: 8,
            border: "1px solid #D0D5DD",
          }}
        >
          <img
            src={url}
            width={size - pad * 2 - 2}
            height={size - pad * 2 - 2}
            alt=""
            draggable={false}
            style={{ display: "block" }}
          />
        </div>
      )
    }
    return (
      <img
        src={url}
        width={size}
        height={size}
        alt=""
        draggable={false}
        style={{ display: "block" }}
      />
    )
  }

  const g = CUSTOM[name]!
  return (
    <svg
      viewBox="0 0 48 48"
      width={size}
      height={size}
      role="img"
      aria-hidden="true"
      style={{ display: "block" }}
    >
      <rect width="48" height="48" rx="7" fill={g.color} />
      <g
        transform="translate(9 9) scale(1.25)"
        fill="none"
        stroke="white"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        {g.paths.map((d, i) => (
          <path key={i} d={d} />
        ))}
        {g.dots?.map(([cx, cy, r], i) => (
          <circle key={i} cx={cx} cy={cy} r={r} fill="white" stroke="none" />
        ))}
      </g>
    </svg>
  )
}
