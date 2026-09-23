import { useEffect, useRef, useState } from "react"

type DiagnosisStatus = "PASS" | "FAIL" | "REVIEW" | "N/A"
type RunState = "idle" | "collecting" | "diagnosing" | "done" | "error"

interface DiagnosisEvidence {
  resource: string
  path: string
  value: string
}

interface DiagnosisResult {
  rule_id: string
  status: DiagnosisStatus
  severity: string
  resource_ids: string[]
  current_value: string
  expected_value: string
  evidence: DiagnosisEvidence[]
  reason: string
  recommendation: string
}

interface CollectionError {
  source: string
  error_code: string
  message: string
  resource?: string
}

interface DiagnosisReport {
  standard: string
  model: string
  summary: { total: number; pass: number; fail: number; review: number; na: number }
  consultant_comment?: string
  results: DiagnosisResult[]
  collection_errors: CollectionError[]
  collected_at: string | null
  region: string | null
}

interface RunStatusResponse {
  id?: number
  status: RunState
  message: string | null
  requestedBy?: string | null
  result: DiagnosisReport | null
  error: string | null
  startedAt?: string | null
  finishedAt?: string | null
}

// AI 응답에는 rule_id/status만 오고 한글 규칙명·카테고리는 안 오기 때문에,
// rules/shieldus_aws_33_rules.json 과 동일한 내용을 화면 표시용으로만 들고 있는다.
const RULE_META: Record<string, { name: string; category: string }> = {
  "1.1": { name: "사용자 계정 관리", category: "계정 관리" },
  "1.2": { name: "IAM 사용자 계정 장기간 비활성화 관리", category: "계정 관리" },
  "1.3": { name: "IAM 사용자 계정 식별 관리", category: "계정 관리" },
  "1.4": { name: "IAM 그룹 사용자 계정 관리", category: "계정 관리" },
  "1.5": { name: "Key Pair 접근 관리", category: "계정 관리" },
  "1.6": { name: "Admin Console 관리자 정책 관리", category: "계정 관리" },
  "1.7": { name: "Admin Console 계정 Access Key 활성화 및 사용주기 관리", category: "계정 관리" },
  "1.8": { name: "MFA (Multi-Factor Authentication) 설정", category: "계정 관리" },
  "1.9": { name: "AWS 계정 패스워드 정책 관리", category: "계정 관리" },
  "2.1": { name: "인스턴스 서비스 정책 관리", category: "권한 관리" },
  "2.2": { name: "네트워크 서비스 정책 관리", category: "권한 관리" },
  "2.3": { name: "기타 서비스 정책 관리", category: "권한 관리" },
  "3.1": { name: "보안 그룹 인/아웃바운드 PORT ANY 설정 관리", category: "가상 리소스 관리" },
  "3.2": { name: "보안 그룹 인/아웃바운드 불필요 정책 관리", category: "가상 리소스 관리" },
  "3.3": { name: "네트워크 ACL 인/아웃바운드 트래픽 정책 관리", category: "가상 리소스 관리" },
  "3.4": { name: "라우팅 테이블 정책 관리", category: "가상 리소스 관리" },
  "3.5": { name: "인터넷 게이트웨이 연결 관리", category: "가상 리소스 관리" },
  "3.6": { name: "NAT 게이트웨이 연결 관리", category: "가상 리소스 관리" },
  "3.7": { name: "S3 버킷/객체 접근 관리", category: "가상 리소스 관리" },
  "3.8": { name: "RDS 서브넷 가용 영역 관리", category: "가상 리소스 관리" },
  "3.9": { name: "ELB(Elastic Load Balancing) 연결 관리", category: "가상 리소스 관리" },
  "4.1": { name: "EBS 및 볼륨 암호화 설정", category: "운영 관리" },
  "4.2": { name: "RDS 암호화 설정", category: "운영 관리" },
  "4.3": { name: "S3 암호화 설정", category: "운영 관리" },
  "4.4": { name: "통신구간 암호화 설정", category: "운영 관리" },
  "4.5": { name: "CloudTrail 암호화 설정", category: "운영 관리" },
  "4.6": { name: "AWS 사용자 계정 로깅 설정", category: "운영 관리" },
  "4.7": { name: "인스턴스 로깅 설정", category: "운영 관리" },
  "4.8": { name: "RDS 로깅 설정", category: "운영 관리" },
  "4.9": { name: "S3 버킷 로깅 설정", category: "운영 관리" },
  "4.10": { name: "VPC 플로우 로깅 설정", category: "운영 관리" },
  "4.11": { name: "로그 보관 기간 설정", category: "운영 관리" },
  "4.12": { name: "백업 사용 여부", category: "운영 관리" },
}

const CATEGORY_ORDER = ["계정 관리", "권한 관리", "가상 리소스 관리", "운영 관리"]

const STATUS_STYLE: Record<DiagnosisStatus, string> = {
  PASS: "bg-[#ECFDF3] text-[#067647] ring-1 ring-[#ABEFC6]",
  FAIL: "bg-[#FEF3F2] text-[#B42318] ring-1 ring-[#FECDCA]",
  REVIEW: "bg-[#FFFAEB] text-[#B54708] ring-1 ring-[#FEDF89]",
  "N/A": "bg-[#F2F4F7] text-[#667085] ring-1 ring-[#EAECF0]",
}

const SEVERITY_STYLE: Record<string, string> = {
  상: "bg-[#FEF3F2] text-[#B42318]",
  중: "bg-[#FFFAEB] text-[#B54708]",
  하: "bg-[#EFF8FF] text-[#175CD3]",
}

function ResultCard({ result }: { result: DiagnosisResult }) {
  const [open, setOpen] = useState(false)
  const meta = RULE_META[result.rule_id]

  return (
    <div className="rounded-xl border border-[#EAECF0] bg-white p-3">
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-start justify-between gap-3 text-left"
      >
        <div>
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[10px] font-mono text-[#98A2B3]">
              {result.rule_id}
            </span>
            <p className="text-[12px] font-bold text-[#101828]">
              {meta?.name ?? result.rule_id}
            </p>
          </div>
          <p className="text-[11px] text-[#667085] mt-1">{result.reason}</p>
        </div>
        <div className="flex items-center gap-1.5 flex-shrink-0">
          <span
            className={`text-[9px] font-bold px-1.5 py-0.5 rounded-full ${
              SEVERITY_STYLE[result.severity] ?? "bg-[#F2F4F7] text-[#667085]"
            }`}
          >
            {result.severity}
          </span>
          <span
            className={`text-[9px] font-bold px-2 py-0.5 rounded-full ${STATUS_STYLE[result.status]}`}
          >
            {result.status}
          </span>
        </div>
      </button>

      {open && (
        <div className="mt-3 pt-3 border-t border-[#F2F4F7] space-y-2 text-[11px]">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <div>
              <p className="text-[#98A2B3] font-semibold">현재 상태</p>
              <p className="text-[#344054] mt-0.5">{result.current_value || "-"}</p>
            </div>
            <div>
              <p className="text-[#98A2B3] font-semibold">기대 상태</p>
              <p className="text-[#344054] mt-0.5">{result.expected_value || "-"}</p>
            </div>
          </div>

          {result.resource_ids.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {result.resource_ids.map((id) => (
                <span
                  key={id}
                  className="text-[10px] font-mono bg-[#F2F4F7] text-[#475467] rounded px-1.5 py-0.5"
                >
                  {id}
                </span>
              ))}
            </div>
          )}

          {result.recommendation && (
            <div>
              <p className="text-[#98A2B3] font-semibold">권장 조치</p>
              <p className="text-[#344054] mt-0.5">{result.recommendation}</p>
            </div>
          )}

          {result.evidence.length > 0 && (
            <div>
              <p className="text-[#98A2B3] font-semibold mb-1">근거</p>
              <div className="space-y-1">
                {result.evidence.map((ev, i) => (
                  <div
                    key={i}
                    className="bg-[#FAFAFA] rounded-lg px-2 py-1.5 font-mono text-[10px] text-[#475467]"
                  >
                    <span className="text-[#101828] font-semibold">{ev.resource}</span>
                    {" · "}
                    {ev.path} = {ev.value}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export function AIDiagnosisPage({
  onUnauthorized,
}: {
  onUnauthorized: () => void
}) {
  const [status, setStatus] = useState<RunStatusResponse | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [statusFilter, setStatusFilter] = useState<"전체" | DiagnosisStatus>("전체")
  const pollRef = useRef<number | null>(null)

  const fetchStatus = async () => {
    try {
      const response = await fetch("/api/ai-diagnosis/status", {
        credentials: "include",
      })
      if (response.status === 401) {
        onUnauthorized()
        return
      }
      if (!response.ok) {
        setLoadError("진단 상태를 불러오지 못했습니다.")
        return
      }
      const data = (await response.json()) as RunStatusResponse
      setLoadError(null)
      setStatus(data)
      return data
    } catch {
      setLoadError("진단 상태를 불러오지 못했습니다.")
    }
  }

  useEffect(() => {
    void fetchStatus()
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current)
    }
  }, [])

  useEffect(() => {
    const running = status?.status === "collecting" || status?.status === "diagnosing"
    if (running && pollRef.current === null) {
      pollRef.current = window.setInterval(() => {
        void fetchStatus()
      }, 4000)
    }
    if (!running && pollRef.current !== null) {
      window.clearInterval(pollRef.current)
      pollRef.current = null
    }
  }, [status?.status])

  const runDiagnosis = async () => {
    setLoadError(null)
    try {
      const response = await fetch("/api/ai-diagnosis/run", {
        method: "POST",
        credentials: "include",
      })
      if (response.status === 401) {
        onUnauthorized()
        return
      }
      if (response.status === 409) {
        void fetchStatus()
        return
      }
      if (!response.ok) {
        setLoadError("진단 실행 요청이 실패했습니다.")
        return
      }
      void fetchStatus()
    } catch {
      setLoadError("진단 실행 요청이 실패했습니다.")
    }
  }

  const running = status?.status === "collecting" || status?.status === "diagnosing"
  const report = status?.status === "done" ? status.result : null

  const grouped = CATEGORY_ORDER.map((category) => ({
    category,
    results: (report?.results ?? []).filter(
      (r) => RULE_META[r.rule_id]?.category === category,
    ),
  })).filter((g) => g.results.length > 0)

  return (
    <div className="min-h-full p-4 space-y-3">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <p className="text-[18px] font-bold text-[#101828]">AI 진단</p>
          <p className="text-[11px] text-[#667085] mt-0.5">
            SK쉴더스 CSPM(DataDog) AWS 보안 가이드 기반 33개 항목으로 현재 AWS
            계정/리소스 구성을 점검합니다. 설정을 변경하거나 조치를 실행하지는
            않습니다.
          </p>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          {status?.status === "done" && (
            <a
              href="/api/ai-diagnosis/report.xlsx"
              className="text-xs font-bold text-[#344054] bg-white hover:bg-[#F9FAFB] ring-1 ring-[#D0D5DD] rounded-lg px-4 py-2.5 transition-colors inline-flex items-center gap-1.5"
            >
              <svg
                viewBox="0 0 24 24"
                width="14"
                height="14"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.8"
              >
                <path d="M12 3v12m0 0l-4-4m4 4l4-4M4 21h16" />
              </svg>
              보고서 다운로드
            </a>
          )}
          <button
            onClick={runDiagnosis}
            disabled={running}
            className="text-xs font-bold text-white bg-[#101828] hover:bg-[#1D2939] disabled:opacity-40 rounded-lg px-4 py-2.5 transition-colors"
          >
            {running ? "진단 실행 중…" : "진단 실행"}
          </button>
        </div>
      </div>

      {loadError && (
        <p className="text-[11px] text-[#B42318] bg-[#FEF3F2] ring-1 ring-[#FECDCA] rounded-lg px-3 py-2">
          {loadError}
        </p>
      )}

      {running && (
        <div className="rounded-xl border border-[#EAECF0] bg-white p-4 flex items-center gap-3">
          <span className="w-4 h-4 rounded-full border-2 border-[#D0D5DD] border-t-[#101828] animate-spin" />
          <p className="text-[12px] text-[#344054]">
            {status?.message ?? "진단을 진행하는 중입니다..."}
          </p>
        </div>
      )}

      {status?.status === "error" && (
        <p className="text-[12px] text-[#B42318] bg-[#FEF3F2] ring-1 ring-[#FECDCA] rounded-xl px-3 py-2.5">
          진단 실패: {status.error}
        </p>
      )}

      {!status || status.status === "idle" ? (
        !running && (
          <div className="flex flex-col items-center justify-center h-32 text-[#98A2B3]">
            <p className="text-xs font-medium">아직 실행한 진단이 없습니다.</p>
          </div>
        )
      ) : null}

      {report && (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
            {[
              ["전체", report.summary.total, "#101828"],
              ["PASS", report.summary.pass, "#067647"],
              ["FAIL", report.summary.fail, "#B42318"],
              ["REVIEW", report.summary.review, "#B54708"],
              ["N/A", report.summary.na, "#667085"],
            ].map(([label, count, color]) => (
              <div
                key={label as string}
                className="rounded-xl border border-[#EAECF0] bg-white p-3"
              >
                <p className="text-[10px] font-semibold text-[#667085]">{label}</p>
                <p
                  className="text-lg font-bold mt-0.5"
                  style={{ color: color as string }}
                >
                  {count}
                </p>
              </div>
            ))}
          </div>

          <p className="text-[10px] text-[#98A2B3]">
            {report.standard} · {status?.finishedAt ?? ""} 완료
            {report.region ? ` · ${report.region}` : ""}
          </p>

          {report.consultant_comment && (
            <div className="rounded-xl border border-[#EAECF0] bg-white p-3.5">
              <p className="text-[11px] font-bold text-[#101828] mb-1.5">
                AI 종합 소견
              </p>
              <p className="text-[12px] text-[#344054] leading-relaxed whitespace-pre-line">
                {report.consultant_comment}
              </p>
            </div>
          )}

          {report.collection_errors.length > 0 && (
            <details className="rounded-xl border border-[#FEDF89] bg-[#FFFAEB] px-3 py-2">
              <summary className="text-[11px] font-semibold text-[#B54708] cursor-pointer">
                일부 AWS 정보를 읽지 못했습니다 ({report.collection_errors.length}건) — 해당 항목은 REVIEW로 표시될 수 있습니다
              </summary>
              <div className="mt-2 space-y-1">
                {report.collection_errors.map((err, i) => (
                  <p key={i} className="text-[10px] font-mono text-[#B54708]">
                    {err.source}: {err.error_code} {err.message}
                  </p>
                ))}
              </div>
            </details>
          )}

          <div className="inline-flex rounded-xl border border-[#D0D5DD] bg-white p-1 flex-wrap">
            {(["전체", "FAIL", "REVIEW", "PASS", "N/A"] as const).map((value) => (
              <button
                key={value}
                onClick={() => setStatusFilter(value)}
                className={`text-[11px] font-semibold px-3 py-1.5 rounded-lg transition-colors ${
                  statusFilter === value
                    ? "bg-[#101828] text-white shadow-sm"
                    : "text-[#475467] hover:bg-[#F2F4F7]"
                }`}
              >
                {value}
              </button>
            ))}
          </div>

          <div className="space-y-4">
            {grouped.map(({ category, results }) => {
              const filtered =
                statusFilter === "전체"
                  ? results
                  : results.filter((r) => r.status === statusFilter)
              if (filtered.length === 0) return null
              return (
                <div key={category}>
                  <p className="text-[12px] font-bold text-[#101828] mb-2">
                    {category}
                    <span className="text-[#98A2B3] font-normal ml-1.5">
                      {filtered.length}건
                    </span>
                  </p>
                  <div className="space-y-2">
                    {filtered.map((result) => (
                      <ResultCard key={result.rule_id} result={result} />
                    ))}
                  </div>
                </div>
              )
            })}
          </div>
        </>
      )}
    </div>
  )
}
