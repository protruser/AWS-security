import { useEffect, useMemo, useRef, useState } from "react"

// GitHub snapshot → integrated proposal → human approvals → verified deployment.

interface DiagnosisEvidence {
  resource: string
  path: string
  value: string
}

interface DiagnosisResult {
  rule_id: string
  status: "PASS" | "FAIL" | "REVIEW" | "N/A"
  severity: string
  resource_ids?: string[]
  current_value?: string
  expected_value?: string
  evidence?: DiagnosisEvidence[]
  reason?: string
  recommendation?: string
  remediation_constraints?: string
  remediation_scope?: {
    selected_resource_ids: string[]
    deferred_resource_ids: string[]
    https_exception_resource_ids?: string[]
    https_exception_reason?: string
    rule_result_may_remain_fail_due_to_https_exception?: boolean
  }
}

interface DiagnosisStatus {
  id?: number
  status: string
  result: { results?: DiagnosisResult[] } | null
  startedAt?: string
}

interface PatchSummary {
  id: string
  diagnosis_run_id: number
  status: string
  requested_by: string
  created_at?: string
  rule_ids?: string[]
  https_exception_count?: number
  first_approval?: boolean
  first_decision?: "approve" | "reject" | null
  ai_verdict?: string | null
  checks_status?: string
  final_approval?: boolean
  final_decision?: "approve" | "reject" | null
  deployment_status?: string | null
}
interface PatchDetail extends PatchSummary {
  content_hash?: string
  approval_hash?: string
  review_hash?: string
  deployment_start_error?: string
  payload: {
    findings: DiagnosisResult[]
    source: {
      repository: string
      ref: string
      commit_sha: string
    } | null
    files: {
      file_path: string
      original_content: string
      proposed_content?: string
      diff?: string
    }[]
    resource_bindings?: {
      rule_id: string
      resource_id: string
      file_path: string
      resource_type: string
      resource_name: string
      module: string
    }[]
    report: {
      summary: string
      changes: {
        file_path: string
        evidence: string
        explanation: string
      }[]
      risks: string[]
      checks: string[]
      impact: string
      service_disruption: string
      resource_replacement: string
    } | null
    audit: {
      event: string
      actor: string
      at: string
      note?: string
    }[]
    error?: { code?: string; message: string }
    ai_review?: {
      verdict: string
      summary: string
      concerns: string[]
      model: string
    } | null
    human_review_approval?: { event: string; actor: string; at: string; note: string } | null
    github_pr?: {
      branch: string
      number?: number
      url?: string
      base_sha: string
      head_sha: string
    } | null
    checks?: {
      results: Record<string, { status: string; url?: string; at?: string }>
      run_id?: number
      url?: string
      plan_summary?: {
        counts: Record<string, number>
        resources: Record<string, string[]>
        labels?: Record<string, string[]>
      }
      plan_sha256?: string
      state?: { lineage: string; serial: number }
    } | null
    final_report?: {
      version: string
      report_notice?: string
      change_details?: {
        file_path: string
        explanations: { evidence: string; explanation: string }[]
        hunks: { location: string; before_lines: string[]; after_lines: string[] }[]
      }[]
      ai_assessment: {
        assessment: string
        change_explanation?: string
        user_impact?: string
        service_disruption?: string
        resource_replacement?: string
        risks: string[]
        decision_points?: string[]
        post_deploy_checks: string[]
      }
    } | null
    first_approval?: { actor: string; at: string } | null
    final_approval?: { event: string; actor: string; at: string } | null
    deployment?: {
      status: string
      url?: string
      merge_sha?: string
      error?: string
    } | null
    rediagnosis?: {
      run_id?: number
      results?: {
        rule_id: string
        before: string
        after: string
        verified: boolean
        current_value?: string
        expected_value?: string
      }[]
      error?: string
    } | null
  }
}
interface HistoryResponse {
  patches: PatchSummary[]
  can_create: boolean
  can_approve: boolean
}
interface MappingPreview {
  repository: string
  ref: string
  commit_sha: string
  mapping: Record<string, {
    status: "MATCHED" | "MANUAL_REVIEW" | "NOT_TERRAFORM" | "NO_CANDIDATE"
    reason: string
    candidates: { file_path: string; identity_match: boolean; covered_resource_ids?: string[]; resources: { type: string; name: string }[] }[]
    unmapped_resource_ids?: string[]
    // 자동 입력할 파일과 전체 후보 수
    suggested?: string[]
    total_candidates?: number
  }>
}

const splitPaths = (value: string | undefined) =>
  (value ?? "").split(",").map((p) => p.trim()).filter(Boolean)
// 백엔드가 주는 시각은 전부 UTC라, 브라우저 로케일로만 찍으면 시차가 난다.
function formatTime(value?: string | null) {
  if (!value) return "-"
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString("ko-KR", {
    timeZone: "Asia/Seoul",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  })
}
const PATCH_STATUS: Record<string, string> = {
  FETCHING: "GitHub 조회 중",
  SOURCE_READY: "원본 조회 완료",
  GENERATING: "AI 생성 중",
  AWAITING_FIRST_APPROVAL: "1차 승인 대기",
  FIRST_APPROVED: "1차 승인 완료",
  REJECTED: "반려",
  FAILED: "실패",
  AI_REVIEWING: "2차 AI 검증 중",
  AI_REJECTED: "2차 AI 검증 반려",
  AI_NEEDS_HUMAN_REVIEW: "2차 AI 추가 확인 필요",
  AI_HUMAN_REJECTED: "사람 검토 반려",
  AI_REVIEW_FAILED: "2차 AI 검증 오류",
  READY_FOR_PR: "독립 브랜치·PR 자동 생성 대기",
  CHECKS_RUNNING: "GitHub 검사 중",
  CHECKS_FAILED: "GitHub 검사 실패",
  FINAL_REPORTING: "최종 보고서 작성 중",
  FINAL_REPORT_FAILED: "최종 보고서 작성 오류",
  AWAITING_FINAL_APPROVAL: "최종 승인 대기",
  FINAL_APPROVED: "최종 승인",
  REVALIDATION_REQUIRED: "기준 변경 · 새 패치와 재승인 필요",
  FINAL_REJECTED: "최종 승인 반려",
  DEPLOYING: "Terraform 배포 중",
  DEPLOY_DISPATCH_UNKNOWN: "배포 요청 확인 필요",
  DEPLOY_FAILED: "배포 실패",
  REDIAGNOSING: "배포 후 재진단 중",
  REDIAGNOSIS_FAILED: "재진단 실패",
  REMEDIATED: "조치 확인 완료",
  NOT_REMEDIATED: "배포됨 · FAIL 잔존",
}

class ApiRequestError extends Error {
  constructor(message: string, readonly status: number) {
    super(message)
  }
}

async function fetchJson<T>(
  url: string,
  init: RequestInit,
  onUnauthorized: () => void,
): Promise<T> {
  const res = await fetch(url, { credentials: "include", ...init })
  if (res.status === 401) {
    onUnauthorized()
    throw new Error("로그인이 필요합니다.")
  }
  const body = await res.json().catch(() => null)
  if (!res.ok)
    throw new ApiRequestError(body?.message || `요청 실패 (HTTP ${res.status})`, res.status)
  return body as T
}

function DiffView({ diff }: { diff: string }) {
  return (
    <pre className="max-h-[320px] overflow-auto rounded-lg border border-[#E4E7EC] bg-[#0C111D] p-3 text-[13.5px] leading-relaxed">
      {diff.split("\n").map((line, i) => {
        let color = "#C2C9D6"
        if (line.startsWith("+") && !line.startsWith("+++")) color = "#6CE9A6"
        else if (line.startsWith("-") && !line.startsWith("---"))
          color = "#FDA29B"
        else if (line.startsWith("@@")) color = "#84CAFF"
        return (
          <div
            key={i}
            style={{ color }}
            className="whitespace-pre-wrap break-all font-mono"
          >
            {line || " "}
          </div>
        )
      })}
    </pre>
  )
}

function resourceNameKorean(ruleId: string, resourceId: string) {
  const listener = resourceId.match(/:listener\/(?:app|net)\/([^/]+)/)
  if (listener) return `로드밸런서 접속 규칙 · ${listener[1]}`
  const balancer = resourceId.match(/:loadbalancer\/(?:app|net)\/([^/]+)/)
  if (balancer) return `로드밸런서 · ${balancer[1]}`
  if (resourceId.startsWith("sg-")) return "보안 그룹"
  if (resourceId.startsWith("i-")) return "가상 서버(EC2)"
  if (resourceId.startsWith("arn:aws:iam::")) return "접근 권한 주체(IAM)"
  if (ruleId === "4.4" || resourceId.startsWith("arn:aws:s3:::")) return "S3 저장소(버킷)"
  return "AWS 리소스"
}

function canMarkHttpsException(ruleId: string, resourceId: string) {
  return (ruleId === "3.9" && resourceId.includes(":loadbalancer/")) ||
    (ruleId === "4.4" && resourceId.includes(":listener/"))
}

function HttpsExceptionSummary({ findings }: { findings: DiagnosisResult[] }) {
  const exceptions = findings.flatMap((finding) =>
    (finding.remediation_scope?.https_exception_resource_ids ?? []).map((resourceId) => ({
      ruleId: finding.rule_id,
      resourceId,
      reason: finding.remediation_scope?.https_exception_reason ?? "",
    })))
  if (!exceptions.length) return null
  return (
    <div className="rounded-lg border border-amber-300 bg-amber-50 p-3 text-xs text-amber-950">
      <h4 className="font-semibold">HTTPS 운영 예외 · 미조치</h4>
      <p className="mt-1">아래 HTTPS 조건은 이번 수정에서 해결되지 않습니다. 원래 진단 결과와 위험은 유지됩니다.</p>
      {exceptions.map((item) => (
        <div key={`${item.ruleId}-${item.resourceId}`} className="mt-2">
          <p className="font-semibold">규칙 {item.ruleId} · {resourceNameKorean(item.ruleId, item.resourceId)}</p>
          <p className="break-all font-mono text-[11px]">AWS ID: {item.resourceId}</p>
          <p className="mt-1 whitespace-pre-wrap">사유: {item.reason}</p>
        </div>
      ))}
    </div>
  )
}

const FAILED_PHASE: Record<string, number> = {
  FAILED: 0,
  REJECTED: 1,
  AI_REJECTED: 1,
  AI_HUMAN_REJECTED: 1,
  AI_REVIEW_FAILED: 1,
  CHECKS_FAILED: 1,
  FINAL_REPORT_FAILED: 1,
  REVALIDATION_REQUIRED: 1,
  FINAL_REJECTED: 1,
  DEPLOY_FAILED: 2,
  REDIAGNOSIS_FAILED: 3,
  NOT_REMEDIATED: 4,
}

function patchPhase(status: string) {
  if (status === "FETCHING") return 0
  if (["FINAL_APPROVED", "DEPLOYING", "DEPLOY_DISPATCH_UNKNOWN", "DEPLOY_FAILED"].includes(status)) return 2
  if (["REDIAGNOSING", "REDIAGNOSIS_FAILED"].includes(status)) return 3
  if (["REMEDIATED", "NOT_REMEDIATED"].includes(status)) return 4
  return FAILED_PHASE[status] ?? 1
}

function PatchProgress({ fix }: { fix: PatchDetail }) {
  const phase = patchPhase(fix.status)
  const failedAt = FAILED_PHASE[fix.status]
  const steps = ["보안 문제 분석", "AI 조치 계획", "AWS 리소스 조치", "재진단", "완료"]
  const finding = fix.payload.findings[0]
  const resourceIds = [...new Set(fix.payload.findings.flatMap((item) => item.resource_ids ?? []))]
  const isProcessing = ["FETCHING", "GENERATING", "AI_REVIEWING", "CHECKS_RUNNING", "FINAL_REPORTING", "DEPLOYING", "REDIAGNOSING"].includes(fix.status)
  return (
    <section className="rounded-2xl border border-[#E4E7EC] bg-white p-4" aria-label="현재 AI 조치 진행 과정">
      <div className="mb-4 flex flex-wrap items-start justify-between gap-2">
        <div>
          <h2 className="text-sm font-bold text-[#101828]">현재 AI 조치 진행 과정</h2>
          <p className="mt-1 text-xs text-[#667085]">{fix.payload.findings.map((item) => `규칙 ${item.rule_id}`).join(" · ")} · {PATCH_STATUS[fix.status] ?? fix.status}</p>
        </div>
        <span className="rounded-full bg-[#F2F4F7] px-2.5 py-1 text-[11px] font-semibold text-[#344054]">진단 #{fix.diagnosis_run_id}</span>
      </div>
      <ol className="space-y-2">
        {steps.map((step, index) => {
          const state = index < phase ? "done" : index > phase ? "waiting" : failedAt === index ? "failed" : fix.status === "REMEDIATED" ? "done" : "active"
          const tone = state === "failed" ? "border-red-200 bg-red-50 text-red-800" : state === "active" ? "border-[#B2DDFF] bg-[#EFF8FF] text-[#175CD3]" : state === "done" ? "border-[#D1FADF] bg-[#F6FEF9] text-[#027A48]" : "border-[#EAECF0] bg-[#F9FAFB] text-[#98A2B3]"
          return (
            <li key={step} className={`rounded-xl border ${tone} ${state === "active" || state === "failed" ? "p-4" : "px-3 py-2"}`}>
              <div className="flex items-center gap-2 text-xs font-semibold">
                <span aria-hidden="true" className="inline-flex h-5 w-5 items-center justify-center rounded-full border border-current">
                  {state === "done" ? "✓" : state === "failed" ? "!" : state === "active" && isProcessing ? "⟳" : "○"}
                </span>
                <span>{step}</span>
                {state === "active" && <span className="ml-auto text-[11px]">{PATCH_STATUS[fix.status] ?? fix.status}</span>}
                {state === "failed" && <span className="ml-auto text-[11px]">진행 중단</span>}
              </div>
              {(state === "active" || state === "failed") && (
                <div className="mt-3 grid gap-3 border-t border-current/15 pt-3 text-xs text-[#344054] sm:grid-cols-2">
                  <div>
                    <p className="font-semibold text-[#667085]">보안 문제</p>
                    <p className="mt-1 whitespace-pre-wrap">{finding?.reason || `진단 규칙 ${finding?.rule_id ?? "-"}`}</p>
                  </div>
                  <div>
                    <p className="font-semibold text-[#667085]">대상 및 수행 작업</p>
                    {resourceIds.length > 0 && <p className="mt-1 break-all">{resourceIds.length === 1 ? `${resourceNameKorean(finding?.rule_id ?? "", resourceIds[0])} · ${resourceIds[0]}` : `${resourceIds.length}개 AWS 리소스`}</p>}
                    <p className="mt-1 whitespace-pre-wrap">{fix.payload.report?.summary || finding?.recommendation || "조치 계획을 준비하고 있습니다."}</p>
                  </div>
                </div>
              )}
            </li>
          )
        })}
      </ol>
    </section>
  )
}

function PatchResult({ fix, onDetails, onReport, onUseLatest, busy }: { fix: PatchDetail; onDetails: () => void; onReport: () => void; onUseLatest: () => void; busy: boolean }) {
  if (!["REMEDIATED", "NOT_REMEDIATED", "DEPLOY_FAILED", "REDIAGNOSIS_FAILED"].includes(fix.status)) return null
  const verified = fix.status === "REMEDIATED"
  const comparisons = fix.payload.rediagnosis?.results ?? []
  return (
    <section className={`rounded-2xl border p-4 ${verified ? "border-[#ABEFC6] bg-[#F6FEF9]" : "border-[#FEDF89] bg-[#FFFCF5]"}`} aria-label="현재 조치 결과">
      <h2 className="text-sm font-bold text-[#101828]">현재 조치 결과</h2>
      <p className={`mt-2 text-base font-bold ${verified ? "text-[#027A48]" : "text-[#B54708]"}`}>
        {verified ? "✓ 보안 조치 확인 완료" : fix.status === "NOT_REMEDIATED" ? "! 배포 후 보안 문제 잔존" : fix.status === "DEPLOY_FAILED" ? "! AWS 리소스 조치 실패" : "! 재진단 결과 확인 실패"}
      </p>
      <p className="mt-1 text-xs text-[#475467]">
        {verified
          ? fix.payload.report?.summary || fix.payload.findings.map((item) => `규칙 ${item.rule_id}`).join(", ")
          : fix.status === "NOT_REMEDIATED"
            ? `재진단에서 ${comparisons.filter((item) => !item.verified).map((item) => `규칙 ${item.rule_id}`).join(", ") || "선택한 규칙"}이 PASS가 아닙니다.`
            : fix.payload.deployment?.error || fix.payload.rediagnosis?.error || PATCH_STATUS[fix.status]}
      </p>
      {comparisons.length > 0 && (
        <div className="mt-4 grid gap-2 sm:grid-cols-2">
          {comparisons.map((item) => (
            <div key={item.rule_id} className="rounded-lg border border-[#E4E7EC] bg-white p-3 text-xs">
              <p className="font-semibold text-[#344054]">규칙 {item.rule_id} · 재진단 {item.verified ? "정상" : "재검토 필요"}</p>
              <p className="mt-2 text-[#667085]">진단 상태: {item.before} → <strong className={item.verified ? "text-[#027A48]" : "text-[#B54708]"}>{item.after}</strong></p>
            </div>
          ))}
        </div>
      )}
      {fix.payload.rediagnosis?.error && <p className="mt-3 text-xs text-[#B54708]">{fix.payload.rediagnosis.error}</p>}
      {fix.payload.deployment?.error && <p className="mt-3 text-xs text-[#B54708]">{fix.payload.deployment.error}</p>}
      <div className="mt-4 flex flex-wrap gap-2">
        {fix.status === "REDIAGNOSIS_FAILED" && fix.payload.deployment?.status === "SUCCESS" && (
          <button type="button" onClick={onUseLatest} disabled={busy} title="배포 완료 후 시작한 최신 AI 진단 결과를 적용합니다. Terraform은 다시 실행하지 않습니다." className="rounded-lg bg-[#101828] px-3 py-2 text-xs font-semibold text-white disabled:opacity-40">
            배포 후 AI 진단 결과 반영
          </button>
        )}
        <button type="button" onClick={onDetails} className="rounded-lg border border-[#D0D5DD] bg-white px-3 py-2 text-xs font-semibold text-[#344054]">상세 정보</button>
        {(fix.payload.report || fix.payload.final_report) && <button type="button" onClick={onReport} className="rounded-lg bg-[#101828] px-3 py-2 text-xs font-semibold text-white">보고서 보기</button>}
      </div>
    </section>
  )
}

export function AIActionsPage({
  onUnauthorized,
  initialSelection,
  initialPatchId,
  onReturnToStart,
}: {
  onUnauthorized: () => void
  initialSelection?: {
    runId: number
    ruleIds: string[]
  } | null
  initialPatchId?: string | null
  onReturnToStart?: () => void
}) {
  const [diagnosis, setDiagnosis] = useState<DiagnosisStatus | null>(null)
  const [selectedRuleIds, setSelectedRuleIds] = useState<string[]>(
    initialSelection?.ruleIds ?? [],
  )
  const [paths, setPaths] = useState<Record<string, string>>({})
  const [targetResources, setTargetResources] = useState<Record<string, string[]>>({})
  const [constraints, setConstraints] = useState<Record<string, string>>({})
  const [httpsExceptions, setHttpsExceptions] = useState<Record<string, string[]>>({})
  const [httpsExceptionReasons, setHttpsExceptionReasons] = useState<Record<string, string>>({})
  const [mappingPreview, setMappingPreview] = useState<MappingPreview | null>(null)
  const [previewRules, setPreviewRules] = useState("")
  const [running, setRunning] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [history, setHistory] = useState<HistoryResponse | null>(null)
  const [offset, setOffset] = useState(0)
  const [fix, setFix] = useState<PatchDetail | null>(null)
  const [showPreparation, setShowPreparation] = useState(!initialPatchId)
  const [reportOpen, setReportOpen] = useState(false)
  const technicalRef = useRef<HTMLDetailsElement>(null)
  const historyRef = useRef<HTMLDetailsElement>(null)
  const pageRef = useRef<HTMLDivElement>(null)
  const [reviewed, setReviewed] = useState(false)
  const [note, setNote] = useState("")
  const api = <T,>(url: string, body?: unknown) =>
    fetchJson<T>(
      url,
      body === undefined
        ? { method: "GET" }
        : {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
          },
      onUnauthorized,
    )
  const loadHistory = async (page = offset) => {
    const data = await api<HistoryResponse>(
      `/api/ai-actions/patches?offset=${page}`,
    )
    setHistory(data)
  }
  useEffect(() => {
    let cancelled = false
    Promise.all([
      fetchJson<DiagnosisStatus>(
        "/api/ai-diagnosis/status",
        { method: "GET" },
        onUnauthorized,
      ),
      fetchJson<HistoryResponse>(
        "/api/ai-actions/patches",
        { method: "GET" },
        onUnauthorized,
      ),
      initialPatchId
        ? fetchJson<PatchDetail>(
            `/api/ai-actions/patches/${initialPatchId}`,
            { method: "GET" },
            onUnauthorized,
          )
        : Promise.resolve(null),
    ])
      .then(([d, h, detail]) => {
        if (!cancelled) {
          setDiagnosis(d)
          setHistory(h)
          if (detail) setFix(detail)
        }
      })
      .catch((e: Error) => !cancelled && setError(e.message))
    return () => {
      cancelled = true
    }
  }, [])
  useEffect(() => {
    if (!initialPatchId || fix?.id === initialPatchId) return
    let cancelled = false
    void api<PatchDetail>(`/api/ai-actions/patches/${initialPatchId}`)
      .then((detail) => {
        if (!cancelled) {
          setFix(detail)
          setShowPreparation(false)
          setReviewed(false)
          setNote("")
        }
      })
      .catch((e: Error) => !cancelled && setError(e.message))
    return () => { cancelled = true }
  }, [initialPatchId])
  useEffect(() => {
    if (!reportOpen) return
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setReportOpen(false)
    }
    window.addEventListener("keydown", closeOnEscape)
    return () => window.removeEventListener("keydown", closeOnEscape)
  }, [reportOpen])
  const fails = useMemo(
    () => (diagnosis?.result?.results ?? []).filter((r) => r.status === "FAIL"),
    [diagnosis],
  )
  useEffect(() => {
    const active = [
      "FETCHING",
      "GENERATING",
      "AI_REVIEWING",
      "CHECKS_RUNNING",
      "FINAL_REPORTING",
      "FINAL_APPROVED",
      "DEPLOYING",
      "REDIAGNOSING",
    ]
    if (!fix || !active.includes(fix.status)) return
    let cancelled = false
    let pending = false
    const timer = window.setInterval(
      async () => {
        if (pending) return
        pending = true
        try {
          const route =
            fix.status === "CHECKS_RUNNING"
              ? "checks/refresh"
              : fix.status === "DEPLOYING"
                ? "deployment/refresh"
                : ""
          const patchUrl = `/api/ai-actions/patches/${fix.id}`
          const current = await api<PatchDetail>(patchUrl)
          let data = current
          if (route && current.status === fix.status) {
            try {
              await api<PatchDetail>(`${patchUrl}/${route}`, {})
            } catch (e) {
              if (!(e instanceof ApiRequestError) || e.status !== 409) throw e
            }
            data = await api<PatchDetail>(patchUrl)
          }
          if (!cancelled) {
            setFix(data)
            setError(null)
            if (!active.includes(data.status)) await loadHistory()
          }
        } catch (e) {
          if (!cancelled)
            setError(e instanceof Error ? e.message : "진행 상태 조회 실패")
        } finally {
          pending = false
        }
      },
      fix.status === "CHECKS_RUNNING" ? 5000 : ["FINAL_APPROVED", "DEPLOYING"].includes(fix.status) ? 10000 : 2500,
    )
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [fix?.id, fix?.status])
  const selected = fails.filter((r) => selectedRuleIds.includes(r.rule_id))
  const selectionKey = selected.map((r) => r.rule_id).sort().join(",")
  const notTerraformSelected = !!mappingPreview && previewRules === selectionKey &&
    selected.some((r) => mappingPreview.mapping[r.rule_id]?.status === "NOT_TERRAFORM")
  const selectDetail = (data: PatchDetail, scrollToTop = false) => {
    setFix(data)
    setShowPreparation(false)
    setReportOpen(false)
    setReviewed(false)
    setNote("")
    if (scrollToTop) {
      pageRef.current?.closest("[data-app-scroll-container]")?.scrollTo({ top: 0, behavior: "auto" })
    }
  }
  const returnToStart = () => {
    setFix(null)
    setShowPreparation(true)
    setReportOpen(false)
    setReviewed(false)
    setNote("")
    setError(null)
    if (historyRef.current) historyRef.current.open = false
    onReturnToStart?.()
    pageRef.current?.closest("[data-app-scroll-container]")?.scrollTo({ top: 0, behavior: "auto" })
  }
  const toggleTechnicalDetails = () => {
    if (!technicalRef.current) return
    technicalRef.current.open = !technicalRef.current.open
    if (technicalRef.current.open) {
      technicalRef.current.scrollIntoView({ behavior: "auto", block: "start" })
    }
  }
  const perform = async (work: () => Promise<void>) => {
    setRunning(true)
    setError(null)
    try {
      await work()
    } catch (e) {
      setError(e instanceof Error ? e.message : "요청에 실패했습니다.")
    } finally {
      setRunning(false)
    }
  }
  const previewFiles = () =>
    perform(async () => {
      const result = await api<MappingPreview>("/api/ai-actions/mapping-preview", {
        diagnosis_run_id: initialSelection?.runId ?? diagnosis?.id,
        rule_ids: selected.map((r) => r.rule_id),
      })
      setMappingPreview(result)
      setPreviewRules(selectionKey)
      setHttpsExceptions({})
      setHttpsExceptionReasons({})
      setTargetResources(Object.fromEntries(selected.map((r) => {
        const item = result.mapping[r.rule_id]
        const suggested = item?.suggested ?? []
        const covered = new Set(item?.candidates
          .filter((candidate) => suggested.includes(candidate.file_path))
          .flatMap((candidate) => candidate.covered_resource_ids ?? []) ?? [])
        const verified = (r.resource_ids ?? []).filter((id) => covered.has(id))
        return [r.rule_id, verified.length ? verified : r.resource_ids ?? []]
      })))
      setPaths(Object.fromEntries(selected.map((r) => {
        const item = result.mapping[r.rule_id]
        const files = item?.suggested ?? (item?.candidates[0] ? [item.candidates[0].file_path] : [])
        return [r.rule_id, files.join(", ")]
      })))
    })
  const toggleCandidate = (ruleId: string, filePath: string) =>
    setPaths((p) => {
      const current = splitPaths(p[ruleId])
      const next = current.includes(filePath)
        ? current.filter((path) => path !== filePath)
        : [...current, filePath]
      return { ...p, [ruleId]: next.join(", ") }
    })
  const fetchSource = () =>
    perform(async () => {
      const mapping = Object.fromEntries(
        selected.map((r) => [
          r.rule_id,
          (paths[r.rule_id] ?? "")
            .split(",")
            .map((p) => p.trim())
            .filter(Boolean),
        ]),
      )
      const data = await api<PatchDetail>("/api/ai-actions/patches", {
        diagnosis_run_id: initialSelection?.runId ?? diagnosis?.id,
        mapping,
        target_resource_ids: Object.fromEntries(selected.map((r) => [
          r.rule_id, targetResources[r.rule_id] ?? r.resource_ids ?? [],
        ])),
        https_exception_resource_ids: Object.fromEntries(selected.map((r) => [
          r.rule_id, httpsExceptions[r.rule_id] ?? [],
        ])),
        https_exception_reasons: Object.fromEntries(selected.map((r) => [
          r.rule_id, httpsExceptionReasons[r.rule_id] ?? "",
        ])),
        remediation_constraints: Object.fromEntries(selected.map((r) => [r.rule_id, constraints[r.rule_id] ?? ""])),
        source_commit_sha: mappingPreview?.commit_sha,
      })
      selectDetail(data)
      await loadHistory()
    })
  const runFix = () =>
    perform(async () => {
      if (!fix) return
      selectDetail(
        await api<PatchDetail>("/api/ai-actions/terraform-fix", {
          patch_id: fix.id,
        }),
      )
      await loadHistory()
    })
  const decide = (decision: "approve" | "reject") =>
    perform(async () => {
      if (!fix) return
      selectDetail(
        await api<PatchDetail>(
          `/api/ai-actions/patches/${fix.id}/first-approval`,
          {
            decision,
            content_hash: fix.content_hash,
            reviewed,
            note,
          },
        ),
      )
      await loadHistory()
    })
  const step = (path: string, body: unknown = {}) =>
    perform(async () => {
      if (!fix) return
      selectDetail(
        await api<PatchDetail>(
          `/api/ai-actions/patches/${fix.id}/${path}`,
          body,
        ),
      )
      await loadHistory()
    })
  const decideFinal = (decision: "approve" | "reject") =>
    step("final-approval", {
      decision,
      approval_hash: fix?.approval_hash,
      reviewed,
      note,
    })
  const decideHumanReview = (decision: "approve" | "reject") =>
    step("human-review", {
      decision,
      review_hash: fix?.review_hash,
      reviewed,
      note,
    })
  const button =
    "rounded-lg bg-[#101828] px-4 py-2 text-xs font-semibold text-white disabled:opacity-40"
  const panel = "rounded-2xl border border-[#E4E7EC] bg-white p-4 space-y-3"
  const checkResults = fix?.payload.checks?.results
  const checksFailed = ["CHECKS_FAILED", "REVALIDATION_REQUIRED"].includes(fix?.status ?? "") ||
    (!!checkResults && Object.values(checkResults).some((result) => ["FAIL", "ERROR"].includes(result.status)))
  const checksPassed = !checksFailed && !!checkResults && ["fmt", "validate", "plan", "tflint", "checkov"]
    .every((name) => checkResults[name]?.status === "PASS")
  return (
    <div ref={pageRef} className="min-h-full space-y-4 p-4">
      <div>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h1 className="text-lg font-bold text-[#101828]">AI 조치</h1>
          {fix && (
            <button type="button" onClick={returnToStart} disabled={running} className="cursor-pointer rounded-lg border border-[#D0D5DD] bg-white px-3 py-1.5 text-xs font-semibold text-[#344054] hover:bg-[#F9FAFB] disabled:cursor-not-allowed disabled:opacity-40">
              ← AI 조치 초기 화면으로
            </button>
          )}
        </div>
        <p className="text-xs text-[#667085]">
          FAIL 다중 선택 → GitHub 원본 조회 → 통합 수정안·변경 보고서 → 사람의
          1차 승인
        </p>
        <p className="mt-1 text-xs text-[#667085]">
          2차 AI 검증과 GitHub 검사 결과를 확인한 뒤 최종 승인과 배포를
          진행합니다.
        </p>
      </div>
      {error && (
        <p
          role="alert"
          className="rounded-lg bg-red-50 p-3 text-xs text-red-700"
        >
          {error}
        </p>
      )}
      {fix && <PatchProgress fix={fix} />}
      {fix && (
        <section className={panel} aria-label="조치 검토 및 다음 작업">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-sm font-bold text-[#101828]">조치 검토 및 다음 작업</h2>
            <div className="flex flex-wrap gap-2">
              <button type="button" onClick={toggleTechnicalDetails} className="rounded-lg border border-[#D0D5DD] px-3 py-1.5 text-xs font-semibold text-[#344054]">상세 정보</button>
              {(fix.payload.report || fix.payload.final_report) && <button type="button" onClick={() => setReportOpen(true)} className="rounded-lg bg-[#101828] px-3 py-1.5 text-xs font-semibold text-white">보고서 보기</button>}
            </div>
          </div>
          <p className="text-xs text-[#667085]">{PATCH_STATUS[fix.status] ?? fix.status}</p>
          {checkResults && (
            <p role="status" className={`rounded-lg px-3 py-2 text-xs font-semibold ${checksPassed ? "bg-[#ECFDF3] text-[#027A48]" : checksFailed ? "bg-[#FEF3F2] text-[#B42318]" : "bg-[#EFF8FF] text-[#175CD3]"}`}>
              GitHub 검사: {checksPassed ? "PASS" : fix.status === "REVALIDATION_REQUIRED" ? "재검증 필요" : checksFailed ? "실패" : "진행 중"}
            </p>
          )}
          {fix.deployment_start_error && (
            <p role="alert" className="text-xs text-red-700">{fix.deployment_start_error}</p>
          )}
          <p className="text-xs">
            진단 #{fix.diagnosis_run_id} · FAIL{" "}
            {fix.payload.findings.map((f) => f.rule_id).join(", ")}
          </p>
          <HttpsExceptionSummary findings={fix.payload.findings} />
          {fix.payload.error && (
            <div role="alert" className="space-y-1 text-xs text-red-700">
              <p>{fix.payload.error.message} 이 패치는 이력에 보존됩니다. 새 패치로 다시 요청하세요.</p>
              {fix.payload.error.code === "NO_CHANGES" &&
                fix.payload.findings.some((finding) => finding.rule_id === "3.2") && (
                  <p>
                    {fix.payload.findings.find((finding) => finding.rule_id === "3.2")?.remediation_constraints?.trim()
                      ? "3.2의 선택한 보안 그룹 ID와 Terraform 파일 연결, 입력한 허용 소스 및 위반 규칙을 확인하세요."
                      : "3.2의 운영 통신 요건이 비어 있습니다. 새 패치에서 허용할 소스 CIDR 또는 보안 그룹과 적용할 규칙을 입력하세요."}
                  </p>
                )}
            </div>
          )}
          {history?.can_create && fix.status === "SOURCE_READY" && (
            <button className={button} onClick={runFix} disabled={running}>
              {running ? "AI 생성 중…" : "1차 AI 통합 수정안 · 보고서 생성"}
            </button>
          )}
          {fix.status === "AWAITING_FIRST_APPROVAL" &&
            (history?.can_create ? (
              <div className="space-y-3 rounded-lg bg-amber-50 p-3 text-xs">
                <label className="flex gap-2">
                  <input
                    type="checkbox"
                    checked={reviewed}
                    disabled={running}
                    onChange={(e) => setReviewed(e.target.checked)}
                  />
                  수정 전후 코드, Diff 및 AI 변경 보고서를 확인했습니다.
                </label>
                <textarea
                  aria-label="1차 승인 의견 또는 반려 사유"
                  value={note}
                  onChange={(e) => setNote(e.target.value)}
                  maxLength={2000}
                  placeholder="승인 의견 또는 반려 사유(반려 시 필수)"
                  className="w-full rounded border border-gray-300 p-2"
                />
                <div className="flex gap-2">
                  <button
                    className={button}
                    disabled={running || !reviewed}
                    onClick={() => decide("approve")}
                  >
                    관리자의 1차 승인 · 2차 AI 검증 시작
                  </button>
                  <button
                    className={button}
                    disabled={running || !reviewed || !note.trim()}
                    onClick={() => decide("reject")}
                  >
                    반려
                  </button>
                </div>
                <p>
                  1차 승인 후 2차 AI가 변경 내용을 바로 검증합니다. 배포는 최종 승인 후 진행됩니다.
                </p>
              </div>
            ) : (
              <p className="text-xs text-amber-700">
                관리자 계정으로 코드·보고서를 검토한 뒤 1차 승인 또는 반려할 수
                있습니다.
              </p>
            ))}
          {fix.status === "FIRST_APPROVED" && history?.can_create && (
            <button
              className={button}
              disabled={running}
              onClick={() => step("ai-review")}
            >
              2차 AI 검증 시작
            </button>
          )}
          {fix.payload.ai_review && (
            <section className="rounded-lg border p-3 text-xs space-y-2">
              <h3 className="font-semibold">
                2차 AI 검증 · {fix.payload.ai_review.verdict}
              </h3>
              <p>{fix.payload.ai_review.summary}</p>
              <ul className="list-disc pl-4">
                {fix.payload.ai_review.concerns.map((c, i) => (
                  <li key={i}>{c}</li>
                ))}
              </ul>
              {fix.status === "AI_REJECTED" && (
                <p>
                  수정이 필요하면 새 패치에서 코드·보고서를 다시 생성하고 1차
                  승인을 받으세요.
                </p>
              )}
              {fix.status === "AI_NEEDS_HUMAN_REVIEW" && (
                history?.can_create ? (
                  <div className="space-y-3 rounded-lg bg-amber-50 p-3">
                    <p>
                      AI가 확인을 보류했습니다. 위 우려사항과 미해결 진단 조건을 확인하세요.
                      승인하면 현재 수정안으로 PR 생성과 GitHub 검사 단계에 진행합니다.
                      승인만으로 규칙이 PASS가 되거나 배포되지는 않습니다.
                    </p>
                    <label className="flex gap-2">
                      <input type="checkbox" checked={reviewed} disabled={running}
                        onChange={(e) => setReviewed(e.target.checked)} />
                      수정 전후 코드, 2차 AI 우려사항과 미해결 조건을 확인했습니다.
                    </label>
                    <textarea aria-label="2차 AI 보류 검토 근거" value={note}
                      onChange={(e) => setNote(e.target.value)} maxLength={2000}
                      placeholder="승인 또는 반려 근거를 입력하세요"
                      className="w-full rounded border border-gray-300 p-2" />
                    <div className="flex gap-2">
                      <button className={button} disabled={running || !reviewed || !note.trim() || !fix.review_hash}
                        onClick={() => decideHumanReview("approve")}>
                        사람 검토 승인 · 다음 단계 진행
                      </button>
                      <button className={button} disabled={running || !reviewed || !note.trim() || !fix.review_hash}
                        onClick={() => decideHumanReview("reject")}>
                        반려
                      </button>
                    </div>
                  </div>
                ) : (
                  <p>관리자 계정에서 우려사항과 미해결 조건을 검토한 뒤 승인 또는 반려할 수 있습니다.</p>
                )
              )}
              {fix.payload.human_review_approval?.event === "HUMAN_REVIEW_APPROVED" && (
                <p className="rounded-lg bg-amber-50 p-3">
                  사람 검토 승인: {fix.payload.human_review_approval.actor} · {fix.payload.human_review_approval.note}
                </p>
              )}
            </section>
          )}
          {fix.status === "READY_FOR_PR" && history?.can_create && (
            <button
              className={button}
              disabled={running}
              onClick={() => step("publish")}
            >
              PR 생성 다시 시도
            </button>
          )}
          {fix.status === "AWAITING_FINAL_APPROVAL" &&
            (history?.can_approve ? (
              <section className="rounded-lg bg-amber-50 p-3 text-xs space-y-2">
                <h3 className="font-semibold">사람의 최종 승인</h3>
                <p>
                  원본·수정 코드, Diff, 최종 보고서, 2차 AI 검증, 검사 결과,
                  Plan 요약과 PR을 확인하세요. 승인은 이 commit과 저장 Plan에
                  묶입니다.
                </p>
                <label className="flex gap-2">
                  <input
                    type="checkbox"
                    checked={reviewed}
                    disabled={running}
                    onChange={(e) => setReviewed(e.target.checked)}
                  />
                  모든 내용을 확인했습니다.
                </label>
                <textarea
                  aria-label="최종 승인 의견 또는 반려 사유"
                  value={note}
                  onChange={(e) => setNote(e.target.value)}
                  maxLength={2000}
                  className="w-full rounded border p-2"
                  placeholder="반려 사유(반려 시 필수)"
                />
                <div className="flex gap-2">
                  <button
                    className={button}
                    disabled={running || !reviewed}
                    onClick={() => decideFinal("approve")}
                  >
                    최종 승인 및 자동 배포
                  </button>
                  <button
                    className={button}
                    disabled={running || !reviewed || !note.trim()}
                    onClick={() => decideFinal("reject")}
                  >
                    최종 반려
                  </button>
                </div>
              </section>
            ) : (
              <p className="text-xs">
                승인자 계정에서 최종 보고서와 Plan을 검토할 수 있습니다.
              </p>
            ))}
          {fix.status === "FINAL_APPROVED" && (
            <p className="text-xs text-gray-600">자동 배포 요청을 재시도하는 중입니다.</p>
          )}
          <details ref={technicalRef} key={fix.id} className="rounded-xl border border-[#E4E7EC] bg-[#F9FAFB]" aria-label="상세 정보">
            <summary className="cursor-pointer px-4 py-3 text-xs font-semibold text-[#344054]">상세 정보 · 코드와 검증 자료</summary>
            <div className="space-y-4 border-t border-[#E4E7EC] bg-white p-4">
              <p className="break-all font-mono text-xs text-[#667085]">패치 ID: {fix.id}</p>
              {fix.payload.findings.map((finding) => (
                <div key={finding.rule_id} className="rounded-lg border border-[#EAECF0] p-3 text-xs">
                  <p className="font-semibold text-[#344054]">진단 규칙 {finding.rule_id} · {finding.status}</p>
                  {finding.resource_ids?.map((resourceId) => (
                    <p key={resourceId} className="mt-1 break-all font-mono text-[#667085]">{resourceNameKorean(finding.rule_id, resourceId)} · {resourceId}</p>
                  ))}
                </div>
              ))}
          {fix.payload.source && (
            <p className="break-all font-mono text-xs text-gray-500">
              {fix.payload.source.repository} · {fix.payload.source.ref} ·{" "}
              {fix.payload.source.commit_sha}
            </p>
          )}
          {fix.payload.findings.some((finding) => finding.rule_id === "3.2") &&
            fix.payload.resource_bindings !== undefined && (
              <div className="rounded-lg border border-gray-200 p-3 text-xs">
                <p className="font-semibold">3.2 · State에서 확인한 AWS ID ↔ Terraform 선언</p>
                {fix.payload.resource_bindings.filter((binding) => binding.rule_id === "3.2").length ? (
                  fix.payload.resource_bindings.filter((binding) => binding.rule_id === "3.2").map((binding) => (
                    <p key={`${binding.resource_id}-${binding.file_path}-${binding.resource_name}`} className="mt-1 break-all">
                      {resourceNameKorean(binding.rule_id, binding.resource_id)} · AWS ID: {binding.resource_id}
                      {" → "}{binding.file_path} · {binding.module ? `${binding.module}.` : ""}{binding.resource_type}.{binding.resource_name}
                    </p>
                  ))
                ) : (
                  <p className="mt-1 text-amber-800">선택한 보안 그룹과 이 파일들의 State 연결을 확인하지 못했습니다. 파일과 리소스 소유권을 확인하세요.</p>
                )}
              </div>
            )}
          {fix.payload.files.map((file) => (
            <div key={file.file_path} className="space-y-2">
              <h3 className="text-xs font-semibold">{file.file_path}</h3>
              <details open={fix.status === "SOURCE_READY"}>
                <summary className="cursor-pointer text-xs">
                  수정 전 원본 코드
                </summary>
                <pre className="max-h-72 overflow-auto bg-gray-50 p-3 text-xs">
                  {file.original_content}
                </pre>
              </details>
              {file.proposed_content !== undefined && (
                <details>
                  <summary className="cursor-pointer text-xs">
                    수정 후 제안 코드
                  </summary>
                  <pre className="max-h-72 overflow-auto bg-gray-50 p-3 text-xs">
                    {file.proposed_content}
                  </pre>
                </details>
              )}
              {file.diff && <DiffView diff={file.diff} />}
            </div>
          ))}
          {fix.payload.github_pr && (
            <section className="rounded-lg border p-3 text-xs space-y-1">
              <h3 className="font-semibold">GitHub PR</h3>
              <p className="break-all">
                브랜치 {fix.payload.github_pr.branch} · 기준{" "}
                {fix.payload.github_pr.base_sha} · 수정{" "}
                {fix.payload.github_pr.head_sha}
              </p>
              {fix.payload.github_pr.url && (
                <a
                  className="underline"
                  href={fix.payload.github_pr.url}
                  target="_blank"
                  rel="noreferrer"
                >
                  PR #{fix.payload.github_pr.number} 열기
                </a>
              )}
            </section>
          )}
          {fix.payload.checks && (
            <section className="rounded-lg border p-3 text-xs space-y-2">
              <h3 className="font-semibold">GitHub 자동 검사</h3>
              {Object.entries(fix.payload.checks.results).map(
                ([name, result]) => (
                  <p key={name}>
                    {name}: <strong>{result.status}</strong>
                    {result.at ? ` · ${formatTime(result.at)}` : ""}
                    {result.url && <a className="ml-2 underline" href={result.url}
                      target="_blank" rel="noreferrer">실행 보기</a>}
                  </p>
                ),
              )}
              {fix.payload.checks.url && (
                <a
                  className="underline"
                  href={fix.payload.checks.url}
                  target="_blank"
                  rel="noreferrer"
                >
                  Actions 실행 #{fix.payload.checks.run_id} 보기
                </a>
              )}
              {fix.payload.checks.plan_summary && (
                <div>
                  <p className="font-semibold">
                    Terraform Plan 요약 · 저장 Plan SHA-256{" "}
                    {fix.payload.checks.plan_sha256}
                  </p>
                  {Object.entries(
                    fix.payload.checks.plan_summary.labels ?? fix.payload.checks.plan_summary.resources,
                  ).map(([kind, addresses]) => (
                    <p key={kind}>
                      {kind} ({fix.payload.checks?.plan_summary?.counts[kind]}):{" "}
                      {addresses.join(", ") || "없음"}
                    </p>
                  ))}
                </div>
              )}
            </section>
          )}
          {fix.payload.deployment && (
            <section className="rounded-lg border p-3 text-xs space-y-2">
              <h3 className="font-semibold">
                배포 결과 · {fix.payload.deployment.status}
              </h3>
              {fix.payload.deployment.url && (
                <a
                  href={fix.payload.deployment.url}
                  target="_blank"
                  rel="noreferrer"
                  className="underline"
                >
                  배포 Actions 실행 보기
                </a>
              )}
              {fix.payload.deployment.merge_sha && (
                <p className="break-all">
                  운영 코드 commit: {fix.payload.deployment.merge_sha}
                </p>
              )}
              {fix.payload.deployment.error && (
                <p className="text-red-700">{fix.payload.deployment.error}</p>
              )}
            </section>
          )}
          {fix.payload.rediagnosis && (
            <section className="rounded-lg border p-3 text-xs space-y-2">
              <h3 className="font-semibold">
                배포 후 재진단 · #{fix.payload.rediagnosis.run_id ?? "실패"}
              </h3>
              {fix.payload.rediagnosis.error && (
                <p className="text-red-700">{fix.payload.rediagnosis.error}</p>
              )}
              {fix.payload.rediagnosis.results?.map((r) => (
                <p key={r.rule_id}>
                  {r.rule_id}: {r.before} → {r.after} ·{" "}
                  {r.verified ? "조치 확인" : "재검토 필요"} · 현재{" "}
                  {r.current_value ?? "-"} · 기준 {r.expected_value ?? "-"}
                </p>
              ))}
            </section>
          )}
          <div className="flex flex-wrap gap-2 text-xs">
            {(["patch", "first", "final", "results"] as const).map((kind) => {
              const available =
                kind === "patch"
                  ? fix.payload.files.some((f) => !!f.diff)
                  : kind === "first"
                    ? !!fix.payload.report
                    : kind === "final"
                      ? !!fix.payload.final_report
                      : !!(fix.payload.deployment || fix.payload.rediagnosis)
              return available ? (
                <a
                  key={kind}
                  className="rounded border border-gray-300 px-3 py-2 underline"
                  href={`/api/ai-actions/patches/${fix.id}/download/${kind}`}
                >
                  {kind === "patch"
                    ? ".patch"
                    : kind === "first"
                      ? "1차 보고서 PDF"
                      : kind === "final"
                        ? "최종 보고서 PDF"
                        : "검증·배포·재진단 PDF"}{" "}
                  다운로드
                </a>
              ) : null
            })}
          </div>
            </div>
          </details>
          <p className="text-xs text-gray-500">
            코드가 변경되면 새 패치를 생성하여 보고서·승인을 다시 받아야 합니다.
          </p>
        </section>
      )}
      {fix && <PatchResult fix={fix} onDetails={toggleTechnicalDetails} onReport={() => setReportOpen(true)} onUseLatest={() => step("rediagnosis/use-latest")} busy={running} />}
      {history?.can_create && (
        <div className="space-y-3">
          <button type="button" onClick={() => setShowPreparation((open) => !open)} aria-expanded={showPreparation} className="w-full rounded-2xl border border-[#E4E7EC] bg-white px-4 py-3 text-left text-sm font-semibold text-[#101828]">
            {showPreparation ? "▾" : "▸"} 새 AI 조치 준비
            <span className="ml-2 text-xs font-normal text-[#667085]">진단 FAIL 선택과 Terraform 파일 지정</span>
          </button>
          {showPreparation && (
        <div className="grid gap-3 lg:grid-cols-[minmax(280px,340px)_1fr]">
          <section className={panel}>
            <h2 className="text-sm font-semibold">
              실패 항목 {fails.length}개 · 선택 {selected.length}개
            </h2>
            {!diagnosis?.result && (
              <p className="text-xs">먼저 AI 진단을 완료하세요.</p>
            )}
            {initialSelection && initialSelection.runId !== diagnosis?.id && (
              <p className="text-xs text-amber-700">
                선택한 진단 이후 새 진단이 있습니다. AI 진단 화면에서 다시
                선택하세요.
              </p>
            )}
            <ul className="max-h-[460px] overflow-auto divide-y divide-gray-100">
              {fails.map((r) => (
                <li key={r.rule_id}>
                  <label className="flex cursor-pointer gap-2 py-3 text-xs">
                    <input
                      type="checkbox"
                      aria-label={`FAIL ${r.rule_id} 선택`}
                      disabled={running}
                      checked={selectedRuleIds.includes(r.rule_id)}
                      onChange={(e) =>
                        setSelectedRuleIds((ids) =>
                          e.target.checked
                            ? [...ids, r.rule_id]
                            : ids.filter((id) => id !== r.rule_id),
                        )
                      }
                    />
                    <span>
                      <strong className="text-red-700">FAIL {r.rule_id}</strong>{" "}
                      · {r.severity}
                      <br />
                      {r.reason}
                    </span>
                  </label>
                </li>
              ))}
            </ul>
          </section>
          <section className={panel}>
            <h2 className="text-sm font-semibold">관련 Terraform 파일 지정</h2>
            <p className="text-xs text-gray-500">
              저장소 기준 상대 경로를 입력하세요. 여러 파일은 쉼표로
              구분합니다. 같은 파일의 선택 항목은 통합합니다.
            </p>
            <button className={button} onClick={previewFiles}
              disabled={running || !selected.length || !!(initialSelection && initialSelection.runId !== diagnosis?.id)}>
              Terraform 파일 자동 추천
            </button>
            {mappingPreview && previewRules === selectionKey && (
              <p className="text-xs text-gray-600">
                {mappingPreview.repository} · {mappingPreview.ref} · {mappingPreview.commit_sha.slice(0, 12)}
              </p>
            )}
            {selected.map((r) => (
              <div key={r.rule_id} className="block text-xs">
                <span className="font-semibold">{r.rule_id}</span> ·{" "}
                {r.recommendation}
                {!!r.resource_ids?.length && (
                  <span className="mt-2 block rounded-lg border border-amber-200 bg-amber-50 p-2">
                    <span className="block font-semibold">리소스별 조치 범위</span>
                    <span className="block text-amber-800">
                      이번 수정에서 제외한 리소스는 미조치로 남습니다. HTTPS 예외는 사유를 기록해 따로 표시하며 진단 결과는 PASS로 바뀌지 않습니다.
                    </span>
                    {r.resource_ids.map((id) => (
                      <span key={id} className="mt-2 block rounded border border-amber-100 bg-white p-2">
                        <span className="block font-semibold">{resourceNameKorean(r.rule_id, id)}</span>
                        <span className="block break-all font-mono text-[11px] text-gray-500">AWS ID: {id}</span>
                        <span className="mt-1 flex flex-wrap items-center gap-4">
                          <span className="inline-flex items-center gap-1">
                            <input aria-label={`${resourceNameKorean(r.rule_id, id)} 이번 수정`} type="checkbox"
                              checked={(targetResources[r.rule_id] ?? r.resource_ids ?? []).includes(id)}
                              onChange={() => {
                                const chosen = targetResources[r.rule_id] ?? r.resource_ids ?? []
                                const selecting = !chosen.includes(id)
                                setTargetResources((current) => ({ ...current, [r.rule_id]: selecting
                                  ? [...(current[r.rule_id] ?? r.resource_ids ?? []), id]
                                  : (current[r.rule_id] ?? r.resource_ids ?? []).filter((value) => value !== id) }))
                                if (!selecting || r.rule_id === "4.4") {
                                  setHttpsExceptions((current) => ({ ...current, [r.rule_id]:
                                    (current[r.rule_id] ?? []).filter((value) => value !== id) }))
                                }
                              }} />
                            이번 수정
                          </span>
                          {canMarkHttpsException(r.rule_id, id) && (
                            <span className="inline-flex items-center gap-1 text-amber-800">
                              <input aria-label={`${resourceNameKorean(r.rule_id, id)} HTTPS 예외`} type="checkbox"
                                checked={(httpsExceptions[r.rule_id] ?? []).includes(id)}
                                onChange={() => {
                                  const marking = !(httpsExceptions[r.rule_id] ?? []).includes(id)
                                  setHttpsExceptions((current) => ({ ...current, [r.rule_id]: marking
                                    ? [...(current[r.rule_id] ?? []), id]
                                    : (current[r.rule_id] ?? []).filter((value) => value !== id) }))
                                  if (marking && r.rule_id === "4.4") {
                                    setTargetResources((current) => ({ ...current, [r.rule_id]:
                                      (current[r.rule_id] ?? r.resource_ids ?? []).filter((value) => value !== id) }))
                                  }
                                  if (marking && r.rule_id === "3.9") {
                                    setTargetResources((current) => ({ ...current, [r.rule_id]:
                                      Array.from(new Set([...(current[r.rule_id] ?? r.resource_ids ?? []), id])) }))
                                  }
                                }} />
                              HTTPS 예외(미조치)
                            </span>
                          )}
                        </span>
                      </span>
                    ))}
                  </span>
                )}
                {!!httpsExceptions[r.rule_id]?.length && (
                  <span className="mt-2 block">
                    <span className="font-semibold">HTTPS 예외 사유</span>
                    <textarea value={httpsExceptionReasons[r.rule_id] ?? ""} maxLength={2000} rows={2}
                      onChange={(event) => setHttpsExceptionReasons((current) => ({
                        ...current, [r.rule_id]: event.target.value,
                      }))}
                      placeholder="예: 도메인·ACM 인증서가 준비되지 않아 HTTPS 전환을 다음 변경으로 미룹니다."
                      className="mt-1 w-full rounded-lg border border-amber-300 px-3 py-2 text-xs" />
                  </span>
                )}
                <span className="mt-2 block text-gray-600">
                  필요한 통신 요건·허용 포트·목적지 (확인된 경우 입력)
                </span>
                {r.rule_id === "3.2" && (
                  <span className="mt-1 block rounded-lg bg-amber-50 p-2 text-amber-900">
                    3.2는 누구나 접근 가능한 소스(0.0.0.0/0, ::/0)를 확인합니다.
                    이번에 제한할 보안 그룹만 선택하고, 실제 허용할 소스 CIDR 또는 보안 그룹과
                    적용할 인바운드 규칙을 운영 요건에 적어 주세요. 공개 접속이 필요한 규칙은
                    임의로 좁히지 마세요. 아래 후보의 “ID 일치”로 AWS ID와 Terraform 선언의
                    연결도 확인하세요.
                  </span>
                )}
                <textarea value={constraints[r.rule_id] ?? ""} maxLength={2000} rows={2}
                  onChange={(e) => setConstraints((current) => ({ ...current, [r.rule_id]: e.target.value }))}
                  placeholder={r.rule_id === "3.2"
                    ? "예: sg-...의 443/TCP 인바운드 소스는 확인된 사내 CIDR 10.0.0.0/8만 허용합니다."
                    : "예: 선택한 SG의 아웃바운드는 VPC CIDR의 443/TCP가 필요합니다. 확인되지 않은 포트는 추측하지 마세요."}
                  className="mt-1 w-full rounded-lg border border-gray-300 px-3 py-2 text-xs" />
                <input
                  value={paths[r.rule_id] ?? ""}
                  disabled={running}
                  onChange={(e) =>
                    setPaths((p) => ({ ...p, [r.rule_id]: e.target.value }))
                  }
                  placeholder="예: modules/network/security_groups.tf"
                  className="mt-1 w-full rounded-lg border border-gray-300 px-3 py-2 font-mono"
                />
                {mappingPreview && previewRules === selectionKey && (() => {
                  const item = mappingPreview.mapping[r.rule_id]
                  if (!item) return null
                  if (item.status === "NOT_TERRAFORM") {
                    return (
                      <span className="mt-1 block text-amber-700">
                        Terraform 조치 대상 아님: {item.reason} 선택을 해제하세요.
                      </span>
                    )
                  }
                  const chosen = splitPaths(paths[r.rule_id])
                  return (
                    <span className="mt-1 block text-gray-600">
                      {item.status === "NO_CANDIDATE"
                        ? item.reason
                        : item.status === "MATCHED"
                          ? "Terraform State에서 리소스 연결을 확인했습니다. 자동 입력된 파일을 검토하세요."
                          : "자동 입력된 파일을 검토하세요(State 연결은 확인하지 못함). 파일을 눌러 추가·제외할 수 있습니다."}
                      {!!item.unmapped_resource_ids?.length && (
                        <span className="block text-amber-700">
                          Terraform State에서 연결을 확인하지 못한 리소스: {item.unmapped_resource_ids
                            .map((id) => `${resourceNameKorean(r.rule_id, id)} (AWS ID: ${id})`).join(", ")}
                        </span>
                      )}
                      {item.candidates.map((candidate) => (
                        <button key={candidate.file_path} type="button"
                          className={`ml-2 underline ${chosen.includes(candidate.file_path) ? "font-semibold text-[#101828]" : ""}`}
                          onClick={() => toggleCandidate(r.rule_id, candidate.file_path)}>
                          {chosen.includes(candidate.file_path) ? "✓ " : "+ "}
                          {candidate.file_path}{candidate.identity_match
                            ? ` (ID 일치: ${(candidate.covered_resource_ids ?? [])
                              .map((id) => `${resourceNameKorean(r.rule_id, id)} · ${id}`).join(", ")})` : ""}
                        </button>
                      ))}
                    </span>
                  )
                })()}
              </div>
            ))}
            <button
              className={button}
              onClick={fetchSource}
              disabled={
                running ||
                !selected.length ||
                !mappingPreview || previewRules !== selectionKey ||
                selected.some((r) => !paths[r.rule_id]?.trim()) ||
                selected.some((r) => r.rule_id === "3.2" && !constraints[r.rule_id]?.trim()) ||
                selected.some((r) => !!httpsExceptions[r.rule_id]?.length && !httpsExceptionReasons[r.rule_id]?.trim()) ||
                selected.some((r) => !!r.resource_ids?.length && !(targetResources[r.rule_id] ?? r.resource_ids ?? []).length) ||
                notTerraformSelected ||
                !!(initialSelection && initialSelection.runId !== diagnosis?.id)
              }
            >
              {running ? "처리 중…" : "GitHub 원본 조회 · 새 패치 생성"}
            </button>
            {selected.some((r) => r.rule_id === "3.2" && !constraints[r.rule_id]?.trim()) && (
              <p className="text-xs text-amber-800">
                3.2의 허용 소스가 비어 있습니다. 적용할 보안 그룹과 규칙의 허용 CIDR 또는
                보안 그룹을 운영 통신 요건에 입력해야 새 패치를 만들 수 있습니다.
              </p>
            )}
            {selected.some((r) => !!httpsExceptions[r.rule_id]?.length && !httpsExceptionReasons[r.rule_id]?.trim()) && (
              <p className="text-xs text-amber-800">HTTPS 예외로 표시한 리소스의 사유를 입력하세요.</p>
            )}
          </section>
        </div>
          )}
        </div>
      )}
      <details ref={historyRef} className="rounded-2xl border border-[#E4E7EC] bg-white" aria-label="패치 이력">
        <summary className="cursor-pointer px-4 py-4 text-sm font-bold text-[#101828]">
          패치 이력 {history ? `${offset + history.patches.length}${history.patches.length === 50 ? "건 이상" : "건"}` : "불러오는 중"}
          <span className="ml-2 text-xs font-normal text-[#667085]">저장된 조치 기록과 과거 요청 보기</span>
        </summary>
        <div className="flex items-center justify-end border-t border-[#EAECF0] px-4 pt-3">
          <button
            className="text-xs underline disabled:opacity-40"
            disabled={running}
            onClick={() => perform(() => loadHistory())}
          >
            새로고침
          </button>
        </div>
        <div className="space-y-3 px-4 pb-4">
        {fix && fix.payload.audit.length > 0 && (
          <div>
            <h3 className="mb-2 text-xs font-semibold text-[#344054]">선택한 패치의 처리 기록</h3>
            <ol className="space-y-2">
              {fix.payload.audit.map((event, index) => (
                <li key={`${event.at}-${index}`} className="flex flex-wrap gap-x-3 gap-y-1 rounded-lg bg-[#F9FAFB] px-3 py-2 text-xs">
                  <time className="text-[#667085]">{formatTime(event.at)}</time>
                  <span className="font-semibold text-[#101828]">{PATCH_STATUS[event.event] ?? event.event}</span>
                  <span className="text-[#667085]">{event.actor}</span>
                  {event.note && <span className="w-full whitespace-pre-wrap text-[#475467]">{event.note}</span>}
                </li>
              ))}
            </ol>
          </div>
        )}
        {history?.patches.length === 0 && (
          <p className="text-xs text-gray-500">저장된 패치가 없습니다.</p>
        )}
        <h3 className="text-xs font-semibold text-[#344054]">과거 AI 조치 요청</h3>
        <ul className="divide-y divide-[#EAECF0] rounded-lg border border-[#EAECF0]">
          {history?.patches.map((patch) => (
            <li key={patch.id} className="flex flex-wrap items-center justify-between gap-3 px-3 py-3 text-xs">
              <div className="min-w-0">
                <p className="font-semibold text-[#101828]">{(patch.rule_ids ?? []).map((id) => `규칙 ${id}`).join(" · ") || "AI 조치 요청"}</p>
                <p className="mt-1 text-[#667085]">{formatTime(patch.created_at)} · 요청자 {patch.requested_by}</p>
                <p className={`mt-1 font-semibold ${patch.status === "REMEDIATED" ? "text-[#027A48]" : FAILED_PHASE[patch.status] !== undefined ? "text-[#B42318]" : "text-[#475467]"}`}>
                  {patch.status === "REMEDIATED" ? "✓" : FAILED_PHASE[patch.status] !== undefined ? "!" : "○"} {PATCH_STATUS[patch.status] ?? patch.status}
                  {patch.deployment_status ? ` · 배포 ${patch.deployment_status}` : ""}
                  {patch.https_exception_count ? ` · HTTPS 예외 ${patch.https_exception_count}건` : ""}
                </p>
              </div>
              <button type="button" className="cursor-pointer rounded-lg border border-[#D0D5DD] px-3 py-1.5 font-semibold text-[#344054] hover:bg-[#F9FAFB] disabled:cursor-not-allowed disabled:opacity-40" disabled={running} onClick={() => perform(async () => selectDetail(await api<PatchDetail>(`/api/ai-actions/patches/${patch.id}`), true))}>상세보기</button>
            </li>
          ))}
        </ul>
        <div className="flex gap-3 text-xs">
          <button
            disabled={running || offset === 0}
            className="disabled:opacity-40"
            onClick={() =>
              perform(async () => {
                await loadHistory(offset - 50)
                setOffset(offset - 50)
              })
            }
          >
            이전
          </button>
          <button
            disabled={running || history?.patches.length !== 50}
            className="disabled:opacity-40"
            onClick={() =>
              perform(async () => {
                await loadHistory(offset + 50)
                setOffset(offset + 50)
              })
            }
          >
            다음
          </button>
        </div>
        <button type="button" onClick={returnToStart} disabled={running} className="cursor-pointer rounded-lg border border-[#D0D5DD] px-3 py-1.5 text-xs font-semibold text-[#344054] hover:bg-[#F9FAFB] disabled:cursor-not-allowed disabled:opacity-40">
          ← AI 조치 초기 화면으로
        </button>
        </div>
      </details>
      {fix && reportOpen && (fix.payload.report || fix.payload.final_report) && (
        <div className="fixed inset-0 z-[110] flex items-center justify-center bg-[#101828]/60 p-3 sm:p-6" onMouseDown={(event) => { if (event.target === event.currentTarget) setReportOpen(false) }}>
          <div role="dialog" aria-modal="true" aria-labelledby="patch-report-title" className="flex max-h-[90vh] w-full max-w-4xl flex-col overflow-hidden rounded-2xl bg-white shadow-xl">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#EAECF0] px-5 py-4">
              <h2 id="patch-report-title" className="text-base font-bold text-[#101828]">AI 보안 조치 보고서</h2>
              <div className="flex flex-wrap items-center gap-3 text-xs">
                {fix.payload.report && <a className="font-semibold text-[#175CD3] underline" href={"/api/ai-actions/patches/" + fix.id + "/download/first"}>1차 보고서 PDF</a>}
                {fix.payload.final_report && <a className="font-semibold text-[#175CD3] underline" href={"/api/ai-actions/patches/" + fix.id + "/download/final"}>최종 보고서 PDF</a>}
                <button type="button" onClick={() => setReportOpen(false)} className="rounded-lg border border-[#D0D5DD] px-3 py-1.5 font-semibold text-[#344054]">닫기</button>
              </div>
            </div>
            <div className="space-y-4 overflow-y-auto p-5">
          {fix.payload.report && (
            <div className="space-y-3 rounded-lg border border-gray-200 p-3 text-xs">
              <h3 className="font-bold">AI 변경 보고서 · 실제 Diff 근거</h3>
              <p className="whitespace-pre-wrap">
                {fix.payload.report.summary}
              </p>
              {fix.payload.report.changes.map((c, i) => (
                <div key={i}>
                  <strong>{c.file_path}</strong>
                  <pre className="overflow-auto bg-gray-50 p-2">
                    {c.evidence}
                  </pre>
                  <p>{c.explanation}</p>
                </div>
              ))}
              <p>예상 영향: {fix.payload.report.impact}</p>
              <p>서비스 중단 가능성: {fix.payload.report.service_disruption}</p>
              <p>리소스 교체 가능성: {fix.payload.report.resource_replacement}</p>
              <h4 className="font-semibold">위험·불확실성</h4>
              <ul className="list-disc pl-4">
                {fix.payload.report.risks.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
              <h4 className="font-semibold">추가 확인사항</h4>
              <ul className="list-disc pl-4">
                {fix.payload.report.checks.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            </div>
          )}
          {fix.payload.final_report && (
            <section className="space-y-4 rounded-lg border p-4 text-sm">
              <h3 className="font-semibold text-[#101828]">
                AI 최종 변경 보고서 · {fix.payload.final_report.version}
              </h3>
              <p className="rounded-lg bg-amber-50 p-3 text-amber-900">
                {fix.payload.final_report.report_notice ??
                  "이 보고서는 배포 전 예상입니다. 실제 보안 문제 해결 여부는 배포 후 재진단으로 확인합니다."}
              </p>
              <HttpsExceptionSummary findings={fix.payload.findings} />
              <div>
                <h4 className="font-semibold">한눈에 보기</h4>
                <p className="mt-1 whitespace-pre-wrap">{fix.payload.final_report.ai_assessment.assessment}</p>
              </div>
              <div>
                <h4 className="font-semibold">무엇이 바뀌나요?</h4>
                <p className="mt-1 whitespace-pre-wrap">
                  {fix.payload.final_report.ai_assessment.change_explanation ?? fix.payload.report?.summary ?? "변경 내용을 확인할 수 없습니다."}
                </p>
                {fix.payload.final_report.change_details?.length ? (
                  <div className="mt-3 space-y-4">
                    {fix.payload.final_report.change_details.map((file) => (
                      <div key={file.file_path} className="rounded-lg border border-gray-200 p-3">
                        <h5 className="break-all font-semibold">변경 파일: {file.file_path}</h5>
                        {file.explanations.map((item, index) => (
                          <div key={index} className="mt-2">
                            <p className="whitespace-pre-wrap">{item.explanation}</p>
                            <p className="mt-1 break-all text-xs text-[#667085]">보고서 근거: <code>{item.evidence}</code></p>
                          </div>
                        ))}
                        {file.hunks.map((hunk, index) => (
                          <div key={index} className="mt-3 border-t border-gray-100 pt-3">
                            <h6 className="font-medium">변경 구간 {index + 1}</h6>
                            <div className="mt-2 grid gap-2 lg:grid-cols-2">
                              <div>
                                <p className="text-xs font-semibold text-[#475467]">변경 전 {hunk.before_lines.length === 0 && "· 새로 추가"}</p>
                                <pre className="mt-1 overflow-x-auto whitespace-pre rounded bg-red-50 p-2 text-xs">{hunk.before_lines.join("\n") || "해당 설정 없음"}</pre>
                              </div>
                              <div>
                                <p className="text-xs font-semibold text-[#475467]">변경 후 {hunk.after_lines.length === 0 && "· 삭제"}</p>
                                <pre className="mt-1 overflow-x-auto whitespace-pre rounded bg-green-50 p-2 text-xs">{hunk.after_lines.join("\n") || "해당 설정 없음"}</pre>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="mt-3 space-y-2">
                    {fix.payload.files.filter((file) => file.diff).map((file) => (
                      <div key={file.file_path} className="rounded-lg border border-gray-200 p-3">
                        <h5 className="break-all font-semibold">변경 파일: {file.file_path}</h5>
                        {fix.payload.report?.changes.filter((change) => change.file_path === file.file_path).map((change, index) => (
                          <p key={index} className="mt-1 whitespace-pre-wrap">{change.explanation}</p>
                        ))}
                        <DiffView diff={file.diff ?? ""} />
                      </div>
                    ))}
                  </div>
                )}
                {fix.payload.checks?.plan_summary?.counts && (
                  <p className="mt-2 text-[#475467]">
                    배포 계획: 새로 생성 {fix.payload.checks.plan_summary.counts.create ?? 0}개 ·
                    설정 변경 {fix.payload.checks.plan_summary.counts.update ?? 0}개 ·
                    삭제 {fix.payload.checks.plan_summary.counts.delete ?? 0}개 ·
                    교체 {fix.payload.checks.plan_summary.counts.replace ?? 0}개
                  </p>
                )}
              </div>
              <div>
                <h4 className="font-semibold">이용자와 서비스에 미칠 영향</h4>
                <p className="mt-1 whitespace-pre-wrap">
                  {fix.payload.final_report.ai_assessment.user_impact ?? fix.payload.report?.impact ?? "이용자 영향은 확인되지 않았습니다."}
                </p>
                <p className="mt-2 whitespace-pre-wrap">
                  <strong>서비스 중단 가능성:</strong> {fix.payload.final_report.ai_assessment.service_disruption ?? fix.payload.report?.service_disruption ?? "배포 전 확인이 필요합니다."}
                </p>
                <p className="mt-2 whitespace-pre-wrap">
                  <strong>리소스 교체 가능성:</strong> {fix.payload.final_report.ai_assessment.resource_replacement ?? fix.payload.report?.resource_replacement ?? "Terraform Plan 확인이 필요합니다."}
                </p>
              </div>
              <div>
                <h4 className="font-semibold">남은 위험</h4>
                <ul className="mt-1 list-disc pl-5">
                {fix.payload.final_report.ai_assessment.risks.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
                </ul>
              </div>
              <div>
                <h4 className="font-semibold">최종 승인 전에 확인할 것</h4>
                <ul className="mt-1 list-disc pl-5">
                  {(fix.payload.final_report.ai_assessment.decision_points ?? fix.payload.report?.checks ?? []).map((item, i) => (
                    <li key={i}>{item}</li>
                  ))}
                </ul>
              </div>
              <div>
                <h4 className="font-semibold">배포 후 확인할 것</h4>
                <ul className="mt-1 list-disc pl-5">
                {fix.payload.final_report.ai_assessment.post_deploy_checks.map(
                  (r, i) => (
                    <li key={i}>{r}</li>
                  ),
                )}
                </ul>
              </div>
            </section>
          )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
