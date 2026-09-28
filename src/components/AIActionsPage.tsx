import { useEffect, useMemo, useState } from "react"

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
  first_approval?: boolean
  ai_verdict?: string | null
  checks_status?: string
  final_approval?: boolean
  deployment_status?: string | null
}
interface PatchDetail extends PatchSummary {
  content_hash?: string
  approval_hash?: string
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
    error?: { message: string }
    ai_review?: {
      verdict: string
      summary: string
      concerns: string[]
      model: string
    } | null
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
      ai_assessment: {
        assessment: string
        risks: string[]
        post_deploy_checks: string[]
      }
    } | null
    first_approval?: { actor: string; at: string } | null
    final_approval?: { actor: string; at: string } | null
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
    status: "MATCHED" | "MANUAL_REVIEW"
    reason: string
    candidates: { file_path: string; identity_match: boolean; resources: { type: string; name: string }[] }[]
  }>
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
  AI_REVIEW_FAILED: "2차 AI 검증 오류",
  READY_FOR_PR: "PR 생성 대기",
  CHECKS_RUNNING: "GitHub 검사 중",
  CHECKS_FAILED: "GitHub 검사 실패",
  FINAL_REPORTING: "최종 보고서 작성 중",
  FINAL_REPORT_FAILED: "최종 보고서 작성 오류",
  AWAITING_FINAL_APPROVAL: "최종 승인 대기",
  FINAL_APPROVED: "최종 승인 완료",
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
    throw new Error(body?.message || `요청 실패 (HTTP ${res.status})`)
  return body as T
}

function DiffView({ diff }: { diff: string }) {
  return (
    <pre className="max-h-[320px] overflow-auto rounded-lg border border-[#E4E7EC] bg-[#0C111D] p-3 text-[11.5px] leading-relaxed">
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

export function AIActionsPage({
  onUnauthorized,
  initialSelection,
  initialPatchId,
}: {
  onUnauthorized: () => void
  initialSelection?: {
    runId: number
    ruleIds: string[]
  } | null
  initialPatchId?: string | null
}) {
  const [diagnosis, setDiagnosis] = useState<DiagnosisStatus | null>(null)
  const [selectedRuleIds, setSelectedRuleIds] = useState<string[]>(
    initialSelection?.ruleIds ?? [],
  )
  const [paths, setPaths] = useState<Record<string, string>>({})
  const [mappingPreview, setMappingPreview] = useState<MappingPreview | null>(null)
  const [previewRules, setPreviewRules] = useState("")
  const [running, setRunning] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [history, setHistory] = useState<HistoryResponse | null>(null)
  const [offset, setOffset] = useState(0)
  const [fix, setFix] = useState<PatchDetail | null>(null)
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
          const data = await api<PatchDetail>(
            `/api/ai-actions/patches/${fix.id}${route ? `/${route}` : ""}`,
            route ? {} : undefined,
          )
          if (!cancelled) {
            setFix(data)
            if (!active.includes(data.status)) await loadHistory()
          }
        } catch (e) {
          if (!cancelled)
            setError(e instanceof Error ? e.message : "진행 상태 조회 실패")
        } finally {
          pending = false
        }
      },
      ["CHECKS_RUNNING", "FINAL_APPROVED", "DEPLOYING"].includes(fix.status) ? 10000 : 2500,
    )
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [fix?.id, fix?.status])
  const selected = fails.filter((r) => selectedRuleIds.includes(r.rule_id))
  const selectionKey = selected.map((r) => r.rule_id).sort().join(",")
  const selectDetail = (data: PatchDetail) => {
    setFix(data)
    setReviewed(false)
    setNote("")
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
      setPaths(Object.fromEntries(selected.map((r) => [
        r.rule_id, result.mapping[r.rule_id]?.candidates[0]?.file_path ?? "",
      ])))
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
  const button =
    "rounded-lg bg-[#101828] px-4 py-2 text-xs font-semibold text-white disabled:opacity-40"
  const panel = "rounded-2xl border border-[#E4E7EC] bg-white p-4 space-y-3"
  return (
    <div className="min-h-full space-y-4 p-4">
      <div>
        <h1 className="text-lg font-bold text-[#101828]">AI 조치</h1>
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
      {history?.can_create && (
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
              구분합니다(최대 5개). 같은 파일의 선택 항목은 통합합니다.
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
              <label key={r.rule_id} className="block text-xs">
                <span className="font-semibold">{r.rule_id}</span> ·{" "}
                {r.recommendation}
                <input
                  value={paths[r.rule_id] ?? ""}
                  disabled={running}
                  onChange={(e) =>
                    setPaths((p) => ({ ...p, [r.rule_id]: e.target.value }))
                  }
                  placeholder="예: modules/network/security_groups.tf"
                  className="mt-1 w-full rounded-lg border border-gray-300 px-3 py-2 font-mono"
                />
                {mappingPreview && previewRules === selectionKey && (
                  <span className="mt-1 block text-gray-600">
                    {mappingPreview.mapping[r.rule_id]?.status === "MANUAL_REVIEW"
                      ? "수동 확인 필요: Terraform State에서 리소스 연결을 확인하지 못했습니다."
                      : "Terraform State에서 리소스 연결을 확인했습니다. 파일을 검토하세요."}
                    {mappingPreview.mapping[r.rule_id]?.candidates.map((candidate) => (
                      <button key={candidate.file_path} type="button"
                        className="ml-2 underline" onClick={() => setPaths((p) => ({ ...p, [r.rule_id]: candidate.file_path }))}>
                        {candidate.file_path}{candidate.identity_match ? " (ID 일치)" : ""}
                      </button>
                    ))}
                  </span>
                )}
              </label>
            ))}
            <button
              className={button}
              onClick={fetchSource}
              disabled={
                running ||
                !selected.length ||
                !mappingPreview || previewRules !== selectionKey ||
                selected.some((r) => !paths[r.rule_id]?.trim()) ||
                !!(initialSelection && initialSelection.runId !== diagnosis?.id)
              }
            >
              {running ? "처리 중…" : "GitHub 원본 조회 · 새 패치 생성"}
            </button>
          </section>
        </div>
      )}
      <section className={panel}>
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold">패치 이력</h2>
          <button
            className="text-xs underline disabled:opacity-40"
            disabled={running}
            onClick={() => perform(() => loadHistory())}
          >
            새로고침
          </button>
        </div>
        {history?.patches.length === 0 && (
          <p className="text-xs text-gray-500">저장된 패치가 없습니다.</p>
        )}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr>
                <th className="p-2">패치 ID</th>
                <th>상태</th>
                <th>FAIL</th>
                <th>1차 승인</th>
                <th>2차 AI</th>
                <th>GitHub 검사</th>
                <th>최종 승인</th>
                <th>배포</th>
                <th>요청자</th>
                <th>생성일</th>
              </tr>
            </thead>
            <tbody>
              {history?.patches.map((p) => (
                <tr key={p.id} className="border-t border-gray-100">
                  <td className="p-2">
                    <button
                      className="font-mono underline disabled:opacity-40"
                      disabled={running}
                      onClick={() =>
                        perform(async () =>
                          selectDetail(
                            await api<PatchDetail>(
                              `/api/ai-actions/patches/${p.id}`,
                            ),
                          ),
                        )
                      }
                    >
                      {p.id}
                    </button>
                  </td>
                  <td>{PATCH_STATUS[p.status] ?? p.status}</td>
                  <td>{p.rule_ids?.join(", ") ?? "-"}</td>
                  <td>{p.first_approval ? "완료" : "-"}</td>
                  <td>{p.ai_verdict ?? "-"}</td>
                  <td>{p.checks_status ?? "-"}</td>
                  <td>{p.final_approval ? "완료" : "-"}</td>
                  <td>{p.deployment_status ?? "-"}</td>
                  <td>{p.requested_by}</td>
                  <td>{p.created_at}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
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
      </section>
      {fix && (
        <section className={panel} aria-label="패치 상세">
          <h2 className="text-sm font-bold">
            패치 상세 · {PATCH_STATUS[fix.status] ?? fix.status}
          </h2>
          <p className="break-all font-mono text-xs">{fix.id}</p>
          <p className="text-xs">
            진단 #{fix.diagnosis_run_id} · FAIL{" "}
            {fix.payload.findings.map((f) => f.rule_id).join(", ")}
          </p>
          {fix.payload.source && (
            <p className="break-all font-mono text-xs text-gray-500">
              {fix.payload.source.repository} · {fix.payload.source.ref} ·{" "}
              {fix.payload.source.commit_sha}
            </p>
          )}
          {fix.payload.error && (
            <p role="alert" className="text-xs text-red-700">
              {fix.payload.error.message} 이 패치는 이력에 보존됩니다. 새 패치로
              다시 요청하세요.
            </p>
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
          {history?.can_create && fix.status === "SOURCE_READY" && (
            <button className={button} onClick={runFix} disabled={running}>
              {running ? "AI 생성 중…" : "1차 AI 통합 수정안 · 보고서 생성"}
            </button>
          )}
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
          {fix.status === "AWAITING_FIRST_APPROVAL" &&
            (history?.can_approve ? (
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
                    사람의 1차 승인
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
                  1차 승인은 배포 승인이 아닙니다. 이후 2차 AI가 변경 내용을
                  검증합니다.
                </p>
              </div>
            ) : (
              <p className="text-xs text-amber-700">
                승인자 계정으로 코드·보고서를 검토한 뒤 1차 승인 또는 반려할 수
                있습니다.
              </p>
            ))}
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
          {fix.status === "FIRST_APPROVED" && history?.can_create && (
            <button
              className={button}
              disabled={running}
              onClick={() => step("ai-review")}
            >
              승인된 코드 2차 AI 검증
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
            </section>
          )}
          {fix.status === "READY_FOR_PR" && history?.can_create && (
            <button
              className={button}
              disabled={running}
              onClick={() => step("publish")}
            >
              독립 브랜치 · PR 생성
            </button>
          )}
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
                    {result.at ? ` · ${result.at}` : ""}
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
          {fix.payload.final_report && (
            <section className="rounded-lg border p-3 text-xs space-y-2">
              <h3 className="font-semibold">
                AI 최종 변경 보고서 · {fix.payload.final_report.version}
              </h3>
              <p>{fix.payload.final_report.ai_assessment.assessment}</p>
              <p className="font-semibold">남은 위험</p>
              <ul className="list-disc pl-4">
                {fix.payload.final_report.ai_assessment.risks.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
              <p className="font-semibold">배포 후 확인</p>
              <ul className="list-disc pl-4">
                {fix.payload.final_report.ai_assessment.post_deploy_checks.map(
                  (r, i) => (
                    <li key={i}>{r}</li>
                  ),
                )}
              </ul>
            </section>
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
                    최종 승인
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
            <p className="text-xs text-gray-600">승인된 패치의 배포 작업을 기다리는 중입니다.</p>
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
          <h3 className="text-xs font-semibold">처리 기록</h3>
          <ul className="space-y-1 text-xs text-gray-600">
            {fix.payload.audit.map((event, i) => (
              <li key={i}>
                {event.at} · {event.actor} ·{" "}
                {PATCH_STATUS[event.event] ?? event.event}
                {event.note ? ` · ${event.note}` : ""}
              </li>
            ))}
          </ul>
          <p className="text-xs text-gray-500">
            코드가 변경되면 새 패치를 생성하여 보고서·승인을 다시 받아야 합니다.
          </p>
        </section>
      )}
    </div>
  )
}
