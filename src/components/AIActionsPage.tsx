import { useEffect, useMemo, useState } from "react"

// AI 조치 (A단계): AI 진단 FAIL 항목 + 사람이 붙여넣은 .tf 파일 → AI 수정안 + 2차 검증 결과 표시.
// 파일 쓰기·커밋·apply 는 하지 않는다. 제안만 보여주고, 실제 반영은 사람이 수동으로 한다.

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
  status: string
  result: { results?: DiagnosisResult[] } | null
  startedAt?: string
}

interface ReviewResult {
  verdict: "APPROVE" | "REJECT" | "NEEDS_HUMAN_REVIEW"
  summary: string
  concerns: string[]
  model: string
}

interface FixResponse {
  file_path: string
  diff: string
  changed: boolean
  proposed_content: string
  review: ReviewResult | null
  message?: string
}

const VERDICT_STYLE: Record<ReviewResult["verdict"], { label: string; className: string }> = {
  APPROVE: { label: "승인", className: "bg-[#ECFDF3] text-[#067647]" },
  REJECT: { label: "반려", className: "bg-[#FEF3F2] text-[#B42318]" },
  NEEDS_HUMAN_REVIEW: { label: "사람 검토 필요", className: "bg-[#FFFAEB] text-[#B54708]" },
}

async function fetchJson<T>(url: string, init: RequestInit, onUnauthorized: () => void): Promise<T> {
  const res = await fetch(url, { credentials: "include", ...init })
  if (res.status === 401) {
    onUnauthorized()
    throw new Error("로그인이 필요합니다.")
  }
  const body = await res.json().catch(() => null)
  if (!res.ok) throw new Error(body?.message || `요청 실패 (HTTP ${res.status})`)
  return body as T
}

function DiffView({ diff }: { diff: string }) {
  return (
    <pre className="max-h-[320px] overflow-auto rounded-lg border border-[#E4E7EC] bg-[#0C111D] p-3 text-[11.5px] leading-relaxed">
      {diff.split("\n").map((line, i) => {
        let color = "#C2C9D6"
        if (line.startsWith("+") && !line.startsWith("+++")) color = "#6CE9A6"
        else if (line.startsWith("-") && !line.startsWith("---")) color = "#FDA29B"
        else if (line.startsWith("@@")) color = "#84CAFF"
        return (
          <div key={i} style={{ color }} className="whitespace-pre-wrap break-all font-mono">
            {line || " "}
          </div>
        )
      })}
    </pre>
  )
}

export function AIActionsPage({ onUnauthorized }: { onUnauthorized: () => void }) {
  const [diagnosis, setDiagnosis] = useState<DiagnosisStatus | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null)
  const [filePath, setFilePath] = useState("")
  const [fileContent, setFileContent] = useState("")
  const [running, setRunning] = useState(false)
  const [fix, setFix] = useState<FixResponse | null>(null)
  const [runError, setRunError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    fetchJson<DiagnosisStatus>("/api/ai-diagnosis/status", { method: "GET" }, onUnauthorized)
      .then((d) => !cancelled && setDiagnosis(d))
      .catch((e: Error) => !cancelled && setLoadError(e.message))
    return () => {
      cancelled = true
    }
  }, [onUnauthorized])

  const fails = useMemo(
    () => (diagnosis?.result?.results ?? []).filter((r) => r.status === "FAIL"),
    [diagnosis],
  )
  const selected = fails.find((r) => r.rule_id === selectedRuleId) ?? null

  const runFix = async () => {
    if (!selected) return
    setRunning(true)
    setRunError(null)
    setFix(null)
    try {
      const data = await fetchJson<FixResponse>(
        "/api/ai-actions/terraform-fix",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ finding: selected, file_path: filePath.trim(), file_content: fileContent }),
        },
        onUnauthorized,
      )
      setFix(data)
    } catch (e) {
      setRunError(e instanceof Error ? e.message : "AI 조치안 생성에 실패했습니다.")
    } finally {
      setRunning(false)
    }
  }

  return (
    <div className="min-h-full space-y-3 p-4">
      <div>
        <p className="text-[18px] font-bold text-[#101828]">AI 조치</p>
        <p className="text-[11.5px] text-[#667085]">
          AI 진단에서 실패(FAIL)한 항목의 Terraform 수정안을 AI가 제안하고, 다른 모델이 2차로 검증합니다.
          제안일 뿐이며 실제 반영은 검토 후 직접 수행하세요.
        </p>
      </div>

      {loadError ? (
        <p className="rounded-lg bg-[#FEF3F2] px-3 py-2 text-[12px] text-[#B42318]">{loadError}</p>
      ) : !diagnosis ? (
        <p className="text-[12px] text-[#667085]">불러오는 중...</p>
      ) : fails.length === 0 ? (
        <p className="rounded-lg bg-[#F9FAFB] px-3 py-4 text-[12px] text-[#667085]">
          {diagnosis.result
            ? "실패(FAIL)한 진단 항목이 없습니다."
            : "완료된 AI 진단 결과가 없습니다. 먼저 'AI 진단'을 실행해 주세요."}
        </p>
      ) : (
        <div className="grid gap-3 lg:grid-cols-[minmax(280px,340px)_1fr]">
          {/* 왼쪽: FAIL 항목 목록 */}
          <section className="rounded-2xl border border-[#E4E7EC] bg-white">
            <p className="border-b border-[#EAECF0] px-3 py-2 text-[12px] font-semibold text-[#344054]">
              실패 항목 {fails.length}개
            </p>
            <ul className="max-h-[560px] divide-y divide-[#F2F4F7] overflow-y-auto">
              {fails.map((r) => (
                <li key={r.rule_id}>
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedRuleId(r.rule_id)
                      setFix(null)
                      setRunError(null)
                    }}
                    className={`w-full px-3 py-2.5 text-left hover:bg-[#F9FAFB] ${
                      selectedRuleId === r.rule_id ? "bg-[#F2F4F7]" : ""
                    }`}
                  >
                    <div className="flex items-center gap-1.5">
                      <span className="rounded bg-[#FEF3F2] px-1.5 text-[10px] font-bold text-[#B42318]">FAIL</span>
                      <span className="text-[12px] font-semibold text-[#101828]">{r.rule_id}</span>
                      <span className="ml-auto text-[10px] text-[#98A2B3]">{r.severity}</span>
                    </div>
                    {r.reason && <p className="mt-1 line-clamp-2 text-[10.5px] text-[#667085]">{r.reason}</p>}
                  </button>
                </li>
              ))}
            </ul>
          </section>

          {/* 오른쪽: 선택 항목 + tf 붙여넣기 + 결과 */}
          <section className="space-y-3">
            {!selected ? (
              <p className="rounded-2xl border border-[#E4E7EC] bg-white p-6 text-[12px] text-[#667085]">
                왼쪽에서 조치할 항목을 선택하세요.
              </p>
            ) : (
              <>
                <div className="rounded-2xl border border-[#E4E7EC] bg-white p-4">
                  <p className="text-[13px] font-bold text-[#101828]">{selected.rule_id} · {selected.severity}</p>
                  {selected.reason && <p className="mt-1 text-[11.5px] text-[#475467]">{selected.reason}</p>}
                  {selected.recommendation && (
                    <p className="mt-2 rounded-lg bg-[#F9FAFB] px-3 py-2 text-[11.5px] text-[#344054]">
                      권장 조치: {selected.recommendation}
                    </p>
                  )}
                  {selected.resource_ids && selected.resource_ids.length > 0 && (
                    <p className="mt-1 text-[10.5px] text-[#667085]">대상: {selected.resource_ids.join(", ")}</p>
                  )}
                </div>

                <div className="rounded-2xl border border-[#E4E7EC] bg-white p-4 space-y-2">
                  <input
                    value={filePath}
                    onChange={(e) => setFilePath(e.target.value)}
                    placeholder="대상 파일명 (예: iam.tf)"
                    className="w-full rounded-lg border border-[#D0D5DD] px-3 py-1.5 text-[12px] outline-none focus:border-[#101828]"
                  />
                  <textarea
                    value={fileContent}
                    onChange={(e) => setFileContent(e.target.value)}
                    placeholder="Terraform(.tf) 파일 내용을 붙여넣으세요"
                    rows={10}
                    className="w-full rounded-lg border border-[#D0D5DD] px-3 py-2 font-mono text-[11.5px] outline-none focus:border-[#101828]"
                  />
                  <button
                    type="button"
                    onClick={runFix}
                    disabled={running || !filePath.trim() || !fileContent.trim()}
                    className="rounded-lg bg-[#101828] px-4 py-2 text-[12px] font-semibold text-white disabled:opacity-40"
                  >
                    {running ? "AI가 분석 중..." : "AI 조치안 생성"}
                  </button>
                  {runError && <p className="text-[11.5px] text-[#B42318]">{runError}</p>}
                </div>

                {fix && (
                  <div className="rounded-2xl border border-[#E4E7EC] bg-white p-4 space-y-3">
                    {!fix.changed ? (
                      <p className="rounded-lg bg-[#FFFAEB] px-3 py-2 text-[12px] text-[#B54708]">
                        {fix.message || "AI가 변경이 필요하지 않다고 판단했습니다."}
                      </p>
                    ) : (
                      <>
                        {fix.review && (
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="text-[12px] font-semibold text-[#344054]">2차 검증</span>
                            <span
                              className={`rounded-full px-2 py-0.5 text-[11px] font-bold ${VERDICT_STYLE[fix.review.verdict].className}`}
                            >
                              {VERDICT_STYLE[fix.review.verdict].label}
                            </span>
                            <span className="text-[10.5px] text-[#98A2B3]">{fix.review.model}</span>
                          </div>
                        )}
                        {fix.review?.summary && (
                          <p className="text-[11.5px] text-[#475467]">{fix.review.summary}</p>
                        )}
                        {fix.review && fix.review.concerns.length > 0 && (
                          <ul className="list-disc space-y-0.5 pl-5 text-[11.5px] text-[#B42318]">
                            {fix.review.concerns.map((c, i) => (
                              <li key={i}>{c}</li>
                            ))}
                          </ul>
                        )}
                        <div>
                          <p className="mb-1 text-[12px] font-semibold text-[#344054]">제안된 변경 ({fix.file_path})</p>
                          <DiffView diff={fix.diff} />
                        </div>
                        <p className="rounded-lg bg-[#FFFAEB] px-3 py-2 text-[10.5px] text-[#B54708]">
                          ⚠ AI가 만든 제안입니다. 그대로 신뢰하지 말고, 검토 후 직접 적용하세요. 이 화면은 파일을 수정하거나 배포하지 않습니다.
                        </p>
                      </>
                    )}
                  </div>
                )}
              </>
            )}
          </section>
        </div>
      )}
    </div>
  )
}
