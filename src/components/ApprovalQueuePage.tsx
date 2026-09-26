import { useEffect, useState } from "react"
import { eventDisplayTitle } from "../services/eventAnalysis"

interface ApprovalRequestItem {
  id: number
  eventId: string
  eventTitle: string | null
  eventScenarioType: string | null
  eventSeverity: string | null
  eventAsset: string | null
  eventStatus: string | null
  actionType: string | null
  note: string | null
  requestType: "auto" | "manual"
  status: "대기" | "승인" | "반려"
  requestedBy: string | null
  reviewedBy: string | null
  rejectReason: string | null
  requestedAt: string | null
  reviewedAt: string | null
  needsManualCompletion: boolean
}

export function ApprovalEventTitle({
  title,
  scenarioType,
  eventId,
}: {
  title: string | null
  scenarioType: string | null
  eventId: string
}) {
  return (
    <p className="text-[12px] font-bold text-[#101828]">
      {title ? eventDisplayTitle({ title, scenarioType: scenarioType ?? undefined }) : eventId}
    </p>
  )
}

const SEVERITY_STYLE: Record<string, string> = {
  Critical: "bg-[#FEF3F2] text-[#B42318]",
  High: "bg-[#FFF4ED] text-[#B93815]",
  Medium: "bg-[#FFFAEB] text-[#B54708]",
  Low: "bg-[#EFF8FF] text-[#175CD3]",
  Info: "bg-[#F2F4F7] text-[#667085]",
}

async function postApprove(id: number) {
  const response = await fetch(`/api/approval-requests/${id}/approve`, {
    method: "POST",
    credentials: "include",
  })
  const result = await response.json()
  if (!response.ok || result.success !== true) {
    throw new Error(result.message || "승인 처리에 실패했습니다.")
  }
}

async function postReject(id: number, reason: string) {
  const response = await fetch(`/api/approval-requests/${id}/reject`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reason }),
  })
  const result = await response.json()
  if (!response.ok || result.success !== true) {
    throw new Error(result.message || "반려 처리에 실패했습니다.")
  }
}

async function postComplete(id: number) {
  const response = await fetch(`/api/approval-requests/${id}/complete`, {
    method: "POST",
    credentials: "include",
  })
  const result = await response.json()
  if (!response.ok || result.success !== true) {
    throw new Error(result.message || "완료 처리에 실패했습니다.")
  }
}

// 요청 현황 목록만 담당한다 - "승인 관리" 페이지(승인자 전용, 전체 화면)와
// "보안 이벤트 > 승인요청" 탭(관리자가 보낸 요청 추적용) 둘 다 이걸 그대로
// 재사용한다. 승인/반려 버튼과 선택 체크박스는 role이 승인자일 때만 뜬다.
export function ApprovalRequestList({
  role,
  onUnauthorized,
  compact = false,
}: {
  role: string
  onUnauthorized: () => void
  compact?: boolean
}) {
  const [requests, setRequests] = useState<ApprovalRequestItem[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [busyId, setBusyId] = useState<number | null>(null)
  const [bulkBusy, setBulkBusy] = useState(false)
  const [rejectTargetId, setRejectTargetId] = useState<number | null>(null)
  const [rejectReason, setRejectReason] = useState("")
  const [showHistory, setShowHistory] = useState(false)
  const [checkedIds, setCheckedIds] = useState<Set<number>>(new Set())
  const [bulkRejectOpen, setBulkRejectOpen] = useState(false)
  const [bulkRejectReason, setBulkRejectReason] = useState("")

  const isApprover = role === "승인자"
  const isAdmin = role === "관리자"
  const pendingRequests = requests.filter((r) => r.status === "대기")
  const busy = busyId !== null || bulkBusy

  const load = async () => {
    try {
      const params = showHistory ? "" : "?status=대기"
      const response = await fetch(`/api/approval-requests${params}`, {
        credentials: "include",
      })
      if (response.status === 401) {
        onUnauthorized()
        return
      }
      if (!response.ok) {
        setLoadError("승인 요청 목록을 불러오지 못했습니다.")
        return
      }
      const data = (await response.json()) as { requests: ApprovalRequestItem[] }
      setLoadError(null)
      setRequests(data.requests ?? [])
    } catch {
      setLoadError("승인 요청 목록을 불러오지 못했습니다.")
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    setLoading(true)
    void load()
    const id = window.setInterval(load, 15000)
    return () => window.clearInterval(id)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [showHistory])

  const toggleChecked = (id: number) => {
    setCheckedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const approve = async (id: number) => {
    if (busy) return
    setBusyId(id)
    try {
      await postApprove(id)
      await load()
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : "승인 처리에 실패했습니다.")
    } finally {
      setBusyId(null)
    }
  }

  const reject = async (id: number) => {
    if (busy) return
    setBusyId(id)
    try {
      await postReject(id, rejectReason)
      setRejectTargetId(null)
      setRejectReason("")
      await load()
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : "반려 처리에 실패했습니다.")
    } finally {
      setBusyId(null)
    }
  }

  const complete = async (id: number) => {
    if (busy) return
    setBusyId(id)
    try {
      await postComplete(id)
      await load()
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : "완료 처리에 실패했습니다.")
    } finally {
      setBusyId(null)
    }
  }

  const bulkApprove = async () => {
    if (busy || checkedIds.size === 0) return
    setBulkBusy(true)
    try {
      const ids = [...checkedIds]
      const results = await Promise.allSettled(ids.map((id) => postApprove(id)))
      const failed = results.filter((r) => r.status === "rejected").length
      setCheckedIds(new Set())
      await load()
      if (failed > 0) {
        setLoadError(`${ids.length - failed}건 승인 완료, ${failed}건 실패했습니다.`)
      }
    } finally {
      setBulkBusy(false)
    }
  }

  const bulkReject = async () => {
    if (busy || checkedIds.size === 0) return
    setBulkBusy(true)
    try {
      const ids = [...checkedIds]
      const results = await Promise.allSettled(ids.map((id) => postReject(id, bulkRejectReason)))
      const failed = results.filter((r) => r.status === "rejected").length
      setCheckedIds(new Set())
      setBulkRejectOpen(false)
      setBulkRejectReason("")
      await load()
      if (failed > 0) {
        setLoadError(`${ids.length - failed}건 반려 완료, ${failed}건 실패했습니다.`)
      }
    } finally {
      setBulkBusy(false)
    }
  }

  return (
    <div className={compact ? "space-y-2" : "space-y-3"}>
      <div className="flex items-center justify-between gap-3 flex-wrap">
        {!compact && (
          <p className="text-[11px] text-[#667085]">
            관리자가 보낸 수동/자동 조치 요청을 승인하거나 반려합니다.
            {!isApprover && " (현재 계정은 승인자가 아니라 조회만 가능합니다.)"}
          </p>
        )}
        <div className="inline-flex rounded-xl border border-[#D0D5DD] bg-white p-1 ml-auto">
          {[
            [false, "대기 중"],
            [true, "전체 이력"],
          ].map(([value, label]) => (
            <button
              key={label as string}
              onClick={() => {
                setShowHistory(value as boolean)
                setCheckedIds(new Set())
              }}
              className={`text-[11px] font-semibold px-3 py-1.5 rounded-lg transition-colors ${
                showHistory === value
                  ? "bg-[#101828] text-white shadow-sm"
                  : "text-[#475467] hover:bg-[#F2F4F7]"
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {isApprover && pendingRequests.length > 0 && (
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <label className="flex items-center gap-1.5 cursor-pointer">
            <input
              type="checkbox"
              checked={pendingRequests.every((r) => checkedIds.has(r.id))}
              onChange={(e) =>
                setCheckedIds(
                  e.target.checked ? new Set(pendingRequests.map((r) => r.id)) : new Set(),
                )
              }
              className="h-3.5 w-3.5 rounded border-[#D0D5DD] accent-[#111111]"
            />
            <span className="text-[11px] font-semibold text-[#344054]">
              전체 선택 (대기 중 {pendingRequests.length}건)
            </span>
          </label>
          {checkedIds.size > 0 && (
            <div className="flex gap-1.5">
              <button
                onClick={bulkApprove}
                disabled={busy}
                className="text-[11px] font-bold text-white bg-[#101828] hover:bg-[#1D2939] disabled:opacity-40 rounded-lg px-3 py-1.5 transition-colors"
              >
                선택한 {checkedIds.size}건 일괄 승인
              </button>
              <button
                onClick={() => setBulkRejectOpen(true)}
                disabled={busy}
                className="text-[11px] font-bold text-[#B42318] bg-white ring-1 ring-[#FECDCA] hover:bg-[#FEF3F2] disabled:opacity-40 rounded-lg px-3 py-1.5 transition-colors"
              >
                선택한 {checkedIds.size}건 일괄 반려
              </button>
            </div>
          )}
        </div>
      )}

      {bulkRejectOpen && (
        <div className="flex gap-1.5 rounded-lg bg-[#FEF3F2] ring-1 ring-[#FECDCA] px-2.5 py-2">
          <input
            autoFocus
            value={bulkRejectReason}
            onChange={(e) => setBulkRejectReason(e.target.value)}
            placeholder={`반려 사유(선택) - 선택한 ${checkedIds.size}건 전체에 적용됩니다`}
            className="flex-1 text-[11px] rounded-lg border border-[#D0D5DD] px-2.5 py-1.5 outline-none focus:border-[#101828] bg-white"
          />
          <button
            onClick={bulkReject}
            disabled={busy}
            className="text-[11px] font-bold text-white bg-[#B42318] hover:bg-[#912018] disabled:opacity-40 rounded-lg px-3 py-1.5 transition-colors"
          >
            반려 확정
          </button>
          <button
            onClick={() => {
              setBulkRejectOpen(false)
              setBulkRejectReason("")
            }}
            className="text-[11px] text-[#475467] hover:bg-[#F2F4F7] rounded-lg px-3 py-1.5 transition-colors"
          >
            취소
          </button>
        </div>
      )}

      {loadError && (
        <p className="text-[11px] text-[#B42318] bg-[#FEF3F2] ring-1 ring-[#FECDCA] rounded-lg px-3 py-2">
          {loadError}
        </p>
      )}

      {loading ? (
        <div className="flex items-center justify-center h-24 text-[#98A2B3]">
          <p className="text-xs font-medium">불러오는 중...</p>
        </div>
      ) : requests.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-24 text-[#98A2B3]">
          <p className="text-xs font-medium">
            {showHistory ? "요청 이력이 없습니다." : "대기 중인 승인 요청이 없습니다."}
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {requests.map((req) => (
            <div
              key={req.id}
              className="rounded-xl border border-[#EAECF0] bg-white p-3.5"
            >
              <div className="flex items-start justify-between gap-3 flex-wrap">
                <div className="flex items-start gap-2">
                  {isApprover && req.status === "대기" && (
                    <input
                      type="checkbox"
                      checked={checkedIds.has(req.id)}
                      onChange={() => toggleChecked(req.id)}
                      className="h-3.5 w-3.5 mt-0.5 rounded border-[#D0D5DD] accent-[#111111] flex-shrink-0"
                    />
                  )}
                  <div>
                    <div className="flex items-center gap-1.5 flex-wrap mb-1">
                      {req.eventSeverity && (
                        <span
                          className={`text-[9px] font-bold px-1.5 py-0.5 rounded-full ${
                            SEVERITY_STYLE[req.eventSeverity] ?? "bg-[#F2F4F7] text-[#667085]"
                          }`}
                        >
                          {req.eventSeverity}
                        </span>
                      )}
                      <span className="text-[9px] font-semibold px-1.5 py-0.5 rounded-full bg-[#F2F4F7] text-[#475467]">
                        {req.requestType === "auto" ? "자동 조치" : "수동 조치"}
                      </span>
                      <span
                        className={`text-[9px] font-bold px-1.5 py-0.5 rounded-full ${
                          req.status === "대기"
                            ? "bg-[#FFFAEB] text-[#B54708]"
                            : req.status === "승인"
                              ? "bg-[#ECFDF3] text-[#067647]"
                              : "bg-[#FEF3F2] text-[#B42318]"
                        }`}
                      >
                        {req.status}
                      </span>
                    </div>
                    <ApprovalEventTitle
                      title={req.eventTitle}
                      scenarioType={req.eventScenarioType}
                      eventId={req.eventId}
                    />
                    <p className="text-[10px] text-[#667085] mt-0.5">
                      {req.eventAsset ?? "-"} · 요청자 {req.requestedBy ?? "-"} · {req.requestedAt}
                    </p>
                    {req.note && (
                      <p className="text-[10px] text-[#344054] mt-1 bg-[#F9FAFB] rounded-lg px-2 py-1.5 whitespace-pre-wrap">
                        <span className="font-semibold text-[#667085]">수동 조치 계획</span>{" "}
                        {req.note}
                      </p>
                    )}
                    {req.status !== "대기" && (
                      <p className="text-[10px] text-[#667085] mt-0.5">
                        처리자 {req.reviewedBy ?? "-"} · {req.reviewedAt}
                        {req.rejectReason && ` · 사유: ${req.rejectReason}`}
                      </p>
                    )}
                  </div>
                </div>

                {req.status === "대기" && isApprover && (
                  <div className="flex gap-1.5 flex-shrink-0">
                    <button
                      onClick={() => approve(req.id)}
                      disabled={busy}
                      className="text-[11px] font-bold text-white bg-[#101828] hover:bg-[#1D2939] disabled:opacity-40 rounded-lg px-3 py-1.5 transition-colors"
                    >
                      승인
                    </button>
                    <button
                      onClick={() => setRejectTargetId(req.id)}
                      disabled={busy}
                      className="text-[11px] font-bold text-[#B42318] bg-white ring-1 ring-[#FECDCA] hover:bg-[#FEF3F2] disabled:opacity-40 rounded-lg px-3 py-1.5 transition-colors"
                    >
                      반려
                    </button>
                  </div>
                )}

                {req.needsManualCompletion && isAdmin && (
                  <button
                    onClick={() => complete(req.id)}
                    disabled={busy}
                    className="text-[11px] font-bold text-white bg-[#067647] hover:bg-[#05603A] disabled:opacity-40 rounded-lg px-3 py-1.5 transition-colors flex-shrink-0"
                  >
                    수동 조치 완료 처리
                  </button>
                )}
              </div>

              {rejectTargetId === req.id && (
                <div className="mt-2.5 pt-2.5 border-t border-[#F2F4F7] flex gap-1.5">
                  <input
                    autoFocus
                    value={rejectReason}
                    onChange={(e) => setRejectReason(e.target.value)}
                    placeholder="반려 사유(선택)"
                    className="flex-1 text-[11px] rounded-lg border border-[#D0D5DD] px-2.5 py-1.5 outline-none focus:border-[#101828]"
                  />
                  <button
                    onClick={() => reject(req.id)}
                    disabled={busy}
                    className="text-[11px] font-bold text-white bg-[#B42318] hover:bg-[#912018] disabled:opacity-40 rounded-lg px-3 py-1.5 transition-colors"
                  >
                    반려 확정
                  </button>
                  <button
                    onClick={() => {
                      setRejectTargetId(null)
                      setRejectReason("")
                    }}
                    className="text-[11px] text-[#475467] hover:bg-[#F2F4F7] rounded-lg px-3 py-1.5 transition-colors"
                  >
                    취소
                  </button>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export function ApprovalQueuePage({
  role,
  onUnauthorized,
}: {
  role: string
  onUnauthorized: () => void
}) {
  return (
    <div className="min-h-full p-4 space-y-3">
      <div>
        <p className="text-[18px] font-bold text-[#101828]">승인 관리</p>
      </div>
      <ApprovalRequestList role={role} onUnauthorized={onUnauthorized} />
    </div>
  )
}
