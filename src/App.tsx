import { useEffect, useMemo, useState } from "react"
import { ArchitectureMap } from "./components/architecture/ArchitectureMap"
import { AttackLabPage } from "./components/attack-lab/AttackLabPage"
import { LoginPage } from "./components/auth/LoginPage"
import { SecurityChatbot } from "./components/chatbot/SecurityChatbot"
import { RightPanel } from "./components/events/RightPanel"
import { ScenarioCardWrapper } from "./components/scenario-cards/ScenarioCardWrapper"
import { ScenarioPage } from "./components/scenario/ScenarioPage"
import { ApprovalModal } from "./components/shared/common"
import { ALERT_RULES, ASSETS, scenariosForAsset } from "./data/architecture"
import { ACTION_EVENTS, DETECT_HISTORY, REMEDIATION_HISTORY, SCENARIO_CARDS } from "./data/mock"
import { SCENARIO_DETAILS } from "./data/scenarios"
import type { ActionEvent, AssetStatus, AuthUser, DashboardApiResponse, DetectHistoryItem, RemediationHistoryItem, RightTab, ScenarioCard } from "./data/types"

function parseRoute(): string | null {
  const m = window.location.hash.match(/^#\/scenario\/(\w+)/)
  return m && SCENARIO_CARDS.some((c) => c.id === m[1]) ? m[1] : null
}

const isLabRoute = () => window.location.hash === "#/lab"

export default function App() {
  const [now, setNow] = useState(new Date())
  const [authState, setAuthState] = useState<
    "loading" | "authenticated" | "unauthenticated"
  >("loading")
  const [authUser, setAuthUser] = useState<AuthUser | null>(null)

  const [autoRefresh, setAutoRefresh] = useState(true)

  const [rightTab, setRightTab] = useState<RightTab>("action")

  const [selectedEvent, setSelectedEvent] = useState<ActionEvent | null>(null)

  const [selectedScenario, setSelectedScenario] = useState<ScenarioCard | null>(
    null,
  )

  // 지도에서 누른 인프라 하나 (그 자산과 연결된 선만 강조)
  const [selectedAsset, setSelectedAsset] = useState<string | null>(null)

  const [approvalTarget, setApprovalTarget] = useState<ActionEvent | null>(null)

  const [removedIds, setRemovedIds] = useState<Set<string>>(new Set())

  // Scenario detail page (hash route: #/scenario/<id>)
  const [pageId, setPageId] = useState<string | null>(parseRoute)

  // 공격 시뮬레이션 페이지 (hash route: #/lab) — 관제 화면과 분리된 별도 페이지
  const [labOpen, setLabOpen] = useState(isLabRoute)

  // actionId -> 실행 시각 (상세 페이지에서 실행한 조치)
  const [doneActions, setDoneActions] = useState<Record<string, string>>({})

  const [toast, setToast] = useState<string | null>(null)

  // 원본 UI는 그대로 유지하고, API 연결 성공 시 DB 데이터로 교체한다.
  // API가 아직 준비되지 않았거나 DB 연결에 실패하면 기존 mock 데이터가 남는다.
  const [actionEvents, setActionEvents] = useState<ActionEvent[]>(ACTION_EVENTS)
  const [detectHistory, setDetectHistory] = useState<DetectHistoryItem[]>(DETECT_HISTORY)
  const [remediationHistory, setRemediationHistory] =
    useState<RemediationHistoryItem[]>(REMEDIATION_HISTORY)

  const loadDashboardData = async () => {
    try {
      const response = await fetch("/api/dashboard", { credentials: "include" })
      if (response.status === 401) {
        setAuthUser(null)
        setAuthState("unauthenticated")
        return
      }
      if (!response.ok) {
        throw new Error(`Dashboard API ${response.status}`)
      }

      const data = (await response.json()) as DashboardApiResponse
      setActionEvents(data.events)
      setDetectHistory(data.detectHistory)
      setRemediationHistory(data.remediationHistory)
    } catch (error) {
      // 개발 중 Flask/DB가 꺼져 있어도 원본 화면은 mock 데이터로 계속 동작한다.
      console.warn("DB 대시보드 데이터를 불러오지 못해 mock 데이터를 유지합니다.", error)
    }
  }

  useEffect(() => {
    const checkAuth = async () => {
      try {
        const response = await fetch("/api/auth/status", {
          credentials: "include",
        })
        if (!response.ok) throw new Error(`Auth API ${response.status}`)

        const data = (await response.json()) as {
          authenticated: boolean
          user?: AuthUser
        }

        if (data.authenticated && data.user) {
          setAuthUser(data.user)
          setAuthState("authenticated")
        } else {
          setAuthState("unauthenticated")
        }
      } catch (error) {
        console.warn("로그인 상태 확인 실패", error)
        setAuthState("unauthenticated")
      }
    }

    void checkAuth()
  }, [])

  useEffect(() => {
    if (authState === "authenticated") void loadDashboardData()
  }, [authState])

  useEffect(() => {
    const onHash = () => {
      setPageId(parseRoute())
      setLabOpen(isLabRoute())
    }
    window.addEventListener("hashchange", onHash)
    return () => window.removeEventListener("hashchange", onHash)
  }, [])

  useEffect(() => {
    if (!toast) return
    const id = setTimeout(() => setToast(null), 2600)
    return () => clearTimeout(id)
  }, [toast])

  const openScenario = (id: string) => {
    window.location.hash = `#/scenario/${id}`
  }

  const closeScenario = () => {
    window.location.hash = ""
  }

  // 실제 현재 시간: 브라우저 시스템 시간을 1초마다 다시 읽는다.
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(id)
  }, [])

  // 자동 갱신은 시간 표시와 분리하여 DB 데이터만 1분마다 다시 읽는다.
  useEffect(() => {
    if (!autoRefresh || authState !== "authenticated") return

    const id = setInterval(() => {
      void loadDashboardData()
    }, 10000)

    return () => clearInterval(id)
  }, [autoRefresh, authState])

  const clearSelection = () => {
    setSelectedScenario(null)
    setSelectedEvent(null)
    setSelectedAsset(null)
  }

  // Esc 로 선택 해제
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !approvalTarget) {
        setSelectedScenario(null)
        setSelectedEvent(null)
        setSelectedAsset(null)
      }
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [approvalTarget])

  // Compute asset statuses based on selected event

  const statuses = useMemo((): Record<string, AssetStatus> => {
    const base: Record<string, AssetStatus> = {}

    ASSETS.forEach((a) => {
      base[a.id] = a.defaultStatus
    })

    const selection = selectedEvent ?? selectedScenario
    if (selection) {
      selection.attackPath.forEach((id) => {
        base[id] = "critical"
      })
      selection.highlightAssets.forEach((id) => {
        if (!selection.attackPath.includes(id)) base[id] = "warning"
      })
    }

    return base
  }, [selectedEvent, selectedScenario])

  // 시나리오 선택 (같은 것을 다시 누르면 해제)
  const toggleScenario = (card: ScenarioCard) => {
    if (selectedScenario?.id === card.id) {
      clearSelection()
      return
    }

    setSelectedAsset(null)
    setSelectedScenario(card)
    setSelectedEvent(
      card.actionEventId
        ? (actionEvents.find((e) => e.id === card.actionEventId) ?? null)
        : null,
    )
  }

  // 지도의 인프라 클릭 → 그 인프라와 연결된 선만 강조 (다시 누르면 해제)
  const handleAssetClick = (assetId: string) => {
    if (selectedAsset === assetId) {
      clearSelection()
      return
    }
    setSelectedScenario(null)
    setSelectedEvent(null)
    setSelectedAsset(assetId)
  }

  const handleSelectEvent = (ev: ActionEvent | null) => {
    if (!ev || selectedEvent?.id === ev.id) {
      clearSelection()
      return
    }

    setSelectedAsset(null)
    setSelectedEvent(ev)
    setSelectedScenario(
      SCENARIO_CARDS.find((c) => c.actionEventId === ev.id) ?? null,
    )
  }

  const handleApproveConfirm = () => {
    if (!approvalTarget) return

    setRemovedIds((prev) => new Set([...prev, approvalTarget.id]))

    setToast(`조치가 실행되었습니다 — ${approvalTarget.title}`)

    setApprovalTarget(null)

    clearSelection()
  }

  const fmt = (d: Date) => {
    const parts = new Intl.DateTimeFormat("ko-KR", {
      timeZone: "Asia/Seoul",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }).formatToParts(d)
    const part = (type: Intl.DateTimeFormatPartTypes) =>
      parts.find((item) => item.type === type)?.value ?? "00"
    return `${part("year")}.${part("month")}.${part("day")} ${part("hour")}:${part("minute")}:${part("second")}`
  }

  const executeScenarioAction = (actionId: string) => {
    const t = `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}`
    setDoneActions((prev) => ({ ...prev, [actionId]: t }))
    setToast("조치가 실행되었습니다")
  }

  const activeEvents = actionEvents.filter((e) => !removedIds.has(e.id))

  const scenarioResolved = (id: string) => {
    const acts = SCENARIO_DETAILS[id]?.actions ?? []
    return acts.length > 0 && acts.every((a) => doneActions[a.id])
  }

  // 아직 해제되지 않은 비상 자산 (지도의 빨간/주황 점)
  const alerts: Record<string, { level: "critical" | "warning"; reason: string }> = {}
  ALERT_RULES.forEach((r) => {
    const cleared =
      (r.clearedByEvent && removedIds.has(r.clearedByEvent)) ||
      (r.clearedByScenario && scenarioResolved(r.clearedByScenario))
    if (!cleared) alerts[r.assetId] = { level: r.level, reason: r.reason }
  })
  const criticalCount = Object.values(alerts).filter((a) => a.level === "critical").length
  const warningCount = Object.values(alerts).length - criticalCount

  const abnormalScenarios = SCENARIO_CARDS.filter(
    (c) => SCENARIO_DETAILS[c.id].tone !== "ok" && !scenarioResolved(c.id),
  ).length

  const avgWait = activeEvents.length
    ? Math.round(
        activeEvents.reduce((n, e) => n + parseInt(e.elapsed, 10), 0) /
          activeEvents.length,
      )
    : 0

  const selection = selectedEvent ?? selectedScenario

  const hasScenario = selection !== null || selectedAsset !== null

  const highlightedAssets = selection
    ? selection.highlightAssets
    : selectedAsset
      ? [selectedAsset]
      : []

  // 누른 인프라와 관련된 시나리오 카드는 함께 강조한다.
  const relatedScenarioIds = selectedAsset ? scenariosForAsset(selectedAsset) : []

  const attackPathAssets = selection ? selection.attackPath : []

  const chatContextEvent = selectedEvent

  const handleLogin = async (username: string, password: string) => {
    const response = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ username, password }),
    })
    const data = (await response.json()) as { user?: AuthUser; message?: string }
    if (!response.ok || !data.user) {
      throw new Error(data.message || "아이디 또는 비밀번호를 확인해 주세요.")
    }

    setAuthUser(data.user)
    setAuthState("authenticated")
    return data.user
  }

  const handleLogout = async () => {
    try {
      await fetch("/api/auth/logout", {
        method: "POST",
        credentials: "include",
      })
    } finally {
      setAuthUser(null)
      setAuthState("unauthenticated")
      clearSelection()
    }
  }

  if (authState === "loading") {
    return (
      <div className="min-h-screen bg-[#F6F7F9] flex items-center justify-center text-[12px] text-[#667085]">
        로그인 상태 확인 중...
      </div>
    )
  }

  if (authState === "unauthenticated") {
    return <LoginPage onLogin={handleLogin} />
  }

  return (
    <div
      className="h-screen flex flex-col overflow-hidden bg-[#FAFAFA]"
      style={{
        fontFamily:
          "'Pretendard Variable', 'Pretendard', -apple-system, sans-serif",
      }}
    >
      {/* ── Header ─────────────────────────────────────────────────────── */}
      <header className="bg-white border-b border-[#E4E7EC] h-14 flex-shrink-0 flex items-center px-5 justify-between">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 bg-[#111111] rounded-lg flex items-center justify-center flex-shrink-0">
              <svg
                viewBox="0 0 24 24"
                width="15"
                height="15"
                fill="none"
                stroke="white"
                strokeWidth="2.2"
              >
                <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" />
              </svg>
            </div>
            <div>
              <p className="text-[11px] font-bold text-[#111111] leading-tight">
                AWS Security Monitoring Center
              </p>
              <p className="text-[9px] text-[#6B6B6B] leading-tight">
                통합 보안관제
              </p>
            </div>
          </div>
          <div className="w-px h-7 bg-[#E0E0E0]" />
          <div className="flex items-center gap-1.5">
            <span
              className={`w-2 h-2 rounded-full flex-shrink-0 ${
                criticalCount
                  ? "bg-[#D92D20] alert-dot-critical"
                  : warningCount
                    ? "bg-[#F79009] alert-dot-warning"
                    : "bg-[#16A34A]"
              }`}
            />
            <span
              className="text-[11px] font-semibold"
              style={{
                color: criticalCount ? "#D92D20" : warningCount ? "#B54708" : "#16A34A",
              }}
            >
              {criticalCount
                ? `비상 ${criticalCount}건 대응 필요`
                : warningCount
                  ? `주의 ${warningCount}건`
                  : "정상 운영 중"}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-4 text-xs text-[#6B6B6B]">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#101828] pulse-dot flex-shrink-0" />
            <span className="text-[#101828] font-bold text-[11px]">LIVE</span>
          </div>
          <span className="font-mono text-[11px] text-[#0D0D0D]">
            {fmt(now)}
          </span>
          <button
            onClick={() => setAutoRefresh((v) => !v)}
            className={`text-[11px] font-semibold px-2.5 py-1 rounded-full border transition-colors ${
              autoRefresh
                ? "border-[#111111] text-[#111111] bg-[#F5F5F5]"
                : "border-[#E0E0E0] text-[#6B6B6B]"
            }`}
          >
            {autoRefresh ? "자동 갱신 ON" : "자동 갱신 OFF"}
          </button>

          <a
            href="#/lab"
            className="text-[11px] text-[#98A2B3] hover:text-[#344054] transition-colors"
          >
            공격 시뮬레이션
          </a>

          {/* Alert bell */}
          <button className="relative p-1.5 hover:bg-[#F5F5F5] rounded-lg">
            <svg
              width="18"
              height="18"
              viewBox="0 0 24 24"
              fill="none"
              stroke="#6B6B6B"
              strokeWidth="2"
            >
              <path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9M13.73 21a2 2 0 01-3.46 0" />
            </svg>
            {criticalCount + warningCount > 0 && (
              <span className="absolute -top-0.5 -right-0.5 w-4 h-4 bg-[#D92D20] text-white text-[9px] font-bold rounded-full flex items-center justify-center">
                {criticalCount + warningCount}
              </span>
            )}
          </button>

          {/* Profile */}
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-2 hover:bg-[#F5F5F5] rounded-lg px-2 py-1 transition-colors">
              <div className="w-7 h-7 rounded-full bg-[#111111] flex items-center justify-center text-white text-[11px] font-bold">
                관
              </div>
              <div>
                <p className="text-[11px] font-semibold text-[#0D0D0D] leading-tight">
                  {authUser?.team || "보안관제팀"}
                </p>
                <p className="text-[9px] text-[#6B6B6B] leading-tight">
                  {authUser?.username || "관리자"} · {authUser?.role || "관리자"}
                </p>
              </div>
            </div>
            <button
              onClick={() => void handleLogout()}
              className="text-[10px] text-[#98A2B3] hover:text-[#344054] transition-colors"
            >
              로그아웃
            </button>
          </div>
        </div>
      </header>

      {/* ── Body ───────────────────────────────────────────────────────── */}
      {labOpen ? (
        <AttackLabPage onBack={closeScenario} />
      ) : pageId ? (
        <ScenarioPage
          id={pageId}
          doneActions={doneActions}
          onExecute={executeScenarioAction}
          onNavigate={openScenario}
          onBack={closeScenario}
        />
      ) : (
      <div className="flex flex-1 overflow-hidden">
        {/* ── Left: Architecture map + scenario cards ──────────────────── */}
        <main
          className="flex-1 min-w-0 overflow-hidden flex flex-col gap-2 p-3"
        >
          {/* Summary strip */}
          <div className="grid grid-cols-4 gap-2 flex-shrink-0">
            {[
              {
                label: "비상 자산",
                value: criticalCount,
                unit: "건",
                tone: criticalCount ? "#D92D20" : "#16A34A",
                hint: warningCount ? `주의 ${warningCount}건 별도` : "주의 없음",
              },
              {
                label: "조치 필요",
                value: activeEvents.length,
                unit: "건",
                tone: activeEvents.length ? "#F79009" : "#16A34A",
                hint: `Critical ${activeEvents.filter((e) => e.severity === "Critical").length}건 포함`,
              },
              {
                label: "이상 시나리오",
                value: abnormalScenarios,
                unit: `/ ${SCENARIO_CARDS.length}`,
                tone: abnormalScenarios ? "#D92D20" : "#16A34A",
                hint: `정상 ${SCENARIO_CARDS.length - abnormalScenarios}개`,
              },
              {
                label: "평균 조치 대기",
                value: avgWait,
                unit: "분",
                tone: "#101828",
                hint: "미조치 이벤트 기준",
              },
            ].map((k) => (
              <div
                key={k.label}
                className="bg-white rounded-lg ring-1 ring-[#EAECF0] px-3 py-1.5 flex items-center gap-2"
              >
                <div>
                  <p className="text-[11px] text-[#667085]">{k.label}</p>
                  <p className="leading-tight">
                    <span
                      className="text-[17px] font-bold"
                      style={{ color: k.tone }}
                    >
                      {k.value}
                    </span>
                    <span className="text-xs text-[#667085] ml-1">{k.unit}</span>
                  </p>
                </div>
                <p className="ml-auto text-[9px] text-[#98A2B3] text-right hidden xl:block">
                  {k.hint}
                </p>
              </div>
            ))}
          </div>

          {/* Architecture map — flex-1 fills remaining height, map scales to fit */}
          <div className="flex-1 min-h-0 relative">
            <ArchitectureMap
              assetStatuses={statuses}
              highlightedAssets={highlightedAssets}
              attackPathAssets={attackPathAssets}
              alerts={alerts}
              onAssetClick={handleAssetClick}
              onBackgroundClick={clearSelection}
              hasScenario={hasScenario}
            />
          </div>

          {/* Scenario cards: compact row of 6 + full-width vuln card */}
          <div className="flex-shrink-0 flex flex-col gap-2">
            <div className="grid grid-cols-6 gap-2" style={{ height: 150 }}>
              {SCENARIO_CARDS.filter((c) => c.type !== "vuln").map((card) => (
                <ScenarioCardWrapper
                  key={card.id}
                  card={card}
                  isSelected={
                    selectedScenario?.id === card.id ||
                    relatedScenarioIds.includes(card.id)
                  }
                  anySelected={hasScenario}
                  onSelect={toggleScenario}
                  onOpen={(c) => openScenario(c.id)}
                />
              ))}
            </div>
            {SCENARIO_CARDS.filter((c) => c.type === "vuln").map((card) => (
              <ScenarioCardWrapper
                key={card.id}
                card={card}
                isSelected={
                  selectedScenario?.id === card.id ||
                  relatedScenarioIds.includes(card.id)
                }
                anySelected={hasScenario}
                onSelect={toggleScenario}
                onOpen={(c) => openScenario(c.id)}
              />
            ))}
          </div>
        </main>

        {/* ── Right: split panel ──────────────────────────────────────── */}
        <aside
          className="flex-shrink-0 border-l border-[#E4E7EC] bg-[#F6F7F9] flex flex-col overflow-hidden"
          style={{ width: 380, height: "calc(100vh - 56px)" }}
        >
          {/* Top: action list + detect history */}
          <div
            className="flex flex-col overflow-hidden"
            style={{ height: "68%" }}
          >
            <RightPanel
              tab={rightTab}
              setTab={setRightTab}
              events={activeEvents}
              detectHistory={detectHistory}
              remediationHistory={remediationHistory}
              selectedEvent={selectedEvent}
              onSelectEvent={handleSelectEvent}
              onApprove={setApprovalTarget}
            />
          </div>

          {/* Divider */}
          <div className="border-t border-[#E4E7EC] flex-shrink-0" />

          {/* Bottom: compact AI assistant */}
          <div
            className="flex flex-col overflow-hidden"
            style={{ height: "32%" }}
          >
            <SecurityChatbot
              selectedEvent={chatContextEvent}
              onHighlightPath={() => {
                if (selectedEvent) {
                  setSelectedEvent(selectedEvent)
                }
              }}
              onShowRecommend={() => {}}
            />
          </div>
        </aside>
      </div>
      )}

      {toast && (
        <div className="fixed top-16 left-1/2 -translate-x-1/2 z-[60] bg-[#101828] text-white text-xs font-semibold rounded-full px-4 py-2.5 shadow-xl fade-in">
          ✓ {toast}
        </div>
      )}

      {/* ── Approval Modal ─────────────────────────────────────────────── */}
      {approvalTarget && (
        <ApprovalModal
          ev={approvalTarget}
          onClose={() => setApprovalTarget(null)}
          onConfirm={handleApproveConfirm}
        />
      )}
    </div>
  )
}
