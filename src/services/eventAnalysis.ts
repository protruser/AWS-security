import type { ActionEvent } from "../data/types"

export interface EventAnalysis {
  event_status: "CONFIRMED" | "SUSPICIOUS" | "INFORMATIONAL"
  attack_type: string
  summary: string
  key_evidence: {
    label: string
    value: string
    description: string
  }[]
  impact: string
  remediation_type: "AUTO" | "MANUAL"
  automatic_action: string | null
  recommended_actions: string[]
  additional_check: string[]
}

const apiBase = (
  import.meta.env.VITE_API_BASE_URL as string | undefined ?? ""
).replace(/\/$/, "")
// Share requests during rapid close/reopen. Persisted results stay on the server,
// so a new session must authenticate again before reading an analysis.
const pending = new Map<string, Promise<EventAnalysis>>()

export function fetchEventAnalysis(eventId: string): Promise<EventAnalysis> {
  const existing = pending.get(eventId)
  if (existing) return existing
  const request = (async () => {
    const signal = AbortSignal.timeout(55_000)
    for (let attempt = 0; attempt < 12; attempt++) {
      const response = await fetch(`${apiBase}/api/events/ai-analysis`, {
        method: "POST",
        credentials: "include",
        signal,
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({ event_id: eventId }),
      })
      if (response.status === 409) {
        await new Promise((resolve) => setTimeout(resolve, 4000))
        continue
      }
      if (!response.ok) throw new Error("AI analysis unavailable")
      const data = (await response.json()) as EventAnalysis
      if (!isEventAnalysis(data)) throw new Error("Invalid AI analysis")
      return data
    }
    throw new Error("AI analysis unavailable")
  })().finally(() => pending.delete(eventId))
  pending.set(eventId, request)
  return request
}

export function isEventAnalysis(data: EventAnalysis): boolean {
  if (!data || typeof data !== "object") return false
  const strings = (items: unknown): items is string[] =>
    Array.isArray(items) && items.every((item) => typeof item === "string")
  return (
    ["CONFIRMED", "SUSPICIOUS", "INFORMATIONAL"].includes(data.event_status) &&
    [data.attack_type, data.summary, data.impact].every(
      (item) => typeof item === "string",
    ) &&
    Array.isArray(data.key_evidence) &&
    data.key_evidence.length >= 2 &&
    data.key_evidence.length <= 5 &&
    data.key_evidence.every(
      (item) =>
        item &&
        [item.label, item.value, item.description].every(
          (value) => typeof value === "string",
        ),
    ) &&
    strings(data.recommended_actions) &&
    strings(data.additional_check) &&
    data.additional_check.length <= 3 &&
    (data.remediation_type === "AUTO"
      ? typeof data.automatic_action === "string" &&
        data.recommended_actions.length === 0
      : data.remediation_type === "MANUAL" &&
        data.automatic_action === null &&
        data.recommended_actions.length >= 1 &&
        data.recommended_actions.length <= 5)
  )
}

export function eventDisplayTitle(
  event: Pick<ActionEvent, "scenarioType" | "title">,
): string {
  if (event.scenarioType !== "vuln") return event.title
  // Only extract the known "CVE-number - package" form; free-form finding titles
  // are not reliable package names. The original title and logs remain untouched.
  const match =
    /^CVE-\d{4}-\d{4,}\s+-\s+([A-Za-z0-9][A-Za-z0-9._+@/-]*)$/i.exec(
      event.title.trim(),
    )
  return match && !/CVE-\d{4}-\d{4,}/i.test(match[1])
    ? `${match[1]} 취약 패키지 탐지`
    : "취약 컨테이너 이미지 탐지"
}
