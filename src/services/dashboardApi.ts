import type { ActionEvent } from "../data/types"
import { ACTION_EVENTS } from "../data/mock"

export type DataSourceMode = "api" | "mock"

export interface EventFeed {
  events: ActionEvent[]
  source: DataSourceMode
  syncedAt: Date
}

const apiBase = ((import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "").replace(/\/$/, "")

export async function fetchActionEvents(): Promise<EventFeed> {
  try {
    const response = await fetch(`${apiBase}/api/events`, {
      headers: { Accept: "application/json" },
    })
    if (!response.ok) throw new Error(`HTTP ${response.status}`)

    const events = (await response.json()) as ActionEvent[]
    return { events, source: "api", syncedAt: new Date() }
  } catch {
    // 개발 중 Flask/DB가 잠시 내려가도 관제 UI 자체는 깨지지 않게 한다.
    return { events: ACTION_EVENTS, source: "mock", syncedAt: new Date() }
  }
}
