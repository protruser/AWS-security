import type { ActionEvent } from "../data/types"

export type DataSourceMode = "api"

export interface EventFeed {
  events: ActionEvent[]
  source: DataSourceMode
  syncedAt: Date
}

const apiBase = ((import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "").replace(/\/$/, "")

export async function fetchActionEvents(): Promise<EventFeed> {
  const response = await fetch(`${apiBase}/api/events`, {
    headers: { Accept: "application/json" },
  })
  if (!response.ok) throw new Error(`HTTP ${response.status}`)

  const events = (await response.json()) as ActionEvent[]
  return { events, source: "api", syncedAt: new Date() }
}
