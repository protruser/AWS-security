// Run after npm run build: node --test scripts/test-event-list-ui.mjs
import assert from "node:assert/strict"
import { readFile, readdir } from "node:fs/promises"
import test from "node:test"
import ts from "typescript"
import { createElement } from "react"
import { renderToStaticMarkup } from "react-dom/server"

function moduleUrl(source, imports = {}) {
  const compiled = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.ESNext,
      target: ts.ScriptTarget.ES2022,
      jsx: ts.JsxEmit.ReactJSX,
    },
  }).outputText.replace(/from "([^"]+)"/g, (_, name) =>
    `from ${JSON.stringify(imports[name] ?? import.meta.resolve(name))}`
  )
  return `data:text/javascript;base64,${Buffer.from(compiled).toString("base64")}`
}

const serviceSource = (await readFile("src/services/eventAnalysis.ts", "utf8"))
  .replaceAll("import.meta.env.VITE_API_BASE_URL", '""')
const serviceUrl = moduleUrl(serviceSource)
const approvalUrl = moduleUrl(await readFile("src/components/ApprovalQueuePage.tsx", "utf8"), {
  "../services/eventAnalysis": serviceUrl,
})
const { ApprovalEventTitle } = await import(approvalUrl)
const appSource = await readFile("src/App.tsx", "utf8")
const actionAndPanel = appSource.slice(appSource.indexOf("function canRemediate"), appSource.indexOf("// ─── Security Chatbot"))
const panelUrl = moduleUrl(`
  import { useState } from "react"
  import { eventDisplayTitle } from "./service"
  function SeverityBadge({sev}) { return <span>{sev}</span> }
  function EventAIAnalysis() { return <span>AI 이벤트 분석</span> }
  function OriginalEventLogs({logs}) { return <details><summary>원본 로그 보기</summary>{logs}</details> }
  function ApprovalRequestList() { return null }
  ${actionAndPanel}
  export { RightPanel }
`, { "./service": serviceUrl })
const { RightPanel } = await import(panelUrl)
const render = (component, props) => renderToStaticMarkup(createElement(component, props))

test("approval title uses scenario type while keeping source title intact", () => {
  for (const [title, expected] of [
    ["CVE-2025-44168 - mariadb", "mariadb 취약 패키지 탐지"],
    ["CVE-2025-12345 - openssl", "openssl 취약 패키지 탐지"],
    ["CVE-2025-44168 - package words", "취약 컨테이너 이미지 탐지"],
  ]) {
    const html = render(ApprovalEventTitle, { title, scenarioType: "vuln", eventId: "id-1" })
    assert.ok(html.includes(expected))
    assert.ok(!html.includes("CVE-"))
  }
  const unchanged = "CVE-2025-44168 - mariadb"
  assert.ok(render(ApprovalEventTitle, { title: unchanged, scenarioType: "sqli", eventId: "id-1" }).includes(unchanged))
  assert.ok(render(ApprovalEventTitle, { title: unchanged, scenarioType: null, eventId: "id-1" }).includes(unchanged))
  assert.ok(render(ApprovalEventTitle, { title: null, scenarioType: "vuln", eventId: "id-1" }).includes("id-1"))
})

function event(id, scenarioType) {
  return {
    id, scenarioType, severity: "High", title: `event ${id}`,
    service: "WAF", asset: "shop", detectedAt: "2026.09.25", elapsed: "1분",
    status: "검토 필요", recommendation: "기존 조치", autoRemediation: scenarioType !== "vuln",
    details: { attackerIP: "195.63.28.83", requestURL: "GET /.env", logs: "원본 로그" },
  }
}

test("auto and manual lists are separate scroll regions with fixed headers and in-list details", () => {
  const events = [
    ...Array.from({ length: 14 }, (_, i) => event(`auto-${i}`, "dir")),
    ...Array.from({ length: 14 }, (_, i) => event(`manual-${i}`, "vuln")),
  ]
  const html = render(RightPanel, {
    tab: "action", setTab() {}, events, detectHistory: [], remediationHistory: [],
    selectedEvent: events[0], onSelectEvent() {}, onApprove() {}, onExcept() {},
    onBulkRequest() {}, role: "관리자", onUnauthorized() {},
  })
  const regions = [...html.matchAll(/<div role="region" aria-label="(자동 조치|수동 조치) 이벤트 목록"[^>]*>/g)]
  assert.equal(regions.length, 2)
  for (const [index, match] of regions.entries()) {
    const label = index === 0 ? "자동 조치" : "수동 조치"
    assert.equal(match[1], label)
    assert.ok(match[0].includes("overflow-y-auto"))
    assert.ok(match[0].includes("overscroll-y-contain"))
    assert.ok(match[0].includes("max-h-[min(520px,55vh)]"))
    assert.ok(match[0].includes("[scrollbar-gutter:stable]"))
    assert.ok(html.indexOf(`${label} (14)`) < match.index)
  }
  assert.ok(html.indexOf("event auto-0") > regions[0].index)
  assert.ok(html.indexOf("취약 컨테이너 이미지 탐지") > regions[1].index)
  assert.ok(html.indexOf("AI 이벤트 분석") > regions[0].index)
  assert.ok(html.includes("원본 로그 보기"))
  assert.ok(html.includes("조치 요청 보내기"))
  assert.ok(html.includes("예외 처리"))
  const manualSelectedHtml = render(RightPanel, {
    tab: "action", setTab() {}, events, detectHistory: [], remediationHistory: [],
    selectedEvent: events[14], onSelectEvent() {}, onApprove() {}, onExcept() {},
    onBulkRequest() {}, role: "관리자", onUnauthorized() {},
  })
  assert.ok(manualSelectedHtml.includes("이 조치로 승인 요청 보내기"))
  assert.ok(manualSelectedHtml.includes("AI 이벤트 분석"))
})

test("production CSS includes bounded independent scrolling and scroll containment", async () => {
  const assets = "dist/assets"
  const cssFile = (await readdir(assets)).find((name) => /^index-.*\.css$/.test(name))
  assert.ok(cssFile)
  const css = await readFile(`${assets}/${cssFile}`, "utf8")
  assert.ok(css.includes("max-height:min(520px,55vh)"))
  assert.ok(css.includes("overscroll-behavior-y:contain"))
  assert.ok(css.includes("scrollbar-gutter:stable"))
})
