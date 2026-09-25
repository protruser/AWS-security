// Run: node --test scripts/test-event-analysis.mjs
// Render the real TSX with ReactDOMServer; no browser or additional test packages.
import assert from "node:assert/strict"
import { readFile } from "node:fs/promises"
import test from "node:test"
import ts from "typescript"
import { createElement } from "react"
import { renderToStaticMarkup } from "react-dom/server"

function moduleUrl(source, imports = {}) {
  const compiled = ts
    .transpileModule(source, {
      compilerOptions: {
        module: ts.ModuleKind.ESNext,
        target: ts.ScriptTarget.ES2022,
        jsx: ts.JsxEmit.ReactJSX,
      },
    })
    .outputText.replace(
      /from "([^"]+)"/g,
      (_, name) =>
        `from ${JSON.stringify(imports[name] ?? import.meta.resolve(name))}`,
    )
  return `data:text/javascript;base64,${Buffer.from(compiled).toString("base64")}`
}

const apiSource = (
  await readFile("src/services/eventAnalysis.ts", "utf8")
).replaceAll("import.meta.env.VITE_API_BASE_URL", '""')
const apiUrl = moduleUrl(apiSource)
const api = await import(apiUrl)
const componentUrl = moduleUrl(
  await readFile("src/components/EventAIAnalysis.tsx", "utf8"),
  { "../services/eventAnalysis": apiUrl },
)
const components = await import(componentUrl)
const appSource = await readFile("src/App.tsx", "utf8")
const cardSource = appSource.slice(
  appSource.indexOf("function canRemediate"),
  appSource.indexOf("// ─── Right panel"),
)
const cardUrl = moduleUrl(
  `
import { EventAIAnalysis, OriginalEventLogs } from "./analysis"
import { eventDisplayTitle } from "./api"
function SeverityBadge({sev}) { return <span>{sev}</span> }
${cardSource}
export { ActionCard }
`,
  { "./analysis": componentUrl, "./api": apiUrl },
)
const { ActionCard } = await import(cardUrl)
const render = (component, props) =>
  renderToStaticMarkup(createElement(component, props))
const analysis = (manual = false) => ({
  event_status: "SUSPICIOUS",
  attack_type: "탐지 유형",
  summary: "요청이 탐지되었습니다. 확인이 필요합니다.",
  key_evidence: [
    { label: "CVE", value: "CVE-2025-44168", description: "Inspector 근거" },
    {
      label: "Payload",
      value: "<script>alert(1)</script>",
      description: "원본 값",
    },
  ],
  impact: "악용 가능성이 있습니다.",
  remediation_type: manual ? "MANUAL" : "AUTO",
  automatic_action: manual ? null : "승인 후 IP 차단 정책에 등록합니다.",
  recommended_actions: manual ? ["패키지를 업데이트합니다."] : [],
  additional_check: ["로그를 확인합니다."],
})

test("all seven cards preserve facts/buttons and place AI before collapsed original logs", () => {
  for (const scenarioType of [
    "sqli",
    "xss",
    "dir",
    "brute",
    "port",
    "cred",
    "vuln",
  ]) {
    const ev = {
      id: scenarioType,
      scenarioType,
      severity: "High",
      title: "CVE-2025-44168 - mariadb",
      service: "test-service",
      asset: "test-resource",
      detectedAt: "2026.09.25 12:00",
      elapsed: "1분",
      status: "검토 필요",
      recommendation: "기존 조치",
      autoRemediation: scenarioType !== "vuln",
      remediationType: scenarioType === "vuln" ? "MANUAL" : "AUTO",
      details: {
        attackerIP: "195.63.28.83",
        requestURL: "GET /.env",
        logs: '{"original":"CVE-2025-44168"}',
      },
    }
    const html = render(ActionCard, {
      ev,
      selected: true,
      checked: false,
      onSelect() {},
      onApprove() {},
      onExcept() {},
      onToggleCheck() {},
    })
    for (const text of [
      "유형",
      scenarioType,
      "195.63.28.83",
      "GET /.env",
      "High",
      ev.service,
      ev.asset,
      ev.detectedAt,
      "예외 처리",
      "AI 이벤트 분석",
      "원본 로그 보기",
    ])
      assert.ok(html.includes(text), text)
    assert.ok(html.indexOf("GET /.env") < html.indexOf("AI 이벤트 분석"))
    assert.ok(html.indexOf("AI 이벤트 분석") < html.indexOf("원본 로그 보기"))
    assert.doesNotMatch(html, /<details[^>]*\sopen(?:[\s=>])/)
    assert.ok(
      html.includes(
        scenarioType === "vuln"
          ? "이 조치로 승인 요청 보내기"
          : "조치 요청 보내기",
      ),
    )
    if (scenarioType === "vuln")
      assert.ok(html.includes("mariadb 취약 패키지 탐지"))
    else assert.ok(html.includes("조치 내용"))
    const collapsed = render(ActionCard, { ev, selected: false })
    assert.ok(!collapsed.includes("AI 이벤트 분석"))
  }
})

test("AUTO/MANUAL sections, CVE evidence and payload escaping", () => {
  for (const manual of [false, true]) {
    const html = render(components.AnalysisContent, {
      analysis: analysis(manual),
    })
    for (const text of [
      "탐지 요약",
      "핵심 근거",
      "예상 영향",
      "추가 확인",
      "CVE-2025-44168",
    ])
      assert.ok(html.includes(text))
    assert.equal(html.includes("자동 조치 내용"), !manual)
    assert.equal(html.includes("권장 조치"), manual)
    assert.ok(!html.includes("<script>"))
    assert.ok(html.includes("&lt;script&gt;"))
  }
})

test("vuln titles are presentation-only and unsafe extraction falls back", () => {
  const ev = { scenarioType: "vuln", title: "CVE-2025-44168 - mariadb" }
  assert.equal(api.eventDisplayTitle(ev), "mariadb 취약 패키지 탐지")
  assert.equal(ev.title, "CVE-2025-44168 - mariadb")
  for (const title of [
    "CVE-2025-44168",
    "CVE-2025-44168 - arbitrary title text",
    "CVE-2025-44168 - CVE-2025-12345",
  ]) {
    assert.equal(
      api.eventDisplayTitle({ ...ev, title }),
      "취약 컨테이너 이미지 탐지",
    )
  }
  assert.equal(api.eventDisplayTitle({ ...ev, scenarioType: "sqli" }), ev.title)
})

test("raw log contents preserved inside native collapsed details", () => {
  const html = render(components.OriginalEventLogs, {
    logs: '{"CVE":"CVE-2025-44168"}',
  })
  assert.ok(html.startsWith("<details"))
  assert.ok(html.includes("<summary"))
  assert.ok(html.includes("CVE-2025-44168"))
  assert.doesNotMatch(html, /<details[^>]*\sopen(?:[\s=>])/)
})

test("frontend rejects malformed analysis instead of crashing rendering", () => {
  assert.ok(api.isEventAnalysis(analysis()))
  assert.ok(api.isEventAnalysis(analysis(true)))
  for (const value of [
    null,
    {},
    { ...analysis(), key_evidence: [null] },
    { ...analysis(), recommended_actions: ["invented"] },
  ]) {
    assert.equal(api.isEventAnalysis(value), false)
  }
})

test("in-flight requests are shared, failures can retry, only event_id is sent", async () => {
  const originalFetch = globalThis.fetch
  let release
  let count = 0
  globalThis.fetch = async (url, options) => {
    count++
    assert.equal(url, "/api/events/ai-analysis")
    assert.deepEqual(JSON.parse(options.body), { event_id: "test" })
    assert.equal(options.credentials, "include")
    await new Promise((resolve) => {
      release = resolve
    })
    return { ok: true, status: 200, json: async () => analysis() }
  }
  try {
    const first = api.fetchEventAnalysis("test")
    const second = api.fetchEventAnalysis("test")
    assert.equal(first, second)
    release()
    await Promise.all([first, second])
    assert.equal(count, 1)
    globalThis.fetch = async () => ({ ok: false, status: 503 })
    await assert.rejects(api.fetchEventAnalysis("test"))
    globalThis.fetch = async () => ({
      ok: true,
      status: 200,
      json: async () => analysis(),
    })
    assert.deepEqual(await api.fetchEventAnalysis("test"), analysis())
  } finally {
    globalThis.fetch = originalFetch
  }
})
