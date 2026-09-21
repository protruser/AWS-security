import { mkdir, writeFile } from "node:fs/promises"

const tabs = await (await fetch("http://localhost:9222/json/list")).json()
const socket = new WebSocket(
  tabs.find((t) => t.type === "page").webSocketDebuggerUrl,
)
await new Promise((resolve) =>
  socket.addEventListener("open", resolve, { once: true }),
)
let seq = 0
const pending = new Map()
const errors = []
socket.addEventListener("message", ({ data }) => {
  const message = JSON.parse(data)
  if (message.id) {
    const { resolve, reject } = pending.get(message.id)
    pending.delete(message.id)
    if (message.error) reject(new Error(JSON.stringify(message.error)))
    else resolve(message.result)
  }
  if (
    message.method === "Runtime.exceptionThrown" ||
    (message.method === "Log.entryAdded" &&
      message.params.entry.level === "error") ||
    (message.method === "Runtime.consoleAPICalled" &&
      message.params.type === "error")
  )
    errors.push(message)
})
function send(method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = ++seq
    pending.set(id, { resolve, reject })
    socket.send(JSON.stringify({ id, method, params }))
  })
}
async function evaluate(expression) {
  const result = await send("Runtime.evaluate", {
    expression,
    returnByValue: true,
    awaitPromise: true,
  })
  if (result.exceptionDetails)
    throw new Error(JSON.stringify(result.exceptionDetails))
  return result.result.value
}
await send("Page.enable")
await send("Runtime.enable")
await send("Log.enable")
await mkdir("artifacts", { recursive: true })
const phase = process.argv[2] || "after"
const assert = (ok, message) => {
  if (!ok) throw new Error(message)
}
const pause = () => new Promise((resolve) => setTimeout(resolve, 150))
async function clickText(text) {
  const clicked = await evaluate(
    `(() => { const el = [...document.querySelectorAll('button')].find(el => el.textContent.trim() === ${JSON.stringify(text)}); el?.click(); return !!el; })()`,
  )
  assert(clicked, `Missing button: ${text}`)
  await pause()
}
for (const width of [1440, 1920]) {
  await send("Emulation.setDeviceMetricsOverride", {
    width,
    height: 1080,
    deviceScaleFactor: 1,
    mobile: false,
  })
  await send("Page.navigate", { url: "http://localhost:8443/" })
  await new Promise((resolve) => setTimeout(resolve, 2000))
  console.log(
    width,
    await evaluate(
      `({ title: document.title, assets: document.querySelectorAll('[data-asset-id]').length, bodyWidth: document.body.scrollWidth, text: document.body.innerText.slice(0, 180) })`,
    ),
  )
  if (phase !== "before") {
    const layout = await evaluate(`(async () => {
      const { ASSETS } = await import('/src/data/architecture.ts');
      const { CONNECTIONS } = await import('/src/data/architectureLayout.ts');
      const problems = [];
      const cards = [...document.querySelectorAll('[data-asset-id]')];
      const overlaps = (a, b) => a.left < b.right - .5 && a.right > b.left + .5 && a.top < b.bottom - .5 && a.bottom > b.top + .5;
      const intersects = (p, q, a) => p.x === q.x
        ? p.x > a.x && p.x < a.x + a.w && Math.max(p.y,q.y) > a.y && Math.min(p.y,q.y) < a.y+a.h
        : p.y > a.y && p.y < a.y+a.h && Math.max(p.x,q.x) > a.x && Math.min(p.x,q.x) < a.x+a.w;
      for (const c of CONNECTIONS) for (let i=1; i<c.points.length; i++) {
        const p=c.points[i-1], q=c.points[i];
        if (Math.abs(p.x-q.x) > .01 && Math.abs(p.y-q.y) > .01) problems.push('diagonal: '+c.id);
        for (const a of ASSETS) if (intersects(p,q,a)) problems.push('line through resource: '+c.id+' / '+a.id);
      }
      for (let i=0; i<cards.length; i++) {
        const a=cards[i], rect=a.getBoundingClientRect();
        for (const b of cards.slice(i+1)) if (overlaps(rect,b.getBoundingClientRect())) problems.push('overlapping resources');
        for (const leaf of a.querySelectorAll('span')) {
          const r=leaf.getBoundingClientRect();
          if (r.left < rect.left-1 || r.right > rect.right+1 || r.bottom > rect.bottom+1) problems.push('overflow: '+a.dataset.assetId+' '+leaf.textContent);
          if (leaf.scrollWidth > leaf.clientWidth+1 && getComputedStyle(leaf).overflow === 'hidden') problems.push('truncated: '+leaf.textContent);
        }
      }
      const labels = [...document.querySelectorAll('[data-connection-label]')];
      for (const label of labels) {
        const rect=label.getBoundingClientRect();
        for (const card of cards) if (overlaps(rect,card.getBoundingClientRect())) problems.push('label/resource overlap: '+label.dataset.connectionLabel);
        for (const title of document.querySelectorAll('[data-subnet-label]')) if (overlaps(rect,title.getBoundingClientRect())) problems.push('label/subnet overlap');
      }
      for (const c of CONNECTIONS.filter(c=>c.labelPos)) {
        const width=c.label.length*7+14;
        const box={x:c.labelPos.x-width/2,y:c.labelPos.y-10,w:width,h:20};
        for (const line of CONNECTIONS) for(let i=1;i<line.points.length;i++) if(intersects(line.points[i-1],line.points[i],box)) problems.push('line/label overlap: '+line.id+' / '+c.id);
      }
      const required = ['shopWAF>shopALB','shopALB>k3s','k3s>flaskApp','flaskApp>shopMySQL','adminWAF>dashALB','dashALB>dashEC2','secGroupA>lambdaA','secGroupB>lambdaB','lambdaA>secMySQL','lambdaB>secMySQL','dashEC2>lambdaRem','lambdaRem>k3s','lambdaRem>flaskApp'];
      for (const edge of required) if(!CONNECTIONS.some(c=>c.assets.join('>')===edge)) problems.push('missing edge: '+edge);
      if(document.body.scrollWidth>innerWidth) problems.push('page horizontal overflow');
      if(document.body.innerText.includes('Critical 이벤트 발생')) problems.push('default critical banner');
      return { problems, resources: cards.length, connections: CONNECTIONS.length };
    })()`)
    console.log("Layout validation", width, layout)
    assert(
      layout.resources === 14 && layout.problems.length === 0,
      JSON.stringify(layout.problems),
    )
  }
  const shot = await send("Page.captureScreenshot", { format: "png" })
  await writeFile(
    `artifacts/${phase}-${width}.png`,
    Buffer.from(shot.data, "base64"),
  )
}
if (phase !== "before") {
  await clickText("자동 갱신 ON")
  await clickText("자동 갱신 OFF")
  await clickText("탐지 이력")
  assert(
    await evaluate('document.querySelectorAll("tbody tr").length === 7'),
    "Detection history lost",
  )
  await clickText("High")
  assert(
    await evaluate('document.querySelectorAll("tbody tr").length === 2'),
    "Severity filter failed",
  )
  await clickText("전체")
  await evaluate(`document.querySelector('[data-asset-id="k3s"]').click()`)
  await pause()
  assert(
    await evaluate(
      `getComputedStyle(document.querySelector('[data-asset-id="k3s"]')).opacity === '1' && getComputedStyle(document.querySelector('[data-asset-id="shopMySQL"]')).opacity !== '1'`,
    ),
    "Asset selection failed",
  )
  await evaluate(
    `document.querySelector('main .grid.grid-cols-6 > div').click()`,
  )
  await pause()
  assert(
    await evaluate(
      `document.querySelector('[data-asset-id="flaskApp"]').getAttribute('aria-label').includes('Critical')`,
    ),
    "Scenario selection failed",
  )
  await clickText("이 이벤트를 요약해 줘")
  assert(
    await evaluate(
      `document.body.innerText.includes('203.0.113.45에서 /api/products')`,
    ),
    "Chat mock response failed",
  )
  await clickText("새 대화")
  await evaluate(
    `[...document.querySelectorAll('button')].find(b=>b.textContent.includes('조치 필요')).click()`,
  )
  await pause()
  await clickText("조치 승인")
  assert(
    await evaluate(
      `[...document.querySelectorAll('button')].find(b=>b.textContent==='조치 실행').disabled`,
    ),
    "High-risk approval gate failed",
  )
  await evaluate(`document.querySelector('input[type="checkbox"]').click()`)
  await pause()
  await clickText("조치 실행")
  assert(
    await evaluate(
      `[...document.querySelectorAll('button')].filter(b=>b.textContent==='조치 승인').length===2`,
    ),
    "Approval did not remove action",
  )
  console.log(
    "Interaction checks passed: refresh, tabs, severity filter, resource/scenario selection, chatbot, approval.",
  )
  await send("Emulation.setDeviceMetricsOverride", {
    width: 1440,
    height: 900,
    deviceScaleFactor: 1,
    mobile: false,
  })
  await send("Page.navigate", { url: "http://localhost:8443/" })
  await pause()
  const compact = await evaluate(
    `(() => { const el = document.querySelector('.architecture-viewport'); el.scrollTop = el.scrollHeight; return { scrollable: el.scrollTop > 0, pageFits: document.body.scrollWidth === innerWidth }; })()`,
  )
  assert(
    compact.scrollable && compact.pageFits,
    "Short desktop must keep map readable and scrollable",
  )
  console.log("1440×900 scroll check:", compact)
}
await writeFile(
  `artifacts/${phase}-errors.json`,
  JSON.stringify(errors, null, 2),
)
console.log("Browser errors:", errors.length)
socket.close()
assert(errors.length === 0, "Browser console errors detected")
