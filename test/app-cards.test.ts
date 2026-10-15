/**
 * MCP Apps result cards (spec 2026-01-26, `text/html;profile=mcp-app`).
 *
 * ChatGPT, Claude and VS Code render a tool result as an in-chat card when the
 * tool carries `_meta.ui.resourceUri` and the result carries
 * `structuredContent`. scan_page and verify_fix get one shared card; every
 * other tool stays text-only, and the text `content` blocks are unchanged for
 * clients that do not render apps.
 *
 * Local server (127.0.0.1) + real browser, like flow-scan-single-page.test.ts.
 */
process.env.WEBABILITY_SCAN_TELEMETRY = 'off'
process.env.WEBABILITY_SCAN_LOG = 'off'

import assert from 'node:assert/strict'
import { createServer as createHttpServer, type Server as HttpServer } from 'node:http'
import { after, before, test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { JSDOM } from 'jsdom'

import { createServer } from '../src/server.ts'
import { CARD_MIME_TYPE, CARD_RESOURCE_URI, cardHtml, scanCard, verifyCard } from '../src/appCards.ts'

async function connect(remote = false) {
  const [c, s] = InMemoryTransport.createLinkedPair()
  const cl = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([createServer(remote ? { remote: true, authToken: 'test-token' } : {}).connect(s), cl.connect(c)])
  return cl
}

/** Load the card in jsdom, deliver one tool-result over the bridge, return the visible text. */
async function renderCard(params: unknown): Promise<string> {
  const dom = new JSDOM(cardHtml(), { runScripts: 'dangerously', pretendToBeVisual: true })
  const w = dom.window as any
  await new Promise((r) => setTimeout(r, 0))
  w.dispatchEvent(new w.MessageEvent('message', { data: { jsonrpc: '2.0', method: 'ui/notifications/tool-result', params } }))
  const text = String(w.document.getElementById('root').textContent)
  w.close()
  return text
}

test('card constants follow the MCP Apps spec', () => {
  assert.equal(CARD_MIME_TYPE, 'text/html;profile=mcp-app')
  assert.match(CARD_RESOURCE_URI, /^ui:\/\//)
})

for (const remote of [false, true]) {
  const label = remote ? 'hosted' : 'local'

  test(`${label}: only scan_page and verify_fix point at the card`, async () => {
    const { tools } = await (await connect(remote)).listTools()
    const withUi = tools.filter((t: any) => t._meta?.ui?.resourceUri).map((t) => t.name).sort()
    assert.deepEqual(withUi, ['scan_page', 'verify_fix'])
    for (const t of tools.filter((t: any) => t._meta?.ui)) assert.equal((t as any)._meta.ui.resourceUri, CARD_RESOURCE_URI)
  })

  test(`${label}: the card is listed and readable as an MCP Apps resource`, async () => {
    const cl = await connect(remote)
    assert.ok(cl.getServerCapabilities()?.resources, 'server advertises resources')
    assert.deepEqual((cl.getServerCapabilities() as any)?.extensions?.['io.modelcontextprotocol/ui'], { mimeTypes: [CARD_MIME_TYPE] }, 'server advertises the MCP Apps extension')
    const { resources } = await cl.listResources()
    const card = resources.find((r) => r.uri === CARD_RESOURCE_URI)
    assert.ok(card, 'card listed')
    assert.equal(card!.mimeType, CARD_MIME_TYPE)
    const read = await cl.readResource({ uri: CARD_RESOURCE_URI })
    const item: any = read.contents[0]
    assert.equal(item.uri, CARD_RESOURCE_URI)
    assert.equal(item.mimeType, CARD_MIME_TYPE)
    assert.equal(item.text, cardHtml())
    assert.equal(item._meta?.ui?.prefersBorder, true)
  })
}

test('reading an unknown ui:// resource is an error, not an empty page', async () => {
  const cl = await connect()
  await assert.rejects(cl.readResource({ uri: 'ui://webability/nope.html' }))
})

test('card HTML is self-contained and speaks the ui/* bridge', () => {
  const html = cardHtml()
  // Runs in a sandboxed iframe with no declared CSP domains: nothing external may load.
  assert.doesNotMatch(html, /\bsrc\s*=\s*["']?(https?:)?\/\//i)
  assert.doesNotMatch(html, /<link\b/i)
  assert.doesNotMatch(html, /@import/i)
  assert.doesNotMatch(html, /\bfetch\s*\(/)
  for (const method of ['ui/initialize', 'ui/notifications/initialized', 'ui/notifications/tool-result', 'ui/notifications/size-changed', 'ui/open-link', 'ui/notifications/host-context-changed']) {
    assert.ok(html.includes(method), `uses ${method}`)
  }
  // Accessible by construction: lang, a real table header, a real button.
  assert.match(html, /<html lang="en"/)
  assert.match(html, /<th scope="col"/)
  assert.match(html, /<button\b/)
  // Host theme variables first, brand colours only as fallbacks.
  assert.match(html, /var\(--color-text-primary,\s*#020817\)/i)
})

const ISSUE = (n: number, impact: string) => ({
  id: `i${n}`,
  impact,
  wcag: '1.1.1',
  type: 'missing_alt',
  message: `Image ${n} has no alt text`,
  selector: `img:nth-of-type(${n})`,
  html: '<img src="a.png">'.repeat(50),
  fix: { op: 'add-attribute' },
})

test('scanCard is compact: counts, top 6 issues, report link, no raw HTML', () => {
  const issues = [ISSUE(1, 'critical'), ...Array.from({ length: 9 }, (_, i) => ISSUE(i + 2, 'moderate'))]
  const card = scanCard({
    url: 'https://uw.test/before.html',
    summary: { total: 10, critical: 1, serious: 0, moderate: 9, minor: 0 },
    issues,
    issuesTotal: 10,
    framework: 'unknown',
  })
  assert.equal(card.kind, 'scan')
  assert.equal(card.url, 'https://uw.test/before.html')
  assert.equal(card.level, 'AA')
  assert.deepEqual(card.summary, { total: 10, critical: 1, serious: 0, moderate: 9, minor: 0 })
  assert.equal(card.issuesTotal, 10)
  assert.equal(card.topIssues.length, 6)
  assert.deepEqual(card.topIssues[0], { type: 'missing_alt', wcag: '1.1.1', impact: 'critical', selector: 'img:nth-of-type(1)', message: 'Image 1 has no alt text' })
  assert.equal(card.reportUrl, 'https://www.webability.io/website-accessibility-checker?url=https%3A%2F%2Fuw.test%2Fbefore.html')
  assert.ok(!JSON.stringify(card).includes('<img'), 'no raw page HTML in structuredContent')
})

test('scanCard keeps a collapsed entry\'s count', () => {
  const card = scanCard({ url: 'https://uw.test/', summary: { total: 5, critical: 0, serious: 5, moderate: 0, minor: 0 }, issues: [{ ...ISSUE(1, 'serious'), count: 5 }], issuesTotal: 5 })
  assert.equal(card.topIssues[0]!.count, 5)
})

test('verifyCard: pass and fail', () => {
  const pass = verifyCard({ url: 'https://uw.test/after.html', selector: '#logo', wcag: '1.1.1', verified: true, remainingCount: 0, remainingIssues: [] })
  assert.deepEqual(pass, { kind: 'verify', url: 'https://uw.test/after.html', selector: '#logo', wcag: '1.1.1', verified: true, remainingCount: 0, remaining: [] })
  const fail = verifyCard({ url: 'https://uw.test/a', selector: 'img', verified: false, remainingCount: 7, remainingIssues: Array.from({ length: 7 }, (_, i) => ISSUE(i + 1, 'serious')) })
  assert.equal(fail.verified, false)
  assert.equal(fail.remaining.length, 5)
  assert.deepEqual(fail.remaining[0], { type: 'missing_alt', wcag: '1.1.1', impact: 'serious', message: 'Image 1 has no alt text' })
  const notFound = verifyCard({ url: 'https://uw.test/a', selector: '#gone', verified: false, reason: 'not-found', remainingCount: null, remainingIssues: [] })
  assert.equal(notFound.reason, 'not-found')
})

const PAGE = `<!doctype html><html lang="en"><head><title>Home</title></head><body><main><h1>Home</h1><img id="hero" src="/a.png"></main></body></html>`
let http: HttpServer
let base = ''
before(async () => {
  http = createHttpServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' })
    res.end(PAGE)
  })
  await new Promise<void>((r) => http.listen(0, '127.0.0.1', () => r()))
  base = `http://127.0.0.1:${(http.address() as any).port}/`
})
after(() => http?.close())

test('scan_page result carries the card as structuredContent; text content unchanged', async () => {
  const cl = await connect()
  const r: any = await cl.callTool({ name: 'scan_page', arguments: { url: base } }, undefined, { timeout: 120_000 })
  assert.notEqual(r.isError, true)
  const json = JSON.parse(String(r.content[1].text).replace(/^```json\n|\n```$/g, ''))
  assert.equal(r.structuredContent?.kind, 'scan')
  assert.equal(r.structuredContent.url, base)
  assert.deepEqual(r.structuredContent.summary, json.summary)
  assert.ok(r.structuredContent.topIssues.some((i: any) => i.wcag?.includes('1.1.1')), 'missing alt is on the card')
  assert.equal(r.content.length, 2, 'headline + findings blocks as before')
})

test('verify_fix result carries the card as structuredContent', async () => {
  const cl = await connect()
  const r: any = await cl.callTool({ name: 'verify_fix', arguments: { url: base, selector: '#hero', wcag: '1.1.1' } }, undefined, { timeout: 120_000 })
  assert.equal(r.structuredContent?.kind, 'verify')
  assert.equal(r.structuredContent.verified, false)
  assert.equal(r.structuredContent.selector, '#hero')
  assert.ok(r.structuredContent.remainingCount >= 1)
})

test('verify_fix on a missing selector still renders a card with the reason', async () => {
  const cl = await connect()
  const r: any = await cl.callTool({ name: 'verify_fix', arguments: { url: base, selector: '#gone' } }, undefined, { timeout: 120_000 })
  assert.equal(r.structuredContent?.kind, 'verify')
  assert.equal(r.structuredContent.reason, 'not-found')
})

const ZERO = { total: 0, critical: 0, serious: 0, moderate: 0, minor: 0 }

test('a filtered zero is not shown as a clean page', async () => {
  const card = scanCard({ url: 'https://uw.test/', summary: ZERO, issues: [], issuesTotal: 0, filters: 'minImpact=critical', pageSummary: { total: 43, critical: 0, serious: 5, moderate: 38, minor: 0 } })
  assert.equal(card.filters, 'minImpact=critical')
  assert.equal(card.pageTotal, 43)
  const text = await renderCard({ structuredContent: card, content: [] })
  assert.doesNotMatch(text, /No AA issues found/)
  assert.match(text, /minImpact=critical/)
  assert.match(text, /43/)
})

test('an unfiltered zero is shown as clean, at the scanned level', async () => {
  assert.match(await renderCard({ structuredContent: scanCard({ url: 'https://uw.test/', summary: ZERO, issues: [], issuesTotal: 0 }), content: [] }), /No AA issues found/)
})

test('a result without card data renders its text instead of waiting forever', async () => {
  const text = await renderCard({ isError: true, content: [{ type: 'text', text: 'BLOCKED: https://uw.test/ was not actually scanned.' }] })
  assert.match(text, /BLOCKED: https:\/\/uw\.test\/ was not actually scanned\./)
  assert.doesNotMatch(text, /Waiting for the result/)
})

test('scan_page with filters carries them and the page total onto the card', async () => {
  const cl = await connect()
  const r: any = await cl.callTool({ name: 'scan_page', arguments: { url: base, minImpact: 'critical' } }, undefined, { timeout: 120_000 })
  const json = JSON.parse(String(r.content[1].text).replace(/^```json\n|\n```$/g, ''))
  assert.match(r.structuredContent.filters, /minImpact=critical/)
  assert.equal(r.structuredContent.pageTotal, json.pageSummary.total)
  assert.ok(Math.abs(Date.now() - Date.parse(r.structuredContent.at)) < 300_000, 'stamped server-side with the scan time')
})

test('the card answers host requests (ping, ui/resource-teardown) so the host never waits on a timeout', async () => {
  const dom = new JSDOM(cardHtml(), { runScripts: 'dangerously', pretendToBeVisual: true })
  const w = dom.window as any
  await new Promise((r) => setTimeout(r, 0))
  const sent: any[] = []
  // JSON copy: the card's objects come from the jsdom realm, and strict deepEqual checks prototypes.
  w.parent.postMessage = (m: any) => sent.push(JSON.parse(JSON.stringify(m)))
  w.dispatchEvent(new w.MessageEvent('message', { data: { jsonrpc: '2.0', id: 'td-1', method: 'ui/resource-teardown', params: {} } }))
  w.dispatchEvent(new w.MessageEvent('message', { data: { jsonrpc: '2.0', id: 77, method: 'ping' } }))
  w.close()
  assert.deepEqual(sent.find((m) => m.id === 'td-1'), { jsonrpc: '2.0', id: 'td-1', result: {} })
  assert.deepEqual(sent.find((m) => m.id === 77), { jsonrpc: '2.0', id: 77, result: {} })
})

test('the footer time is when the result was produced, not when the card renders', async () => {
  const at = '2026-01-02T03:04:00.000Z'
  const card = scanCard({ url: 'https://uw.test/', summary: ZERO, issues: [], issuesTotal: 0, at })
  assert.equal(card.at, at)
  const text = await renderCard({ structuredContent: card, content: [] })
  assert.match(text, /Scanned .*2026/)
  const v = await renderCard({ structuredContent: verifyCard({ url: 'https://uw.test/', selector: '#a', verified: true, remainingCount: 0, remainingIssues: [], at }), content: [] })
  assert.match(v, /Checked .*2026/)
  // No stamp → no clock, rather than a render-time clock that looks like scan time.
  assert.doesNotMatch(await renderCard({ structuredContent: scanCard({ url: 'https://uw.test/', summary: ZERO, issues: [], issuesTotal: 0 }), content: [] }), /Scanned at/)
})
