/**
 * Wave 8 — the scanner judges uncertain findings itself. No tool output may
 * contain an `incomplete[]` / "needs review" bucket, a review count, or text
 * telling the agent to treat findings as questions.
 */
process.env.WEBABILITY_SCAN_TELEMETRY = 'off'
process.env.WEBABILITY_SCAN_LOG = 'off'

import assert from 'node:assert/strict'
import { createServer as createHttpServer, type Server as HttpServer } from 'node:http'
import { after, before, test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer } from '../src/server.ts'

// Everything below used to land in incomplete[]: text on a gradient, a
// cross-page link-label variation, a duplicated id, a dangling aria-controls.
const PAGE = `<!doctype html><html lang="en"><head><title>Review</title></head><body><main id="m"><h1>Review</h1>
<div style="background:linear-gradient(90deg,#999,#fff);padding:20px"><p style="color:#bbb">Mixed gradient text</p></div>
<p><a href="/x">Read more</a> <a href="/y">Learn more</a> <a href="/z">More</a></p>
<div id="dup">a</div><div id="dup">b</div>
<button aria-expanded="false" aria-controls="not-here">Toggle</button>
<img src="/company-logo.png" alt="Acme logo text" width="200" height="40">
</main></body></html>`

const BANNED = /needs[ -]review|need(?:s)? human review|human review|do NOT auto-fix|incomplete/i

let http: HttpServer
let url = ''
let client: Client

before(async () => {
  http = createHttpServer((_, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(PAGE) })
  await new Promise<void>((r) => http.listen(0, '127.0.0.1', () => r()))
  url = `http://127.0.0.1:${(http.address() as any).port}/`
  const [c, s] = InMemoryTransport.createLinkedPair()
  const server = createServer({})
  client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(s), client.connect(c)])
})
after(() => http?.close())

const call = async (name: string, args: Record<string, unknown>) => {
  const r: any = await client.callTool({ name, arguments: args }, undefined, { timeout: 180_000 })
  return (r.content as any[]).map((x) => String(x.text ?? '')).join('\n')
}

test('no tool description mentions a review bucket', async () => {
  const { tools } = await client.listTools()
  for (const t of tools) {
    const blob = JSON.stringify([t.description, t.inputSchema])
    assert.doesNotMatch(blob, BANNED, `${t.name}: ${blob.match(BANNED)?.[0]}`)
  }
})

for (const format of ['json', 'compact'] as const) {
  test(`scan_page (${format}) has no review bucket, count or wording`, async () => {
    const text = await call('scan_page', { url, format })
    assert.doesNotMatch(text, BANNED, text.match(BANNED)?.[0])
  })
}

test('scan_html has no review bucket, count or wording', async () => {
  const text = await call('scan_html', { html: PAGE })
  assert.doesNotMatch(text, BANNED, text.match(BANNED)?.[0])
})

test('check_aria has no review bucket, count or wording', async () => {
  const text = await call('check_aria', { html: PAGE })
  assert.doesNotMatch(text, BANNED, text.match(BANNED)?.[0])
})

test('flow_scan has no review bucket, count or wording', async () => {
  const text = await call('flow_scan', { startUrl: url, autoNavigate: [url + '?b=1'] })
  assert.doesNotMatch(text, BANNED, text.match(BANNED)?.[0])
})

test('diff_scan has no review bucket, count or wording', async () => {
  const text = await call('diff_scan', { url, baselineUrl: url })
  assert.doesNotMatch(text, BANNED, text.match(BANNED)?.[0])
})
