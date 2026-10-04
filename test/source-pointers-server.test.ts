/**
 * DEV-1089 items 4–6 at the tool boundary: a real page with a synthetic React
 * fiber tree → `source` on the issue; `format: "compact"` prints the pointer;
 * `scan_html` runs in-process by default and still offers the browser engine.
 */
import assert from 'node:assert/strict'
import { createServer as createHttp } from 'node:http'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

process.env.WEBABILITY_SCAN_LOG_DIR = mkdtempSync(join(tmpdir(), 'wa-src-'))
const { createServer } = await import('../src/server.ts')

async function connect() {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  const server = createServer({})
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  return client
}

// A dev-build lookalike: the image has no alt, and its host node carries a
// React 18 fiber whose _debugSource is the JSX call site.
const PAGE = `<!doctype html><html lang="en"><head><title>Fixture</title></head><body>
<main><h1>Hero</h1><img id="hero" src="data:image/gif;base64,R0lGODlhAQABAAAAACw=">
<script>
  const el = document.getElementById('hero');
  function Hero() {}
  el['__reactFiber$abc'] = {
    type: 'img',
    _debugSource: { fileName: '/app/src/Hero.tsx', lineNumber: 12, columnNumber: 5 },
    _debugOwner: { type: Hero, return: null },
    return: null,
  };
</script></main></body></html>`

const http = createHttp((_req, res) => { res.setHeader('content-type', 'text/html'); res.end(PAGE) })
await new Promise<void>((r) => http.listen(0, '127.0.0.1', r))
const url = `http://127.0.0.1:${(http.address() as any).port}/`
const jsonBlock = (res: any) => JSON.parse(String(res.content[1].text).replace(/^```json\n|\n```$/g, ''))

test('scan_page attaches a React source pointer to the issue', async () => {
  const client = await connect()
  const res: any = await client.callTool({ name: 'scan_page', arguments: { url } })
  const payload = jsonBlock(res)
  const hero = [...payload.issues, ...payload.incomplete].find((i: any) => i.selector.includes('hero') || i.selector.startsWith('img'))
  assert.ok(hero, `expected a finding on the alt-less image, got ${JSON.stringify(payload.issues.map((i: any) => i.selector))}`)
  assert.deepEqual(hero.source, { framework: 'react', file: '/app/src/Hero.tsx', line: 12, column: 5, component: 'Hero' })
})

test('format: "compact" prints one line per element with the file:line pointer', async () => {
  const client = await connect()
  const res: any = await client.callTool({ name: 'scan_page', arguments: { url, format: 'compact' } })
  const text = String(res.content[1].text)
  assert.ok(!text.startsWith('```json'), 'compact output must not be the JSON block')
  assert.match(text, /→ \/app\/src\/Hero\.tsx:12:5 \(Hero\)/)
})

test('minImpact filters before the cap and is echoed in the summary line', async () => {
  const client = await connect()
  const res: any = await client.callTool({ name: 'scan_page', arguments: { url, minImpact: 'critical' } })
  const payload = jsonBlock(res)
  for (const i of payload.issues) assert.equal(i.impact, 'critical')
  assert.match(String(res.content[0].text), /matching the filters \(minImpact=critical\)/)
  const bad: any = await client.callTool({ name: 'scan_page', arguments: { url, minImpact: 'huge' } })
  assert.match(String(bad.content[0].text), /^Error: minImpact/)
})

test('scan_html defaults to the in-process engine and returns structured fixes', async () => {
  const client = await connect()
  const res: any = await client.callTool({ name: 'scan_html', arguments: { html: '<img src="x.png"><button></button>' } })
  const payload = jsonBlock(res)
  assert.equal(payload.engine, 'in-process')
  assert.equal(payload.fragment, true)
  assert.ok(payload.durationMs < 5000, `in-process scan took ${payload.durationMs}ms`)
  const alt = payload.issues.find((i: any) => i.type === 'missing_alt' || i.type === 'image-alt')
  assert.ok(alt, `expected a missing-alt finding, got ${payload.issues.map((i: any) => i.type)}`)
  assert.ok(alt.fix?.op, 'in-process issues carry fix.op')
  assert.ok(alt.fixability, 'in-process issues carry fixability')
  assert.match(String(res.content[0].text), /in-process/)
})

test('scan_html engine: "browser" keeps the axe violations shape', async () => {
  const client = await connect()
  const res: any = await client.callTool({ name: 'scan_html', arguments: { html: '<img src="x.png">', engine: 'browser' } })
  const payload = jsonBlock(res)
  assert.ok(Array.isArray(payload.violations), 'browser engine returns violations[]')
  assert.ok(payload.violations.some((v: any) => v.id === 'image-alt'))
})

test.after(() => http.close())

// Codex P1 on PR #68: a compact or filtered scan_page archived the compact
// text / filtered set, so diff_scan could not use it as a baseline and
// scan_history lost the unfiltered findings. Archive the canonical JSON always.
test('compact + filtered scan_page still archives the canonical unfiltered JSON', async () => {
  const client = await connect()
  const compact: any = await client.callTool({ name: 'scan_page', arguments: { url, format: 'compact', minImpact: 'critical' } })
  assert.ok(!String(compact.content[1].text).startsWith('```json'))
  const hist: any = await client.callTool({ name: 'scan_history', arguments: { limit: 1 } })
  const id = /id=(\S+)/.exec(String(hist.content[0].text))?.[1]
  assert.ok(id, `scan id in history: ${String(hist.content[0].text).slice(0, 200)}`)
  const full: any = await client.callTool({ name: 'scan_history', arguments: { id } })
  const entry = JSON.parse(String(full.content[0].text).replace(/^```json\n|\n```$/g, ''))
  const stored = JSON.parse(String(entry.response.content[1].text).replace(/^```json\n|\n```$/g, ''))
  assert.ok(Array.isArray(stored.issues), 'archive is JSON, not compact text')
  const unfiltered: any = await client.callTool({ name: 'scan_page', arguments: { url } })
  const ref = jsonBlock(unfiltered)
  assert.equal(stored.issues.length + stored.incomplete.length, ref.issuesTotal + ref.incompleteTotal, 'archive holds every finding, not the filtered set')
  const d: any = await client.callTool({ name: 'diff_scan', arguments: { baselineId: id, url } })
  assert.match(String(d.content[0].text), /No regressions/, String(d.content[0].text).slice(0, 200))
})
