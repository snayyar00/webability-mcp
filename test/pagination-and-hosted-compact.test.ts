/**
 * Small output by default on hosted, and a way past the 50-issue cap
 * (note 2026-11-05-learn-from-best-mcps, change 1).
 *
 * - Hosted scan tools default to format "compact" when the caller passes none.
 *   An explicit format always wins. Local stays "json".
 * - scan_page takes `offset`: an index into the severity-sorted list. The
 *   response says where the next page starts (`nextOffset`, null at the end).
 *
 * Drives the real scan_page (local transport) against a localhost page that
 * yields more than 50 visual-tier findings, as inline-budget.test.ts does.
 */
process.env.WEBABILITY_SCAN_TELEMETRY = 'off'
process.env.WEBABILITY_SCAN_LOG = 'off'

import assert from 'node:assert/strict'
import { createServer as createHttpServer, type Server as HttpServer } from 'node:http'
import { after, before, test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { parseOutputControls } from '../src/outputControls.ts'
import { createServer } from '../src/server.ts'

test('hosted default is compact; explicit format wins; local stays json', () => {
  assert.equal(parseOutputControls({}, { hosted: true }).format, 'compact')
  assert.equal(parseOutputControls({}, { hosted: true }).formatExplicit, false)
  assert.equal(parseOutputControls({ format: 'json' }, { hosted: true }).format, 'json')
  assert.equal(parseOutputControls({ format: 'json' }, { hosted: true }).formatExplicit, true)
  assert.equal(parseOutputControls({}).format, 'json')
})

test('offset must be a non-negative integer', () => {
  assert.equal(parseOutputControls({ offset: 50 }).offset, 50)
  assert.equal(parseOutputControls({}).offset, 0)
  assert.throws(() => parseOutputControls({ offset: -1 }), /offset/)
  assert.throws(() => parseOutputControls({ offset: 1.5 }), /offset/)
  assert.throws(() => parseOutputControls({ offset: 'x' }), /offset/)
})

const cls = Array.from({ length: 8 }, (_, k) => `utility-class-${k}`).join(' ')
const rows: string[] = []
for (let i = 0; i < 30; i++) {
  const g = (150 + i).toString(16)
  rows.push(`<p class="${cls}" style="color:#${g}${g}${g}">Low contrast paragraph number ${i}</p>`)
  rows.push(`<div><button aria-label="a${i}" class="${cls}" style="width:14px;height:14px;padding:0;border:1px solid #000"></button><button aria-label="b${i}" class="${cls}" style="width:14px;height:14px;padding:0;margin-left:2px;border:1px solid #000"></button></div>`)
}
const PAGE = `<!doctype html><html lang="en"><head><title>Paging</title></head><body style="background:#fff;color:#000"><main><h1>Paging</h1>${rows.join('\n')}</main></body></html>`

let http: HttpServer
let url = ''
before(async () => {
  http = createHttpServer((_, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(PAGE) })
  await new Promise<void>((r) => http.listen(0, '127.0.0.1', () => r()))
  url = `http://127.0.0.1:${(http.address() as any).port}/`
})
after(() => http?.close())

async function scanJson(extra: Record<string, unknown>) {
  const [c, s] = InMemoryTransport.createLinkedPair()
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([createServer({}).connect(s), client.connect(c)])
  const r: any = await client.callTool({ name: 'scan_page', arguments: { url, format: 'json', ...extra } }, undefined, { timeout: 180_000 })
  await client.close()
  const text = (r.content as any[]).map((x) => String(x.text ?? '')).join('\n')
  return { text, body: JSON.parse(text.match(/```json\n([\s\S]*)\n```/)![1]!) }
}

test('offset pages past the 50-issue cap and reports the next page', async () => {
  const first = await scanJson({})
  assert.ok(first.body.issueEntries > 50, `fixture yields ${first.body.issueEntries} entries; needs more than 50 or it exercises nothing`)
  assert.equal(first.body.issuesReturned, 50)
  assert.equal(first.body.nextOffset, 50)
  assert.match(first.text, /offset: 50/)

  const second = await scanJson({ offset: 50 })
  assert.equal(second.body.offset, 50)
  assert.ok(second.body.issuesReturned > 0)
  const firstIds = new Set(first.body.issues.map((i: any) => i.id ?? i.selector))
  const overlap = second.body.issues.filter((i: any) => firstIds.has(i.id ?? i.selector))
  assert.equal(overlap.length, 0, 'page two repeats page one')
  const expectedNext = 50 + second.body.issuesReturned < second.body.issueEntries ? 100 : null
  assert.equal(second.body.nextOffset, expectedNext)
})

test('an offset past the end returns no issues and no next page', async () => {
  const r = await scanJson({ offset: 100000 })
  assert.equal(r.body.issuesReturned, 0)
  assert.equal(r.body.nextOffset, null)
})

import { INLINE_BUDGET, renderFindingsBlock } from '../src/outputControls.ts'

test('implicit compact output still respects the inline budget; explicit compact does not', () => {
  const items = Array.from({ length: 50 }, (_, i) => ({ id: `i${i}`, type: 'x', impact: 'serious', wcag: '1.1.1', message: 'm', selector: '#' + 'a'.repeat(640) + i }))
  const lists = [{ title: 'Issues', items, total: 50 }]
  const implicit = renderFindingsBlock(parseOutputControls({}, { hosted: true }), { summary: { total: 50 }, issues: items }, lists)
  assert.ok(implicit.text.length <= INLINE_BUDGET, `implicit compact is ${implicit.text.length} chars`)
  assert.match(implicit.text, /not shown/)
  const explicit = renderFindingsBlock(parseOutputControls({ format: 'compact' }, { hosted: true }), { summary: { total: 50 }, issues: items }, lists)
  assert.ok(explicit.text.length > INLINE_BUDGET, 'explicit compact stays unbounded')
})
