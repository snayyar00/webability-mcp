/**
 * MCP dogfood 2026-10-03: the default scan_page response on allbirds.com was
 * 107,921 chars; the client refused it inline and spilled it to a file, so
 * the first question a store owner asks failed. The default response must fit
 * inline (< 25k chars) while every finding stays counted, and full detail
 * stays one explicit arg away (format: "json", rules[], wcag[]).
 *
 * Drives the real scan_page (local transport) against a page served on
 * localhost that yields ~90 visual-tier findings — visual findings never
 * collapse, each carries up to 400 chars of html.
 */
process.env.WEBABILITY_SCAN_TELEMETRY = 'off'
process.env.WEBABILITY_SCAN_LOG = 'off'

import assert from 'node:assert/strict'
import { createServer as createHttpServer, type Server as HttpServer } from 'node:http'
import { after, before, test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer } from '../src/server.ts'

const LONG = 'utility-class-' + 'x'.repeat(30)
const cls = Array.from({ length: 8 }, (_, k) => `${LONG}-${k}`).join(' ')
const rows: string[] = []
for (let i = 0; i < 30; i++) {
  const g = (150 + i).toString(16)
  rows.push(`<p class="${cls}" style="color:#${g}${g}${g}">Low contrast paragraph number ${i}</p>`)
  rows.push(`<label for="f${i}">Field ${i}</label><input id="f${i}" class="${cls}" style="border:1px solid #f${i % 10}f${i % 10}f${i % 10};background:#fff">`)
  rows.push(`<div><button aria-label="a${i}" class="${cls}" style="width:14px;height:14px;padding:0;border:1px solid #000"></button><button aria-label="b${i}" class="${cls}" style="width:14px;height:14px;padding:0;margin-left:2px;border:1px solid #000"></button></div>`)
}
const PAGE = `<!doctype html><html lang="en"><head><title>Budget</title></head><body style="background:#fff;color:#000"><main><h1>Budget</h1>${rows.join('\n')}</main></body></html>`

let http: HttpServer
let url = ''
before(async () => {
  http = createHttpServer((_, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(PAGE) })
  await new Promise<void>((r) => http.listen(0, '127.0.0.1', () => r()))
  url = `http://127.0.0.1:${(http.address() as any).port}/`
})
after(() => http?.close())

async function scanPage(extra: Record<string, unknown>) {
  const [c, s] = InMemoryTransport.createLinkedPair()
  const server = createServer({})
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(s), client.connect(c)])
  const r: any = await client.callTool({ name: 'scan_page', arguments: { url, ...extra } }, undefined, { timeout: 180_000 })
  return (r.content as any[]).map((x) => String(x.text ?? '')).join('\n')
}

const BUDGET = 25_000

test('default scan_page response fits inline and counts every finding', async () => {
  const full = await scanPage({ format: 'json' })
  const fullJson = JSON.parse(full.match(/```json\n([\s\S]*)\n```/)![1]!)
  assert.ok(full.length > BUDGET, `fixture must overflow the budget in JSON (got ${full.length}) or it exercises nothing`)
  const total = fullJson.summary.total as number
  assert.ok(total >= 60, `fixture yields ${total} issues`)

  const text = await scanPage({})
  assert.ok(text.length < BUDGET, `default response is ${text.length} chars`)
  assert.match(text, /format: "json"/, 'says how to get the full JSON')
  // Counts survive: the structured summary block carries the same totals.
  const block = JSON.parse(text.match(/```json\n([\s\S]*)\n```/)![1]!)
  assert.equal(block.summary.total, total)
  assert.equal(block.issuesTotal, fullJson.issuesTotal)
  const byRuleSum = Object.values(block.byRule as Record<string, number>).reduce((a, b) => a + b, 0)
  assert.equal(byRuleSum, fullJson.issuesTotal, 'per-rule counts add up to every issue')
})

test('format: "json" is always the full JSON, whatever its size', async () => {
  const text = await scanPage({ format: 'json' })
  assert.ok(text.length > BUDGET)
  assert.doesNotMatch(text, /over the inline budget/)
})
