/**
 * scan_page answers with the same JSON fields after moving onto the one
 * engine (@webability/core/engine); scan_html (still scanDocument) is pinned
 * too. The field lists below were recorded from the pre-engine path on main
 * b6437fe7 (scan() direct, scanDocument) on the same inputs; this file passes
 * on both.
 *
 * scan_page uses a local page with a rule that repeats (five unlabelled
 * inputs), so the grouped fields (count, examples, expand) appear; no network.
 */
process.env.WEBABILITY_SCAN_TELEMETRY = 'off'
process.env.WEBABILITY_SCAN_LOG = 'off'
delete process.env.OPENROUTER_API_KEY

import assert from 'node:assert/strict'
import { createServer as createHttpServer, type Server as HttpServer } from 'node:http'
import { after, before, test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer } from '../src/server.ts'

async function call(name: string, args: Record<string, unknown>) {
  const [c, s] = InMemoryTransport.createLinkedPair()
  const cl = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([createServer({}).connect(s), cl.connect(c)])
  const r: any = await cl.callTool({ name, arguments: args }, undefined, { timeout: 180_000 })
  const text = (r.content as any[]).map((x) => String(x.text ?? '')).join('\n')
  const m = text.match(/```json\n([\s\S]*?)\n```/)
  return { isError: r.isError === true, text, json: m ? JSON.parse(m[1]!) : null }
}

const PAGE = '<!doctype html><html lang="en"><head><title>Form</title></head><body><main><h1>Form</h1><form><input type="text"><input type="text"><input type="text"><input type="text"><input type="text"><img src="data:image/png;base64,iVBORw0KGgo="><button></button><button></button><button></button></form></main></body></html>'

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

const keys = (o: object) => Object.keys(o).sort()
const issueKeys = (list: object[]) => [...new Set(list.flatMap((i) => Object.keys(i)))].sort()

test('scan_page on a local page: same top-level and issue fields', { timeout: 180_000 }, async () => {
  const r = await call('scan_page', { url: base, format: 'json' })
  assert.equal(r.isError, false, r.text.slice(0, 300))
  assert.deepEqual(keys(r.json), ['counts', 'cssFramework', 'cssToolkit', 'framework', 'internal_bugs', 'issueEntries', 'issues', 'issuesReturned', 'issuesTotal', 'summary', 'truncated', 'url'])
  assert.deepEqual(keys(r.json.summary), ['critical', 'minor', 'moderate', 'serious', 'total'])
  assert.deepEqual(issueKeys(r.json.issues), ['count', 'examples', 'expand', 'fix', 'fixability', 'html', 'id', 'impact', 'message', 'selector', 'type', 'wcag'])
  assert.ok(r.json.issuesTotal > 0)
  assert.ok(r.json.issues.some((i: any) => i.count > 1), 'the fixture must group a repeated rule')
})

test('scan_html in-process: same top-level and issue fields', { timeout: 60_000 }, async () => {
  const r = await call('scan_html', { html: '<img src="a.png"><button></button><a href="#"></a>' })
  assert.equal(r.isError, false, r.text.slice(0, 300))
  assert.deepEqual(keys(r.json), ['durationMs', 'engine', 'fragment', 'internal_bugs', 'issues', 'skippedVisual', 'summary'])
  assert.deepEqual(issueKeys(r.json.issues), ['fix', 'fixability', 'html', 'id', 'impact', 'level', 'message', 'selector', 'type', 'wcag'])
  assert.deepEqual(r.json.issues.map((i: any) => i.type).sort(), ['button-name', 'image-alt', 'link-name'])
})
