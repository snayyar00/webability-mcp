/**
 * verify_fix with no `wcag` checks the element at AA, the product's
 * conformance level. It used to scan at AAA, so a fix that meets AA (text at
 * 5.3:1) read as NOT RESOLVED because of the AAA 7:1 enhanced-contrast rule.
 * A named criterion is still checked whatever its level.
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

import { createServer } from '../src/server.ts'

async function call(name: string, args: Record<string, unknown>) {
  const [c, s] = InMemoryTransport.createLinkedPair()
  const cl = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([createServer({}).connect(s), cl.connect(c)])
  const r: any = await cl.callTool({ name, arguments: args }, undefined, { timeout: 120_000 })
  const text = (r.content as any[]).map((x) => String(x.text ?? '')).join('\n')
  const m = text.match(/```json\n([\s\S]*?)\n```/)
  return { text, json: m ? JSON.parse(m[1]!) : null }
}

// #6b6b6b on #ffffff is 5.3:1: passes 1.4.3 (AA, 4.5:1), fails 1.4.6 (AAA, 7:1).
const PAGE = `<!doctype html><html lang="en"><head><title>AA</title></head><body style="background:#fff"><main><h1>Fixed</h1><p id="note" style="color:#6b6b6b;font-size:16px">Enrollment closes on Friday.</p></main></body></html>`

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

test('verify_fix with no wcag passes an element that meets AA', async () => {
  const r = await call('verify_fix', { url: base, selector: '#note' })
  assert.equal(r.json?.verified, true, r.text)
})

test('a named AAA criterion is still checked', async () => {
  const r = await call('verify_fix', { url: base, selector: '#note', wcag: '1.4.6' })
  assert.equal(r.json?.verified, false, r.text)
})
