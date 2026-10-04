/**
 * Persona round 4 (c22, docs.python.org `a.skip-link`): verify_fix returned
 * `"verified": true, "remainingCount": 0` for a selector that matched NO
 * element — a hedge sentence in the text, but the machine verdict said
 * "fixed". An agent reads the boolean. A selector that matches nothing has
 * verified nothing, so the verdict must be false with reason "not-found".
 *
 * Drives the real verify_fix (local transport) against a page served on
 * localhost.
 */
process.env.WEBABILITY_SCAN_TELEMETRY = 'off'
process.env.WEBABILITY_SCAN_LOG = 'off'

import assert from 'node:assert/strict'
import { createServer as createHttpServer, type Server as HttpServer } from 'node:http'
import { after, before, test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer } from '../src/server.ts'

const PAGE = `<!doctype html><html lang="en"><head><title>Verify</title></head><body style="background:#fff;color:#000">
<main><h1>Verify</h1>
  <img id="good" src="data:image/gif;base64,R0lGODlhAQABAAAAACw=" alt="Company logo" width="40" height="40">
  <p id="ok">Plain readable paragraph.</p>
</main></body></html>`

let http: HttpServer
let url = ''
before(async () => {
  http = createHttpServer((_, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(PAGE) })
  await new Promise<void>((r) => http.listen(0, '127.0.0.1', () => r()))
  url = `http://127.0.0.1:${(http.address() as any).port}/`
})
after(() => http?.close())

async function verify(args: Record<string, unknown>) {
  const [c, s] = InMemoryTransport.createLinkedPair()
  const server = createServer({})
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(s), client.connect(c)])
  const r: any = await client.callTool({ name: 'verify_fix', arguments: { url, ...args } }, undefined, { timeout: 180_000 })
  const text = (r.content as any[]).map((x) => String(x.text ?? '')).join('\n')
  const json = JSON.parse(text.match(/```json\n([\s\S]*)\n```/)![1]!)
  return { text, json }
}

test('a selector that matches nothing is NOT verified', async () => {
  const { text, json } = await verify({ selector: 'a.skip-link', wcag: '2.4.1' })
  assert.equal(json.verified, false, text)
  assert.equal(json.reason, 'not-found')
  assert.doesNotMatch(text, /^VERIFIED/m)
  // Same keys as the normal payload so consumers reading them do not break.
  assert.equal(json.remainingCount, null)
  assert.deepEqual(json.remainingIssues, [])
  assert.match(text, /removed the element/)
})

test('an invalid selector is NOT verified', async () => {
  const { text, json } = await verify({ selector: 'p[[bad', wcag: '1.4.3' })
  assert.equal(json.verified, false, text)
  assert.equal(json.reason, 'invalid-selector')
})

test('control: a clean element that exists is still verified', async () => {
  const { text, json } = await verify({ selector: '#ok', wcag: '1.4.3' })
  assert.equal(json.verified, true, text)
  assert.match(text, /^VERIFIED/m)
})
