/**
 * Persona round 4 (22/80 runs): detect_framework returned the CSS toolkit
 * (`tailwind` for svelte.dev) while scan_page.framework said something else
 * for the same page. Both tools now read ONE function and return
 * {framework, cssToolkit} separately — they cannot disagree.
 *
 * Local transport against a localhost SvelteKit-shaped page; hosted refuses
 * loopback (covered by hosted-localhost-refusal.test.ts).
 */
process.env.WEBABILITY_SCAN_TELEMETRY = 'off'
process.env.WEBABILITY_SCAN_LOG = 'off'

import assert from 'node:assert/strict'
import { createServer as createHttpServer, type Server as HttpServer } from 'node:http'
import { after, before, test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer } from '../src/server.ts'

const TW = '<div class="flex p-4 m-2 rounded shadow text-gray-700 bg-gray-100 w-4 h-4 grid">x</div>'.repeat(3)
const PAGE = `<!doctype html><html lang="en"><head><title>Kit</title></head><body data-sveltekit-preload-data="hover"><main><h1>Kit</h1>${TW}<img src="/a.png"></main></body></html>`

let http: HttpServer
let url = ''
before(async () => {
  http = createHttpServer((_, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(PAGE) })
  await new Promise<void>((r) => http.listen(0, '127.0.0.1', () => r()))
  url = `http://127.0.0.1:${(http.address() as any).port}/`
})
after(() => http?.close())

async function call(name: string, args: Record<string, unknown>) {
  const [c, s] = InMemoryTransport.createLinkedPair()
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([createServer({}).connect(s), client.connect(c)])
  const r: any = await client.callTool({ name, arguments: args }, undefined, { timeout: 180_000 })
  const text = (r.content as any[]).map((x) => String(x.text ?? '')).join('\n')
  const m = text.match(/```json\n([\s\S]*?)\n```/)
  return { r, text, json: m ? JSON.parse(m[1]!) : null }
}

test('detect_framework and scan_page give the same {framework, cssToolkit}', async () => {
  const df = await call('detect_framework', { url })
  const sp = await call('scan_page', { url, format: 'json' })
  assert.ok(df.json, `detect_framework returns a JSON block: ${df.text}`)
  assert.equal(df.json.framework, 'sveltekit')
  assert.equal(df.json.cssToolkit, 'tailwind')
  assert.equal(sp.json.framework, df.json.framework)
  assert.equal(sp.json.cssToolkit, df.json.cssToolkit)
  // cssFramework is a deprecated alias kept for JSON consumers of <= 1.6.4.
  assert.ok('cssFramework' in sp.json, 'deprecated cssFramework alias still emitted')
  assert.equal(sp.json.cssFramework, sp.json.cssToolkit)
  assert.match(df.text, /^Framework: sveltekit$/m)
  assert.match(df.text, /^CSS toolkit: tailwind$/m)
  assert.ok(Array.isArray(df.json.evidence) && df.json.evidence.length > 0, 'names its evidence')
  assert.equal(df.json.aiFixFramework, 'tailwind', 'the value to pass to generate_ai_fix')
})

test('detect_framework: missing url and an unreachable url are honest errors', async () => {
  const none = await call('detect_framework', {})
  assert.equal(none.r.isError, true)
  assert.match(none.text, /^Error: url is required/)
  const dead = await call('detect_framework', { url: 'http://127.0.0.1:9/' })
  assert.equal(dead.r.isError, true)
  assert.match(dead.text, /^Detection failed:/)
})
