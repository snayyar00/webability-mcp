/**
 * scan_page on the engine scans inside iframes, as the pre-engine path did:
 * axe's frame-aware run (AxeBuilder) needs the live Playwright page, which the
 * session hands the engine. The top document is clean; every issue below is
 * inside the same-origin iframe.
 */
process.env.WEBABILITY_SCAN_TELEMETRY = 'off'
process.env.WEBABILITY_SCAN_LOG = 'off'
delete process.env.OPENROUTER_API_KEY

import assert from 'node:assert/strict'
import { createServer as createHttpServer, type Server as HttpServer } from 'node:http'
import { after, before, test } from 'node:test'

import { scanPageOnEngine } from '../src/server.ts'

const TOP = '<!doctype html><html lang="en"><head><title>Top</title></head><body><main><h1>Top</h1><iframe title="Inner" src="/frame"></iframe></main></body></html>'
const FRAME = '<!doctype html><html lang="en"><head><title>Inner</title></head><body><img src="data:image/png;base64,iVBORw0KGgo="><button></button></body></html>'

let http: HttpServer
let base = ''
before(async () => {
  http = createHttpServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' })
    res.end(req.url === '/frame' ? FRAME : TOP)
  })
  await new Promise<void>((r) => http.listen(0, '127.0.0.1', () => r()))
  base = `http://127.0.0.1:${(http.address() as any).port}/`
})
after(() => http?.close())

test('scan_page reports axe findings inside a same-origin iframe', { timeout: 120_000 }, async () => {
  const { result } = await scanPageOnEngine(base, null, 'desktop', { level: 'AA' }, false)
  const found = result.issues.map((i) => `${i.type} ${i.selector}`)
  assert.ok(result.issues.some((i) => /image-alt|missing_alt/.test(String(i.type))), `no image-alt from the iframe: ${JSON.stringify(found)}`)
  assert.ok(result.issues.some((i) => /button-name|button/.test(String(i.type))), `no button-name from the iframe: ${JSON.stringify(found)}`)
})
