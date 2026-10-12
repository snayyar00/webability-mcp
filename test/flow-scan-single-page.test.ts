/**
 * flow_scan without autoNavigate used to be a hard error ("requires
 * autoNavigate"): 109 of 110 hosted calls failed in 30 days of production
 * telemetry, because agents call it with only a startUrl. It now scans
 * startUrl as one page (same result as scan_page) with a note, and keeps the
 * multi-page walk when autoNavigate is given.
 *
 * Local server (127.0.0.1) + real browser, like aa-default.test.ts.
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
  return { isError: r.isError === true, text, json: m ? JSON.parse(m[1]!) : null }
}

const PAGE = `<!doctype html><html lang="en"><head><title>Home</title></head><body><main><h1>Home</h1><img src="/a.png"><a href="/two">Two</a></main></body></html>`
const TWO = `<!doctype html><html lang="en"><head><title>Two</title></head><body><main><h1>Two</h1><img src="/b.png"></main></body></html>`

let http: HttpServer
let base = ''
before(async () => {
  http = createHttpServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' })
    res.end(req.url === '/two' ? TWO : PAGE)
  })
  await new Promise<void>((r) => http.listen(0, '127.0.0.1', () => r()))
  base = `http://127.0.0.1:${(http.address() as any).port}/`
})
after(() => http?.close())

test('flow_scan {startUrl} only is not an error: scans the start page', async () => {
  const r = await call('flow_scan', { startUrl: base })
  assert.equal(r.isError, false, r.text)
  assert.match(r.text, /only the start page was scanned/i)
  assert.match(r.text, /autoNavigate/)
  assert.ok(r.json, 'has the scan_page json block')
  assert.ok((r.json.issues ?? []).length > 0, 'fixture has a missing-alt finding')
})

test('flow_scan {startUrl, autoNavigate: []} behaves the same', async () => {
  const r = await call('flow_scan', { startUrl: base, autoNavigate: [] })
  assert.equal(r.isError, false, r.text)
  assert.match(r.text, /only the start page was scanned/i)
})

test('single-page flow_scan returns the same findings as scan_page', async () => {
  const flow = await call('flow_scan', { startUrl: base })
  const page = await call('scan_page', { url: base })
  assert.deepEqual(
    (flow.json.issues ?? []).map((i: any) => i.id).sort(),
    (page.json.issues ?? []).map((i: any) => i.id).sort(),
  )
})

test('flow_scan {} is still an error (startUrl missing)', async () => {
  const r = await call('flow_scan', {})
  assert.equal(r.isError, true)
  assert.match(r.text, /startUrl is required/)
})

test('flow_scan with autoNavigate keeps the multi-page walk and has no single-page note', async () => {
  const r = await call('flow_scan', { startUrl: base, autoNavigate: [`${base}two`] })
  assert.equal(r.isError, false, r.text)
  assert.doesNotMatch(r.text, /only the start page was scanned/i)
  assert.ok(Array.isArray(r.json.pages), 'multi-page report has pages[]')
  assert.equal(r.json.pages.filter((p: any) => p.status === 'scanned').length, 2)
})

test('flow_scan schema no longer requires autoNavigate', async () => {
  const [c, s] = InMemoryTransport.createLinkedPair()
  const cl = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([createServer({}).connect(s), cl.connect(c)])
  const tool = (await cl.listTools()).tools.find((t) => t.name === 'flow_scan')!
  assert.deepEqual((tool.inputSchema as any).required, ['startUrl'])
})
