/**
 * scan_page runs on the one engine (runEngine from @webability/core/engine).
 *
 * - Tunnelling: the relay route is on the session's context before the
 *   engine's own navigation, so the tunnel secret reaches the main document
 *   through the engine path (hosted mode: the SSRF guard runs too).
 * - Default = deterministic only: no Model is injected, the agent stage does
 *   not run, 0 model calls, and no HTTP call leaves this process.
 */
process.env.WEBABILITY_SCAN_TELEMETRY = 'off'
process.env.WEBABILITY_SCAN_LOG = 'off'
delete process.env.OPENROUTER_API_KEY

import assert from 'node:assert/strict'
import { createServer as createHttpServer, type Server as HttpServer } from 'node:http'
import { after, before, test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { openSession } from '../src/browser.ts'
import { createServer, scanPageOnEngine } from '../src/server.ts'
import { parseTunnelTarget, TUNNEL_SECRET_HEADER } from '../src/tunnelAuth.ts'

const PAGE = '<!doctype html><html lang="en"><head><title>App</title></head><body><main><h1>App</h1><img src="data:image/png;base64,iVBORw0KGgo="><button></button></main></body></html>'

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

test('tunnel: the secret reaches the main document through the engine navigation', { timeout: 120_000 }, async () => {
  const ID = '29dc0021f320e7f525be802aa18b1b58'
  const SECRET = 'b'.repeat(64)
  const url = `https://tunnel.webability.io/t/${ID}/app.html`
  const tunnel = parseTunnelTarget(url, SECRET)
  assert.ok(tunnel)
  const seen: Array<{ url: string; secret?: string }> = []
  // The real session, with the context's route wrapped: the SSRF/relay guard
  // the server installs decides the headers; this wrapper records them and
  // answers the relay locally instead of going to the network.
  const open: typeof openSession = (o) =>
    openSession({
      ...o,
      setupContext: async (ctx: any) => {
        const recorder = {
          route: (pattern: string, handler: (r: any) => unknown) =>
            ctx.route(pattern, (route: any) =>
              handler({
                request: () => route.request(),
                abort: () => route.abort(),
                continue: async (opt?: { headers?: Record<string, string> }) => {
                  const u = route.request().url()
                  seen.push({ url: u, secret: opt?.headers?.[TUNNEL_SECRET_HEADER] })
                  if (u === url) return route.fulfill({ status: 200, contentType: 'text/html', body: PAGE })
                  return route.abort()
                },
              }),
            ),
        }
        await o.setupContext?.(recorder)
      },
    })
  const { result } = await scanPageOnEngine(url, tunnel, 'desktop', { level: 'AA' }, true, undefined, open)
  const main = seen.find((s) => s.url === url)
  assert.ok(main, `the engine never requested the tunnel URL: ${JSON.stringify(seen)}`)
  assert.equal(main.secret, SECRET)
  assert.equal(result.blocked, undefined)
  assert.ok(result.issues.some((i) => /button/.test(String(i.type))), JSON.stringify(result.issues.map((i) => i.type)))
})

test('default scan_page: deterministic only, 0 model calls, no outbound HTTP', { timeout: 120_000 }, async () => {
  const realFetch = globalThis.fetch
  let fetches = 0
  globalThis.fetch = (async (...a: Parameters<typeof fetch>) => {
    fetches++
    return realFetch(...a)
  }) as typeof fetch
  try {
    const { result } = await scanPageOnEngine(base, null, 'desktop', { level: 'AA' }, false)
    assert.equal(result.stats.agent.ran, false)
    assert.equal(result.stats.agent.skipped, 'no model injected')
    assert.ok(result.issues.length > 0)
    assert.deepEqual(result.internal_bugs, [])

    const [c, s] = InMemoryTransport.createLinkedPair()
    const cl = new Client({ name: 'test', version: '1' }, { capabilities: {} })
    await Promise.all([createServer({}).connect(s), cl.connect(c)])
    const r: any = await cl.callTool({ name: 'scan_page', arguments: { url: base, format: 'json' } }, undefined, { timeout: 120_000 })
    assert.notEqual(r.isError, true)
    const json = JSON.parse(String(r.content.map((x: any) => x.text).join('\n').match(/```json\n([\s\S]*?)\n```/)?.[1]))
    assert.equal(json.judged, undefined, 'no judge without a key')
    assert.deepEqual(json.internal_bugs, [], 'internal_bugs: always present, empty on a clean run (invariant P gate)')
    assert.equal(fetches, 0)
  } finally {
    globalThis.fetch = realFetch
  }
})

test('scan() throws after a good load: the tool fails, never a clean 0-finding result', { timeout: 120_000 }, async () => {
  // Navigation succeeds, then scan() throws (here: page.url() fails after the
  // load). runEngine records an engine:scan internal bug with an empty issue
  // list; scan_page / diff_scan must not read that as "0 issues" (diff_scan
  // would mark every baseline finding fixed).
  const open: typeof openSession = async (o) => {
    const session = await openSession(o)
    ;(session.page as any).url = () => {
      throw new Error('Execution context was destroyed, most likely because of a navigation')
    }
    return session
  }
  await assert.rejects(scanPageOnEngine(base, null, 'desktop', { level: 'AA' }, false, undefined, open), (err: Error) => {
    assert.match(err.message, /scan\(\) threw, every finding dropped: Error: Execution context was destroyed/)
    // The tool answers with this text (hosted too): the message only, no stack frames or install paths.
    assert.doesNotMatch(err.message, /\n|\bat \//)
    return true
  })
})
