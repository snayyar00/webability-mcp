/**
 * diff_scan compares two live loads. A page can differ between two loads with
 * no code change, so a difference has to hold on a second pair of scans before
 * it is called new or fixed. Seen on a live site: one unchanged page gave
 * "2 new, 6 fixed".
 */
import assert from 'node:assert/strict'
import { createServer as createHttpServer } from 'node:http'
import dnsPromises from 'dns/promises'
import { after, before, test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

const { createServer } = await import('../src/server.ts')

let hits = 0
let badLoads = new Set<number>()
let imagesByLoad: number[] = []
const IMG = (n: number) => `<img id="gsi_${n}" src="data:image/gif;base64,R0lGODlhAQABAAAAACw=">`
const page = (bad: boolean, images = 0) => `<!doctype html><html lang="en"><head><title>t</title></head><body><main><h1>t</h1><p>ok</p>${bad ? '<img id="flaky" src="data:image/gif;base64,R0lGODlhAQABAAAAACw=">' : ''}${Array.from({ length: images }, (_, n) => IMG(n)).join('')}</main></body></html>`
const http = createHttpServer((req, res) => {
  if (req.url !== '/') { res.writeHead(204); res.end(); return }
  hits++
  res.writeHead(200, { 'content-type': 'text/html' })
  res.end(page(badLoads.has(hits), imagesByLoad[hits - 1] ?? 0))
})
let url = ''
let client: Client
before(async () => {
  await new Promise<void>((r) => http.listen(0, '127.0.0.1', () => r()))
  url = `http://127.0.0.1:${(http.address() as any).port}/`
  const [a, b] = InMemoryTransport.createLinkedPair()
  const server = createServer({})
  client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(b), client.connect(a)])
})
after(() => { http.close() })

const run = async (loads: number[], images: number[] = []) => {
  hits = 0
  badLoads = new Set(loads)
  imagesByLoad = images
  const r: any = await client.callTool({ name: 'diff_scan', arguments: { baselineUrl: url, url, format: 'json' } })
  assert.notEqual(r.isError, true, r.content?.[0]?.text)
  return { text: r.content.map((c: any) => c.text).join('\n'), loads: hits }
}

test('a finding seen on one load only is unstable, not a regression', async () => {
  const { text, loads } = await run([2])
  assert.equal(loads, 4, 'a difference gets a second pair of scans')
  assert.match(text, /No regressions/)
  assert.match(text, /only one load/)
}, )

test('a finding that holds on the second pair is still a regression', async () => {
  const { text } = await run([2, 4])
  assert.match(text, /REGRESSIONS: 1 new/)
})

test('no difference needs no second pair', async () => {
  const { text, loads } = await run([])
  assert.equal(loads, 2)
  assert.match(text, /No regressions/)
})

// Generated ids share one key, so these findings differ only by count.
test('one more equivalent element on both pairs is still a regression', async () => {
  const { text } = await run([], [1, 2, 1, 2])
  assert.match(text, /REGRESSIONS: 1 new/)
})

test('one fewer equivalent element on both pairs is still a fix', async () => {
  const { text } = await run([], [2, 1, 2, 1])
  assert.match(text, /No regressions: 1 fixed/)
})

test('a count change on one pair only is unstable', async () => {
  const { text } = await run([], [1, 2, 1, 1])
  assert.match(text, /No regressions: 0 fixed/)
  assert.match(text, /only one load/)
})

// Hosted budget. One budget covers the whole call, second pass included.
// The hosted guard refuses local addresses, so the test gives the call a fake
// public host name (DNS stubbed) and its own session, which serves that host
// from a local slow server through openSession.
// Runs one hosted diff_scan. Load 2 differs from load 1, so a second pair is
// wanted. From `hangFrom` on, the page never answers.
const hostedDiff = async (budgetMs: number, delayMs: number, hangFrom: number) => {
  const { openSession } = await import('../src/browser.ts')
  let n = 0
  let thirdLoadAt = 0
  const sockets = new Set<import('node:net').Socket>()
  const slow = createHttpServer((req, res) => {
    if (req.url !== '/') { res.writeHead(204); res.end(); return }
    n++
    const load = n
    if (load >= 3) thirdLoadAt ||= Date.now()
    if (load >= hangFrom) return // never answer
    setTimeout(() => {
      res.writeHead(200, { 'content-type': 'text/html' })
      res.end(page(load === 2, 0))
    }, delayMs)
  })
  slow.on('connection', (s) => { sockets.add(s); s.on('close', () => sockets.delete(s)) })
  await new Promise<void>((r) => slow.listen(0, '127.0.0.1', () => r()))
  const localBase = `http://127.0.0.1:${(slow.address() as any).port}`
  const slowUrl = 'http://slow-diff.test/'
  const realLookup = dnsPromises.lookup
  ;(dnsPromises as any).lookup = async () => [{ address: '93.184.215.14', family: 4 }]
  const [a, b] = InMemoryTransport.createLinkedPair()
  const server = createServer({
    remote: true,
    authToken: 'test-token',
    scanPageDeadlineMs: budgetMs,
    openSession: async (o) => {
      const session = await openSession({ ...o, remote: false, setupContext: undefined })
      await session.context.route('http://slow-diff.test/**', async (route: any) => {
        const res = await fetch(localBase + new URL(route.request().url()).pathname).catch(() => null)
        if (!res) return route.abort().catch(() => {})
        await route.fulfill({ status: res.status, contentType: 'text/html', body: await res.text() }).catch(() => {})
      })
      return session
    },
  })
  const c = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(b), c.connect(a)])
  try {
    const started = Date.now()
    const r: any = await c.callTool({ name: 'diff_scan', arguments: { baselineUrl: slowUrl, url: slowUrl, format: 'json', context: 'Checking the hosted diff budget covers the second pass.' } })
    const text = r.content.map((x: any) => x.text).join('\n')
    assert.notEqual(r.isError, true, text)
    return { text, elapsed: Date.now() - started, started, thirdLoadAt }
  } finally {
    ;(dnsPromises as any).lookup = realLookup
    await c.close()
    for (const s of sockets) s.destroy()
    slow.close()
  }
}

test('hosted diff_scan: the second pair shares the call budget and an unfinished pair is unconfirmed', async () => {
  // Wide enough that a first pair on a loaded machine still leaves room for the second.
  const BUDGET_MS = 24_000
  const { text, elapsed, started, thirdLoadAt } = await hostedDiff(BUDGET_MS, 0, 3)
  assert.ok(thirdLoadAt > 0, 'the second pair must have started')
  assert.ok(thirdLoadAt - started > 500, 'the first pair must take a visible time, or this test cannot tell a restarted budget')
  assert.ok(elapsed < BUDGET_MS + 1_500, `returned after ${elapsed}ms; budget ${BUDGET_MS}ms counts from the start of the call`)
  assert.match(text, /^UNCONFIRMED: 1 possible new/)
  assert.doesNotMatch(text, /REGRESSIONS/)
  assert.match(text, /"unconfirmed": ?true/)
}, 45_000)

test('hosted diff_scan: a second pair that cannot fit does not start, and the reply comes early', async () => {
  // Each load takes 5s plus the scan, so the first pair takes over half the budget.
  const BUDGET_MS = 22_000
  const { text, elapsed, thirdLoadAt } = await hostedDiff(BUDGET_MS, 5_000, 99)
  assert.equal(thirdLoadAt, 0, 'no third load')
  assert.ok(elapsed < BUDGET_MS, `returned after ${elapsed}ms`)
  assert.match(text, /^UNCONFIRMED: 1 possible new/)
}, 45_000)
