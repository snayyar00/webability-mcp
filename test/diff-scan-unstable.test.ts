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
// A pair scans at once, so arrival order says nothing about the side. The current
// side asks for /?c. Baseline loads are numbered 1, 3 and current loads 2, 4.
const loadNumber = (seen: { baseline: number; current: number }, reqUrl: string | undefined) =>
  reqUrl === '/?c' ? 2 * ++seen.current : 2 * ++seen.baseline - 1
let seen = { baseline: 0, current: 0 }
const http = createHttpServer((req, res) => {
  if (req.url !== '/' && req.url !== '/?c') { res.writeHead(204); res.end(); return }
  hits++
  const load = loadNumber(seen, req.url)
  res.writeHead(200, { 'content-type': 'text/html' })
  res.end(page(badLoads.has(load), imagesByLoad[load - 1] ?? 0))
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
  seen = { baseline: 0, current: 0 }
  badLoads = new Set(loads)
  imagesByLoad = images
  const r: any = await client.callTool({ name: 'diff_scan', arguments: { baselineUrl: url, url: url + '?c', format: 'json' } })
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
const hostedDiff = async (budgetMs: number | undefined, delayMs: number, hangFrom: number) => {
  const { openSession } = await import('../src/browser.ts')
  const seenSlow = { baseline: 0, current: 0 }
  let thirdLoadAt = 0
  const startedAt: Record<number, number> = {}
  const sockets = new Set<import('node:net').Socket>()
  const slow = createHttpServer((req, res) => {
    if (req.url !== '/' && req.url !== '/?c') { res.writeHead(204); res.end(); return }
    const load = loadNumber(seenSlow, req.url)
    startedAt[load] = Date.now()
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
        const target = new URL(route.request().url())
        const res = await fetch(localBase + target.pathname + target.search).catch(() => null)
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
    const r: any = await c.callTool({ name: 'diff_scan', arguments: { baselineUrl: slowUrl, url: slowUrl + '?c', format: 'json', context: 'Checking the hosted diff budget covers the second pass.' } })
    const text = r.content.map((x: any) => x.text).join('\n')
    assert.notEqual(r.isError, true, text)
    return { text, elapsed: Date.now() - started, started, thirdLoadAt, startedAt }
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
  // Each load takes 12s plus the scan, so the first pair takes over half the budget.
  const BUDGET_MS = 22_000
  const { text, elapsed, thirdLoadAt } = await hostedDiff(BUDGET_MS, 12_000, 99)
  assert.equal(thirdLoadAt, 0, 'no third load')
  assert.ok(elapsed < BUDGET_MS, `returned after ${elapsed}ms`)
  assert.match(text, /^UNCONFIRMED: 1 possible new/)
}, 45_000)

// Seen on prod: 12.6s scans, one after the other, ran past the 25s hosted budget
// on both real pages tried. Two scans at once take about as long as one.
test('hosted diff_scan: a pair that fits only at once scans at once', async () => {
  const DELAY_MS = 7_000
  const { text, startedAt } = await hostedDiff(18_000, DELAY_MS, 99)
  assert.ok(Math.abs(startedAt[1] - startedAt[2]) < DELAY_MS, `load 1 and load 2 started ${Math.abs(startedAt[1] - startedAt[2])}ms apart`)
  assert.match(text, /^UNCONFIRMED: 1 possible new/)
}, 45_000)

test('hosted diff_scan: when one side fails, the other scan stops too', async () => {
  const { openSession } = await import('../src/browser.ts')
  const realLookup = dnsPromises.lookup
  ;(dnsPromises as any).lookup = async () => [{ address: '93.184.215.14', family: 4 }]
  let opened = 0
  const closed = new Set<unknown>()
  const [a, b] = InMemoryTransport.createLinkedPair()
  const server = createServer({
    remote: true,
    authToken: 'test-token',
    scanPageDeadlineMs: 20_000,
    openSession: async (o) => {
      const session = await openSession({ ...o, remote: false, setupContext: undefined })
      opened++
      const close = session.close.bind(session)
      session.close = async () => { closed.add(session); await close() }
      await session.context.route('http://fail-diff.test/**', async (route: any) => {
        if (route.request().url().endsWith('?c')) return route.abort() // the current side fails at once
        // the baseline side never answers
      })
      return session
    },
  })
  const c = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(b), c.connect(a)])
  try {
    const started = Date.now()
    const r: any = await c.callTool({ name: 'diff_scan', arguments: { baselineUrl: 'http://fail-diff.test/', url: 'http://fail-diff.test/?c', format: 'json', context: 'Checking a failed side stops the other scan in a pair.' } })
    const elapsed = Date.now() - started
    assert.equal(r.isError, true)
    assert.ok(elapsed < 10_000, `returned after ${elapsed}ms`)
    // A session still opening when the failure comes closes as soon as it opens.
    for (let i = 0; i < 80 && closed.size < 2; i++) await new Promise((r) => setTimeout(r, 100))
    assert.equal(closed.size, 2, `${opened} opened, ${closed.size} closed: both browser sessions must be closed`)
  } finally {
    ;(dnsPromises as any).lookup = realLookup
    await c.close()
  }
}, 45_000)

// Seen on prod: two diff_scan calls together ran 4 Chromiums and both timed out.
// The hosted server builds one server per request, so the limit must span them.
test('hosted diff_scan: a second call during a run is refused as busy, and the next call works', async () => {
  const { openSession } = await import('../src/browser.ts')
  const realLookup = dnsPromises.lookup
  ;(dnsPromises as any).lookup = async () => [{ address: '93.184.215.14', family: 4 }]
  let release = () => {}
  let held = new Promise<void>((r) => { release = r })
  let firstLoad = () => {}
  const loading = new Promise<void>((r) => { firstLoad = r })
  const connect = async () => {
    const [a, b] = InMemoryTransport.createLinkedPair()
    const server = createServer({
      remote: true,
      authToken: 'test-token',
      scanPageDeadlineMs: 20_000,
      openSession: async (o) => {
        const session = await openSession({ ...o, remote: false, setupContext: undefined })
        await session.context.route('http://busy-diff.test/**', async (route: any) => {
          firstLoad()
          await held
          await route.fulfill({ status: 200, contentType: 'text/html', body: page(false, 0) }).catch(() => {})
        })
        return session
      },
    })
    const c = new Client({ name: 'test', version: '1' }, { capabilities: {} })
    await Promise.all([server.connect(b), c.connect(a)])
    return c
  }
  const args = { baselineUrl: 'http://busy-diff.test/', url: 'http://busy-diff.test/?c', format: 'json', context: 'Checking overlapping hosted calls.' }
  const [first, second, third] = [await connect(), await connect(), await connect()]
  try {
    const running: Promise<any> = first.callTool({ name: 'diff_scan', arguments: args })
    await loading
    const started = Date.now()
    const busy: any = await second.callTool({ name: 'diff_scan', arguments: args })
    assert.ok(Date.now() - started < 2_000, 'a busy reply must come at once')
    assert.equal(busy.isError, true)
    assert.match(busy.content[0].text, /busy/)
    assert.equal(busy.structuredContent.error.retriable, true)
    release()
    assert.notEqual((await running).isError, true)
    const after: any = await third.callTool({ name: 'diff_scan', arguments: args })
    assert.notEqual(after.isError, true, after.content?.[0]?.text)
  } finally {
    release()
    ;(dnsPromises as any).lookup = realLookup
    await Promise.all([first.close(), second.close(), third.close()])
  }
}, 45_000)

// Seen on prod: kedianomics pairs took 20.7s to 23.1s, and a 25s budget left little room.
test('hosted diff_scan: the default budget runs to 28s and stops before the 30s limit', async () => {
  // The second pair hangs, so the call ends exactly when the budget does.
  const { text, elapsed } = await hostedDiff(undefined, 0, 3)
  assert.ok(elapsed > 26_000, `stopped after ${elapsed}ms`)
  assert.ok(elapsed < 29_500, `stopped after ${elapsed}ms`)
  assert.match(text, /^UNCONFIRMED: 1 possible new/)
}, 45_000)
