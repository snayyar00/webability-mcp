/**
 * Does a hosted browser session refuse a REDIRECT into a private address?
 *
 * installSsrfRoute (context.route) checks the first request only: Playwright
 * does not call a route handler for a redirect hop, so a public URL that
 * answers 302 -> http://169.254.169.254/ used to land the scan on the private
 * page and verify_fix returned its markup (#198). Hosted sessions now send
 * every connection through the egress proxy, which checks the resolved
 * address of every hop.
 *
 * Loopback stands in for both the "public" relay and the private target, so
 * the proxy's address check is injected: only the secret server's port is
 * "private". The production check (isBlockedAddress) is covered without a
 * browser in egress-proxy.test.ts.
 *
 * Needs Chromium, like the other mcp scan tests (CI installs it).
 */
import assert from 'node:assert/strict'
import { createServer, Server } from 'node:http'
import { AddressInfo } from 'node:net'
import { test } from 'node:test'

import { createSessionOpener, launchChromium } from '../src/browser'
import { startEgressProxy } from '../src/egressProxy'

const MARKER = 'internal-metadata-7f3a'

function listen(handler: Parameters<typeof createServer>[1]): Promise<{ server: Server; port: number }> {
  return new Promise((resolve) => {
    const server = createServer(handler)
    server.listen(0, '127.0.0.1', () => resolve({ server, port: (server.address() as AddressInfo).port }))
  })
}

async function fixture() {
  const secret = await listen((req, res) => {
    res.writeHead(200, { 'content-type': req.url === '/pixel.png' ? 'image/png' : 'text/html' })
    res.end(req.url === '/pixel.png' ? '' : `<html><body><h1>${MARKER}</h1><img src="/pixel.png"></body></html>`)
  })
  const relay = await listen((_req, res) => {
    res.writeHead(302, { location: `http://127.0.0.1:${secret.port}/latest/meta-data` })
    res.end()
  })
  return { secret, relay, close: () => (secret.server.close(), relay.server.close()) }
}

test('remote: a 302 from an allowed host into a blocked address does not load', async () => {
  const f = await fixture()
  const proxy = await startEgressProxy({ isBlocked: (_addr, port) => port === f.secret.port })
  const open = createSessionOpener(launchChromium, async () => proxy.settings)
  const session = await open({ remote: true })
  try {
    const html = await session
      .goto(`http://127.0.0.1:${f.relay.port}/`, { waitUntil: 'domcontentloaded', timeout: 15000 })
      .then(() => session.page.content())
      .catch(() => '')
    assert.ok(!html.includes(MARKER), 'the redirect target (private address) was loaded')
  } finally {
    await session.close()
    await proxy.close()
    f.close()
  }
})

test('remote: the same redirect to an allowed host still loads, with sub-resources', async () => {
  // The known-positive half: without it the test above passes against a
  // proxy that breaks every request.
  const f = await fixture()
  const proxy = await startEgressProxy({ isBlocked: () => false })
  const open = createSessionOpener(launchChromium, async () => proxy.settings)
  const session = await open({ remote: true })
  try {
    const pixel = session.page.waitForResponse((r: any) => r.url().endsWith('/pixel.png'), { timeout: 15000 })
    await session.goto(`http://127.0.0.1:${f.relay.port}/`, { waitUntil: 'load', timeout: 15000 })
    assert.ok((await session.page.content()).includes(MARKER), 'the allowed redirect target did not load')
    assert.equal(session.page.url(), `http://127.0.0.1:${f.secret.port}/latest/meta-data`, 'the page URL is the redirect target')
    assert.equal((await pixel).status(), 200)
  } finally {
    await session.close()
    await proxy.close()
    f.close()
  }
})

test('local (remote: false): no proxy is used', async () => {
  let asked = 0
  const f = await fixture()
  const open = createSessionOpener(launchChromium, async () => {
    asked++
    throw new Error('a local session must not ask for the egress proxy')
  })
  const session = await open({ remote: false })
  try {
    await session.goto(`http://127.0.0.1:${f.relay.port}/`, { waitUntil: 'domcontentloaded', timeout: 15000 })
    assert.ok((await session.page.content()).includes(MARKER))
    assert.equal(asked, 0)
  } finally {
    await session.close()
    f.close()
  }
})
