/**
 * Where the tunnel secret is allowed to go.
 *
 * A scanned page can reference any host it likes. This codebase has already
 * shipped a header leak of exactly this shape — setExtraHTTPHeaders is
 * context-wide, and a per-site token went to every third-party script on the
 * page. These tests exist so that cannot happen again with a key to someone's
 * laptop.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { parseTunnelTarget, RELAY_ORIGIN, TUNNEL_SECRET_HEADER, tunnelHeadersFor } from '../src/tunnelAuth'

const ID = 'a'.repeat(32)
const OTHER = 'b'.repeat(32)
const RELAY = RELAY_ORIGIN
const target = parseTunnelTarget(`${RELAY}/t/${ID}/`, 'sekret')!

test('a tunnel URL is recognised, an ordinary URL is not', () => {
  assert.equal(target.id, ID)
  assert.equal(target.origin, RELAY)
  assert.equal(parseTunnelTarget('https://example.com/about', 'sekret'), null)
  assert.equal(parseTunnelTarget(`${RELAY}/t/not-hex/`, 'sekret'), null)
  // No secret, no target — never send a request pretending to be authenticated.
  assert.equal(parseTunnelTarget(`${RELAY}/t/${ID}/`, ''), null)
})

test('the secret goes to the tunnel URL', () => {
  const headers = tunnelHeadersFor(`${RELAY}/t/${ID}/dashboard`, target)
  assert.equal(headers[TUNNEL_SECRET_HEADER], 'sekret')
})

test('the secret NEVER goes to a third-party host on the page', () => {
  // The leak that already happened once here, with a customer's auth token.
  for (const url of ['https://evil.example.com/x.js', 'https://cdn.jsdelivr.net/npm/x', 'https://www.google-analytics.com/collect', 'http://tunnel.webability.io.evil.com/t/' + ID + '/']) {
    assert.deepEqual(tunnelHeadersFor(url, target), {}, `must not send the secret to ${url}`)
  }
})

test('the secret never goes to another tunnel on the same relay', () => {
  // Same origin is not enough — every developer's tunnel shares it.
  assert.deepEqual(tunnelHeadersFor(`${RELAY}/t/${OTHER}/`, target), {})
})

test('a non-tunnel path on the relay gets nothing', () => {
  for (const url of [`${RELAY}/healthz`, `${RELAY}/`, `${RELAY}/t/`]) {
    assert.deepEqual(tunnelHeadersFor(url, target), {})
  }
})

test('http and https are different origins', () => {
  // A downgrade would put the secret on the wire in clear text.
  assert.deepEqual(tunnelHeadersFor(`http://tunnel.webability.io/t/${ID}/`, target), {})
})

test('no target means no header, ever', () => {
  assert.deepEqual(tunnelHeadersFor(`${RELAY}/t/${ID}/`, null), {})
})

test('the secret is never logged or echoed back in a target', () => {
  // A target is passed around inside the server; it must not stringify into
  // logs by accident. This is a reminder in test form: if someone adds a
  // toString or a JSON dump of the target, this is where it should hurt.
  const t = parseTunnelTarget(`${RELAY}/t/${ID}/`, 'sekret')!
  assert.equal(Object.keys(t).sort().join(','), 'id,origin,secret')
})

// ── The origin is pinned, not chosen by the caller ────────────────────────

test('a tunnel-shaped URL on someone ELSE\'s host is not a target', () => {
  // The hole this closes. Deriving the origin from the caller's URL meant an
  // attacker served a page at https://evil.example.com/t/<32hex>/ and every
  // same-origin subresource on it collected the secret — and they knew the id,
  // because it was the path of the page they served.
  for (const host of ['https://evil.example.com', 'https://tunnel.webability.io.evil.com', 'https://tunnelxwebability.io', 'https://sub.tunnel.webability.io']) {
    assert.equal(parseTunnelTarget(`${host}/t/${ID}/`, 'sekret'), null, `must not accept ${host}`)
  }
  // The real relay still works.
  assert.ok(parseTunnelTarget(`${RELAY}/t/${ID}/`, 'sekret'))
})

test('an http tunnel URL is refused outright', () => {
  // The outer SSRF check permits http, so this is the only thing stopping a
  // key to someone's laptop from crossing the network in clear text.
  assert.equal(parseTunnelTarget(`http://tunnel.webability.io/t/${ID}/`, 'sekret'), null)
})
