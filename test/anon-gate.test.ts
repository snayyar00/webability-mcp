/**
 * Hosted anonymous gate (http.ts): the per-IP trial and rate limit must key on
 * an address the caller cannot choose, and must see EVERY tool a request calls.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { anonCallCost, anonLimitClass, calledTools, clientIp, createAnonLimiter } from '../src/anonGate.ts'

const call = (name: string, id = 1) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: {} } })

test('a forged leftmost X-Forwarded-For does not change the bucket', () => {
  // Behind one proxy that appends the real peer: "<client-sent>, <real peer>".
  const a = clientIp({ 'x-forwarded-for': 'spoof-1, 203.0.113.9' }, '10.0.0.2', {})
  const b = clientIp({ 'x-forwarded-for': 'spoof-2, 203.0.113.9' }, '10.0.0.2', {})
  assert.equal(a, '203.0.113.9')
  assert.equal(a, b)
})

test('TRUSTED_PROXY_HOPS=2 (Cloudflare -> Traefik) picks the client Cloudflare saw', () => {
  const env = { TRUSTED_PROXY_HOPS: '2' }
  assert.equal(clientIp({ 'x-forwarded-for': 'spoof, 198.51.100.7, 172.68.1.1' }, '10.0.0.2', env), '198.51.100.7')
})

test('TRUSTED_PROXY_HOPS=0 ignores X-Forwarded-For entirely', () => {
  assert.equal(clientIp({ 'x-forwarded-for': 'spoof' }, '192.0.2.4', { TRUSTED_PROXY_HOPS: '0' }), '192.0.2.4')
})

test('fewer XFF entries than hops falls back to the socket address', () => {
  assert.equal(clientIp({ 'x-forwarded-for': '198.51.100.7' }, '192.0.2.4', { TRUSTED_PROXY_HOPS: '2' }), '192.0.2.4')
})

test('CF-Connecting-IP wins only when TRUST_CF_CONNECTING_IP=true', () => {
  const h = { 'cf-connecting-ip': '198.51.100.7', 'x-forwarded-for': 'spoof, 172.68.1.1' }
  assert.equal(clientIp(h, '10.0.0.2', { TRUST_CF_CONNECTING_IP: 'true' }), '198.51.100.7')
  assert.equal(clientIp(h, '10.0.0.2', {}), '172.68.1.1')
})

test('a JSON-RPC batch exposes every tool it calls', () => {
  const body = [call('visual_audit', 1), call('scan_page', 2), { jsonrpc: '2.0', method: 'notifications/initialized' }]
  assert.deepEqual(calledTools(body).map((c) => c.name), ['visual_audit', 'scan_page'])
})

test('a single call still yields its tool; non-calls yield none', () => {
  assert.deepEqual(calledTools(call('scan_page')).map((c) => c.name), ['scan_page'])
  assert.deepEqual(calledTools({ jsonrpc: '2.0', id: 1, method: 'tools/list' }), [])
  assert.deepEqual(calledTools(undefined), [])
})

test('calledTools keeps each call\'s arguments, single and batch', () => {
  const withArgs = (name: string, args: unknown, id = 1) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } })
  assert.deepEqual(calledTools(withArgs('check_color_contrast', { url: 'https://a.test' })), [{ name: 'check_color_contrast', args: { url: 'https://a.test' } }])
  const batch = calledTools([withArgs('check_color_contrast', { foreground: '#000' }, 1), withArgs('check_color_contrast', { url: 'https://a.test' }, 2)])
  assert.deepEqual(batch.map((c) => anonLimitClass(c)), [null, 'heavy'])
})

test('limiter.full() reports a spent bucket without counting (#201 bad-token gate)', () => {
  let t = 1_000
  const l = createAnonLimiter(() => t)
  for (let i = 0; i < 5; i++) assert.equal(l.full('ip:badtoken', 2).ok, true, 'peeking must not use the budget')
  l.allow('ip:badtoken', 2)
  assert.equal(l.full('ip:badtoken', 2).ok, true)
  l.allow('ip:badtoken', 2)
  const g = l.full('ip:badtoken', 2)
  assert.equal(g.ok, false)
  assert.ok(g.retryAfterS > 0)
  assert.equal(l.full('other-ip:badtoken', 2).ok, true)
  t += 60 * 60 * 1000 + 1
  assert.equal(l.full('ip:badtoken', 2).ok, true, 'the window resets')
})

// --- byte-weighted anonymous AI gate (issue #225 C2-02c) -------------------
// A call-count cap let one caller spend a whole hour's budget in a single
// request by sending a huge html/context payload. The AI bucket now charges
// for the payload, so a 2 MB call costs more than a small one.

const SIZE_UNIT = 16 * 1024
const aiCall = (args: unknown) => ({ name: 'generate_ai_fix', args })

test('a small AI fix call costs one unit', () => {
  assert.equal(anonCallCost(aiCall({ issue: { message: 'x' }, html: '<p>x</p>' })), 1)
  assert.equal(anonCallCost(aiCall(undefined)), 1)
})

test('cost grows with payload weight: one unit is 16 KB, rounded up', () => {
  const html = (n: number) => aiCall({ issue: { message: 'x' }, html: 'a'.repeat(n) })
  assert.equal(anonCallCost(html(SIZE_UNIT - 32)), 1, 'under one unit still costs one')
  assert.equal(anonCallCost(html(SIZE_UNIT * 4)), 5, 'four clean units plus the issue round up')
  assert.equal(anonCallCost(html(SIZE_UNIT * 10)), 11)
})

test('one 2 MB AI fix call costs ~129 units, not one', () => {
  const l = createAnonLimiter(() => 1_000)
  const heavy = anonCallCost(aiCall({ issue: { message: 'x' }, html: 'a'.repeat(2 * 1024 * 1024) }))
  assert.equal(heavy, 129, `2 MB plus a tiny issue rounds up to 129 units, got ${heavy}`)
  assert.equal(l.allow('ip:ai', 10, heavy).ok, false, 'a single 2 MB call blows a 10-call budget')
})

test('html, context and issue all count toward the cost', () => {
  const half = 'a'.repeat(SIZE_UNIT)
  const split = anonCallCost(aiCall({ issue: { message: 'x' }, html: half, context: half + half }))
  const together = anonCallCost(aiCall({ issue: { message: 'x' }, html: half + half + half }))
  assert.equal(split, together, 'the same payload weight costs the same wherever it sits')
  assert.ok(split > 1, 'a 48 KB payload costs more than one unit')
})

test('a non-AI tool costs one, whatever its arguments', () => {
  const args = { url: 'https://a.test', html: 'a'.repeat(SIZE_UNIT * 8) }
  assert.equal(anonCallCost({ name: 'scan_page', args }), 1)
  assert.equal(anonCallCost({ name: 'get_rules', args }), 1)
})

test('allow() charges the cost, so one heavy call can spend the whole budget', () => {
  const l = createAnonLimiter(() => 1_000)
  const g = l.allow('ip:ai', 2, 3)
  assert.equal(g.ok, false, 'cost 3 exceeds a limit of 2')
  assert.equal(l.full('ip:ai', 2).ok, false, 'the refused request still counts what it tried to spend')
})

test('allow() defaults to a cost of one (existing callers unchanged)', () => {
  const l = createAnonLimiter(() => 1_000)
  assert.equal(l.allow('ip:ai', 2).ok, true)
  assert.equal(l.allow('ip:ai', 2).ok, true)
  assert.equal(l.allow('ip:ai', 2).ok, false)
})
