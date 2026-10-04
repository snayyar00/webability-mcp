/**
 * Hosted anonymous gate (http.ts): the per-IP trial and rate limit must key on
 * an address the caller cannot choose, and must see EVERY tool a request calls.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { anonLimitClass, calledTools, clientIp } from '../src/anonGate.ts'

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
