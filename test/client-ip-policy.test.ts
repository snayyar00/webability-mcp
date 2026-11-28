/**
 * The hosted anonymous gate keys on `clientIp`, whose answer depends entirely
 * on two env vars (TRUST_CF_CONNECTING_IP, TRUSTED_PROXY_HOPS). Get them wrong
 * and either every caller shares one bucket (huge XFF) or a caller mints a new
 * bucket per request (leftmost XFF). Neither fails loudly — the limiter just
 * behaves differently. So the effective policy is stated once at boot, and the
 * statement is generated from the same parsing `clientIp` uses, so it cannot
 * drift from the decision it describes.
 */
import assert from 'node:assert/strict'
import { spawn, type ChildProcess } from 'node:child_process'
import { createServer } from 'node:net'
import { after, test } from 'node:test'

import { clientIp, describeClientIpPolicy } from '../src/anonGate.ts'

test('policy: TRUST_CF_CONNECTING_IP=true names the header it trusts', () => {
  const line = describeClientIpPolicy({ TRUST_CF_CONNECTING_IP: 'true' })
  assert.match(line, /cf-connecting-ip/i)
  assert.doesNotMatch(line, /x-forwarded-for/i)
})

test('policy: the default proxies through one hop of X-Forwarded-For', () => {
  const line = describeClientIpPolicy({})
  assert.match(line, /x-forwarded-for/i)
  assert.match(line, /1/)
  assert.match(line, /TRUSTED_PROXY_HOPS/)
})

test('policy: TRUSTED_PROXY_HOPS=2 says two hops', () => {
  assert.match(describeClientIpPolicy({ TRUSTED_PROXY_HOPS: '2' }), /2/)
})

test('policy: TRUSTED_PROXY_HOPS=0 says the socket address is used', () => {
  const line = describeClientIpPolicy({ TRUSTED_PROXY_HOPS: '0' })
  assert.match(line, /socket/)
  assert.doesNotMatch(line, /rightmost/i)
})

test('policy: an unparsable hop count reports the fallback it actually uses', () => {
  // clientIp falls back to 1, so the line must describe 1 — not echo "-3".
  const line = describeClientIpPolicy({ TRUSTED_PROXY_HOPS: '-3' })
  assert.match(line, /1/)
  assert.doesNotMatch(line, /-3/)
  assert.equal(clientIp({ 'x-forwarded-for': 'spoof, 203.0.113.9' }, '10.0.0.2', { TRUSTED_PROXY_HOPS: '-3' }), '203.0.113.9')
})

test('policy: TRUST_CF_CONNECTING_IP without a value does not claim CF', () => {
  const line = describeClientIpPolicy({ TRUST_CF_CONNECTING_IP: '1' })
  assert.doesNotMatch(line, /cf-connecting-ip/i)
  assert.match(line, /x-forwarded-for/i)
})

// ---- boot log: the live server states its policy once ---------------------

async function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = createServer().listen(0, () => {
      const p = (s.address() as { port: number }).port
      s.close(() => resolve(p))
    })
  })
}

let proc: ChildProcess | undefined
after(() => proc?.kill())

test('hosted: the boot log states the effective client-ip policy', async () => {
  const port = await freePort()
  proc = spawn('./node_modules/.bin/tsx', ['src/http.ts'], {
    env: { ...process.env, PORT: String(port), OAUTH_SIGNING_SECRET: 'client-ip-policy-test-secret-0123456789', TRUSTED_PROXY_HOPS: '2', TRUST_CF_CONNECTING_IP: '', WEBABILITY_SCAN_TELEMETRY: 'off', POSTHOG_PROJECT_API_KEY: '', POSTHOG_API_KEY: '' },
    stdio: ['ignore', 'ignore', 'pipe'],
  })
  let stderr = ''
  proc.stderr?.setEncoding('utf8')
  proc.stderr?.on('data', (c: string) => { stderr += c })
  const base = `http://127.0.0.1:${port}`
  for (let i = 0; i < 100; i++) {
    try { if ((await fetch(base + '/health')).ok) break } catch { /* not up */ }
    await new Promise((r) => setTimeout(r, 100))
  }
  assert.match(stderr, /listening/i, 'the server started')
  assert.match(stderr, /client ip:/i)
  assert.match(stderr, /x-forwarded-for/i)
  assert.match(stderr, /2/, 'the hop count actually in force')
  // Exactly once: a per-request line would flood a production log.
  assert.equal(stderr.match(/client ip:/gi)?.length, 1)
})
