/**
 * Persona round 4: the hosted anonymous per-IP cap answered "Anonymous rate
 * limit reached for this tool. Sign in … or retry later." — no limit, no
 * reset time (4 runs, 24 capped calls; R4-46 hit it on its first call
 * from a shared IP). The message now states the limit, when the limiter's
 * own window resets, and how to sign in.
 */
import assert from 'node:assert/strict'
import { spawn, type ChildProcess } from 'node:child_process'
import { createServer } from 'node:net'
import { after, test } from 'node:test'

import * as gate from '../src/anonGate.ts'

test('limiter: counts per key inside one window and reports the window it opened', () => {
  const g: any = gate
  assert.equal(typeof g.createAnonLimiter, 'function', 'anonGate must export createAnonLimiter')
  let now = Date.UTC(2026, 9, 4, 14, 5, 0)
  const lim = g.createAnonLimiter(() => now)
  const a = lim.allow('1.2.3.4:heavy', 2)
  assert.equal(a.ok, true)
  assert.equal(a.resetAt, Date.UTC(2026, 9, 4, 15, 5, 0))
  assert.equal(lim.allow('1.2.3.4:heavy', 2).ok, true)
  now += 20 * 60 * 1000
  const third = lim.allow('1.2.3.4:heavy', 2)
  assert.equal(third.ok, false)
  assert.equal(third.retryAfterS, 40 * 60, 'reset comes from the window the first call opened')
  assert.equal(lim.allow('5.6.7.8:heavy', 2).ok, true, 'another IP has its own bucket')
  now += 41 * 60 * 1000
  assert.equal(lim.allow('1.2.3.4:heavy', 2).ok, true, 'a new window after the reset')
})

test('message: limit, reset in minutes and UTC clock time, sign-in hint', () => {
  const g: any = gate
  assert.equal(typeof g.anonLimitMessage, 'function', 'anonGate must export anonLimitMessage')
  const msg = g.anonLimitMessage({ cls: 'heavy', limit: 30, retryAfterS: 40 * 60, resetAt: Date.UTC(2026, 9, 4, 15, 5, 0) })
  assert.match(msg, /30 /)
  assert.match(msg, /per hour/)
  assert.match(msg, /resets in 40 min \(at 15:05 UTC\)/)
  assert.match(msg, /[Ss]ign in with a free WebAbility account/)
  assert.match(msg, /webability login/)
  assert.doesNotMatch(msg, /abilyo/i)
  // One source of sign-in text (signIn.ts): per-client steps, not a generic hint.
  assert.ok(msg.includes('/mcp/auth'), msg)
  assert.match(msg, /claude mcp login <server-name>/)
  assert.match(msg, /codex mcp login <server-name>/)
  assert.match(msg, /opencode mcp auth <server-name>/)
  assert.doesNotMatch(msg, /authenticate option/i)
  const ai = g.anonLimitMessage({ cls: 'ai', limit: 10, retryAfterS: 30, resetAt: Date.UTC(2026, 9, 4, 15, 5, 0) })
  assert.match(ai, /10 AI fix/)
  assert.match(ai, /resets in 30 s/)
})

// ---- end to end: the real hosted HTTP server ------------------------------

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

test('hosted: the 429 carries the reset window, Retry-After, and structured data', async () => {
  const port = await freePort()
  proc = spawn('./node_modules/.bin/tsx', ['src/http.ts'], {
    env: { ...process.env, PORT: String(port), ANON_HEAVY_PER_HOUR: '1', TRUSTED_PROXY_HOPS: '0', WEBABILITY_SCAN_TELEMETRY: 'off', POSTHOG_PROJECT_API_KEY: '', POSTHOG_API_KEY: '' },
    stdio: ['ignore', 'ignore', 'ignore'],
  })
  const base = `http://127.0.0.1:${port}`
  for (let i = 0; i < 100; i++) {
    try { if ((await fetch(base + '/health')).ok) break } catch { /* not up */ }
    await new Promise((r) => setTimeout(r, 100))
  }
  // detect_framework is heavy; a loopback url is refused by the SSRF guard
  // after the gate has counted it, so no browser launches.
  const body = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'detect_framework', arguments: { url: 'http://127.0.0.1:9/' } } }
  const post = () => fetch(base + '/mcp', { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' }, body: JSON.stringify(body) })
  const first = await post()
  assert.equal(first.status, 200, 'first anonymous heavy call is allowed')
  const second = await post()
  assert.equal(second.status, 429)
  const retry = Number(second.headers.get('retry-after'))
  assert.ok(retry > 3500 && retry <= 3600, `Retry-After ${retry}`)
  const json: any = await second.json()
  assert.match(json.error.message, /1 page-loading call/)
  assert.match(json.error.message, /resets in 60 min \(at \d{2}:\d{2} UTC\)/)
  assert.match(json.error.message, /[Ss]ign in with a free WebAbility account/)
  assert.equal(json.error.data.limit, 1)
  assert.equal(typeof json.error.data.resetAt, 'string')
  assert.ok(json.error.data.retryAfterSeconds > 3500)
})
