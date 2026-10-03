/**
 * The relay redeploys on every webability-platform merge (5 times on
 * 2026-09-26/27) and the CLI exited on each one. The relay now closes agents
 * with RELAY_RESTART_CODE on shutdown; the CLI reconnects on that code only,
 * with backoff, and prints the NEW url + secret (the registry is in memory,
 * so the old pair is gone). Any other close still exits non-zero.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { keepTunnel, RELAY_RESTART_CODE } from '../src/tunnel/reconnect.ts'

type Closer = (info: { code: number; reason: string }) => void

/** A fake openTunnel: each call yields the next scripted outcome. */
function scripted(outcomes: Array<{ close: number } | { fail: string } | { stay: true }>) {
  const opened: string[] = []
  let i = 0
  const open = async (onClosed: Closer) => {
    const o = outcomes[i++]
    if (!o) throw new Error('no more outcomes')
    if ('fail' in o) throw new Error(o.fail)
    const handle = { url: `https://relay/t/${i}/`, secret: `s${i}`, secretHeader: 'x', close() {} }
    opened.push(handle.url)
    if ('close' in o) setImmediate(() => onClosed({ code: o.close, reason: o.close === RELAY_RESTART_CODE ? 'relay restarting' : 'x' }))
    return handle
  }
  return { open, opened }
}

const noSleep = async () => {}

test('the restart code matches the relay (tunnel-relay/src/server.ts RELAY_RESTART_CODE)', () => {
  assert.equal(RELAY_RESTART_CODE, 4409)
})

test('a relay restart reconnects and reports the new tunnel', async () => {
  const { open, opened } = scripted([{ close: RELAY_RESTART_CODE }, { stay: true }])
  const seen: Array<{ url: string; reconnect: boolean }> = []
  const result = await Promise.race([
    keepTunnel({ open, sleep: noSleep, onOpened: (t, reconnect) => seen.push({ url: t.url, reconnect }) }),
    new Promise((r) => setTimeout(() => r('still-open'), 100)),
  ])
  assert.equal(result, 'still-open')
  assert.deepEqual(opened, ['https://relay/t/1/', 'https://relay/t/2/'])
  assert.deepEqual(seen.map((s) => s.reconnect), [false, true])
})

test('the new container not being up yet is retried with growing delays', async () => {
  const { open } = scripted([{ close: RELAY_RESTART_CODE }, { fail: 'ECONNREFUSED' }, { fail: '502' }, { stay: true }])
  const delays: number[] = []
  const seen: boolean[] = []
  await Promise.race([
    keepTunnel({ open, sleep: async (ms) => void delays.push(ms), onOpened: (_t, r) => seen.push(r) }),
    new Promise((r) => setTimeout(r, 100)),
  ])
  assert.deepEqual(seen, [false, true])
  assert.equal(delays.length, 3)
  assert.ok(delays[0] < delays[1] && delays[1] < delays[2], `delays ${delays}`)
})

test('reconnecting gives up after the attempt limit and reports the last error', async () => {
  const { open } = scripted([{ close: RELAY_RESTART_CODE }, ...Array.from({ length: 10 }, () => ({ fail: 'ECONNREFUSED' }))])
  const end = await keepTunnel({ open, sleep: noSleep, maxAttempts: 4, onOpened: () => {} })
  assert.equal(end.reason, 'reconnect-failed')
  assert.match(end.message, /ECONNREFUSED/)
})

test('any other close is final — expiry, a revoked token, a dead network', async () => {
  for (const code of [4408, 4401, 1006, 1000]) {
    const { open, opened } = scripted([{ close: code }, { stay: true }])
    const end = await keepTunnel({ open, sleep: noSleep, onOpened: () => {} })
    assert.equal(end.reason, 'closed', `code ${code}`)
    assert.equal(end.code, code)
    assert.equal(opened.length, 1, `code ${code} must not reconnect`)
  }
})

test('a failure on the FIRST open is not retried — a bad token or flag should fail fast', async () => {
  const { open, opened } = scripted([{ fail: 'the relay rejected your token' }, { stay: true }])
  await assert.rejects(keepTunnel({ open, sleep: noSleep, onOpened: () => {} }), /rejected your token/)
  assert.equal(opened.length, 0)
})

test('a reconnect attempt that never settles is abandoned, and a late tunnel is closed', async () => {
  let calls = 0
  let lateClosed = false
  const open = async (onClosed: Closer) => {
    calls++
    if (calls === 1) {
      setImmediate(() => onClosed({ code: RELAY_RESTART_CODE, reason: 'relay restarting' }))
      return { url: 'u1', secret: 's', secretHeader: 'x', close() {} }
    }
    // Hangs past the attempt deadline, then finally opens.
    await new Promise((r) => setTimeout(r, 80))
    return { url: `late${calls}`, secret: 's', secretHeader: 'x', close: () => void (lateClosed = true) }
  }
  const end = await Promise.race([
    keepTunnel({ open, sleep: noSleep, maxAttempts: 2, attemptTimeoutMs: 20, onOpened: () => {} }),
    new Promise<string>((r) => setTimeout(() => r('hung'), 1_000)),
  ])
  assert.notEqual(end, 'hung', 'a stuck open blocked every later attempt')
  assert.equal((end as any).reason, 'reconnect-failed')
  assert.match((end as any).message, /timed out/)
  await new Promise((r) => setTimeout(r, 150))
  assert.equal(lateClosed, true, 'a tunnel that opened after its deadline was left running')
})
